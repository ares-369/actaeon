"""Evidence bundle for one alert case: everything the verdict rests on, in one file that can be checked later.

The bundle holds the alerts as received, every tool call with its arguments, its result and the result's
SHA-256, the checked verdict, the second look, the proposed actions and their decisions, the notes, a
digest of every prompt sent to a model and every reply (the prompts themselves are not kept), and the
audit-log rows of the case with the audit chain's head hash.

It is sealed with HMAC-SHA256 over its canonical JSON. The key is ``ACTAEON_EVIDENCE_KEY`` (or, if unset,
``ACTAEON_SECRET_KEY``). Anyone holding the key can check that nothing in the file was changed; it is
not a public-key signature, so keep the key where the people who check bundles can use it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from .. import __version__
from .util import iso

FORMAT = "actaeon-case-evidence/1"


def _key() -> bytes:
    k = os.getenv("ACTAEON_EVIDENCE_KEY") or os.getenv("ACTAEON_SECRET_KEY") or ""
    if not k:
        raise ValueError("set ACTAEON_EVIDENCE_KEY (or ACTAEON_SECRET_KEY) in .env to seal evidence bundles")
    return k.encode()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False).encode()


def sha256(text: str | bytes) -> str:
    return hashlib.sha256(text if isinstance(text, bytes) else (text or "").encode()).hexdigest()


def build(case: dict, *, audit=None) -> dict:
    r = case.get("report") or {}
    steps = []
    for s in case.get("steps") or []:
        item = {k: s.get(k) for k in ("n", "kind", "connector", "tool", "role", "arguments", "why", "ok", "note", "ts")}
        if s.get("kind") == "call":
            item["evidence_id"] = f"E{s['n']}"
            item["result"] = s.get("result") or ""
            item["result_sha256"] = sha256(s.get("result") or "")
        steps.append(item)
    audit_rows, head = [], ""
    if audit is not None:
        audit_rows = [{k: row.get(k) for k in ("ts", "actor", "connector", "tool", "arguments", "decision", "status",
                                               "attempts", "error", "hash")}
                      for row in reversed(audit.recent(limit=1000, hunt_id=f"case:{case['id']}"))]
        try:
            head = audit.verify().get("head", "")
        except Exception:
            head = ""
    body = {
        "format": FORMAT, "generator": f"actaeon {__version__}", "exported": iso(),
        "case": {k: case.get(k) for k in ("id", "title", "status", "severity", "severity_label", "created",
                                          "first_alert", "last_alert", "triaged_at", "closed_at", "closed_by",
                                          "analyst_verdict", "analyst_note", "assignee", "restricted")},
        "verdict": {k: r.get(k) for k in ("verdict", "confidence", "severity", "title", "summary", "findings",
                                          "contradicting", "missing", "timeline", "entities", "relations", "attack",
                                          "fix", "gaps", "next_steps", "checks", "injection", "verification")},
        "first_look": case.get("first_look") or {},
        "alerts": [{k: a.get(k) for k in ("id", "source", "ts", "rule_id", "rule_name", "title", "severity",
                                          "entities", "attack", "raw")} for a in case.get("alerts") or []],
        "steps": steps,
        "model_calls": r.get("model_calls") or [],
        "actions": [{k: a.get(k) for k in ("id", "name", "target", "connector", "tool", "arguments", "reason", "status",
                                           "requested_by", "approvers", "decided_by", "decided_at", "result",
                                           "undo_kind", "proposed_at", "expires")} for a in case.get("actions") or []],
        "notes": case.get("notes") or [],
        "usage": case.get("usage") or {},
        "audit": {"rows": audit_rows, "chain_head": head},
    }
    body["seal"] = {"alg": "HMAC-SHA256", "content_sha256": sha256(canonical(body)),
                    "hmac": hmac.new(_key(), canonical(body), hashlib.sha256).hexdigest()}
    return body


def verify(bundle: dict) -> dict:
    """Check a bundle's seal (and that every result still matches its digest)."""
    seal = (bundle or {}).get("seal") or {}
    body = {k: v for k, v in bundle.items() if k != "seal"}
    problems = []
    if bundle.get("format") != FORMAT:
        problems.append(f"unknown format {bundle.get('format')!r}")
    if sha256(canonical(body)) != seal.get("content_sha256"):
        problems.append("the content does not match its SHA-256 (the file was changed)")
    try:
        if not hmac.compare_digest(hmac.new(_key(), canonical(body), hashlib.sha256).hexdigest(), str(seal.get("hmac"))):
            problems.append("the HMAC does not match (changed, or sealed with another key)")
    except ValueError as exc:
        problems.append(str(exc))
    for s in body.get("steps") or []:
        if "result_sha256" in s and sha256(s.get("result") or "") != s["result_sha256"]:
            problems.append(f"{s.get('evidence_id')}: the result does not match its digest")
    return {"ok": not problems, "problems": problems, "case": (body.get("case") or {}).get("id")}


class RecordingLLM:
    """Wraps the LLM for one case and keeps a digest of every prompt and reply (not the text)."""

    def __init__(self, llm):
        self.llm = llm
        self.calls: list[dict] = []

    def for_role(self, role: str):
        b = self.llm.for_role(role)
        rec = self

        class _Bound:
            provider, model = b.provider, b.model

            def chat(self, messages, **kw):
                res = b.chat(messages, **kw)
                rec.calls.append({"role": role, "provider": getattr(b.provider, "name", ""), "model": res.model or b.model,
                                  "ts": iso(), "prompt_sha256": sha256(canonical(messages)),
                                  "reply_sha256": sha256(res.text or ""), "error": (res.error or "")[:200],
                                  "tokens_in": int(getattr(res, "tokens_in", 0) or 0),
                                  "tokens_out": int(getattr(res, "tokens_out", 0) or 0)})
                return res
        return _Bound()

    @property
    def usage(self):
        u = getattr(self.llm, "usage", {})
        return u() if callable(u) else u

    def usage_summary(self):
        return self.llm.usage_summary() if hasattr(self.llm, "usage_summary") else {}
