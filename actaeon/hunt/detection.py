"""Draft detection rules from a hunt.

Two parts:
  * native: the queries that returned data in this hunt, exactly as they ran, per connector
  * sigma: a Sigma rule draft written by the reporter model from the hypothesis, findings,
    those queries and the field names seen, then checked: valid YAML, required keys
    (title, logsource, detection with a condition), status forced to ``experimental``,
    ATT&CK tags from the hunt. Benign feedback on findings becomes ``falsepositives``.
Everything is a DRAFT for a detection engineer to review and test before deploying.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

import yaml

from ..connectors.untrusted import SYSTEM_RULE
from .jsonparse import first_object
from .signals import hits

SIGMA_SYSTEM = f"""You write Sigma detection rules (YAML) from a finished threat hunt.
Use only field names and values that appear in the hunt's queries and evidence. Keep the rule specific enough
to avoid noise. Reply with ONE JSON object: {{"sigma": "<the complete Sigma YAML as a string>", "notes": "one or two
sentences on tuning or known gaps"}}.
The Sigma rule must have: title, description, logsource (category and/or product), detection (with selection
blocks and a condition), level, tags (attack.tXXXX), falsepositives.
{SYSTEM_RULE}"""


def native_queries(h: dict) -> list[dict]:
    cited = {e for f in (h.get("verdict") or {}).get("findings") or [] for e in f.get("evidence") or []}
    out, seen = [], set()
    for s in h.get("steps") or []:
        if s["kind"] != "call" or not s["ok"] or not isinstance(s.get("arguments"), dict):
            continue
        q = s["arguments"].get("query")
        if not isinstance(q, str) or not q.strip() or q in seen:
            continue
        n = hits(s.get("result") or "")
        if (n or 0) > 0 or f"E{s['n']}" in cited:
            seen.add(q)
            out.append({"evidence": f"E{s['n']}", "connector": s["connector"], "tool": s["tool"], "query": q,
                        "hits": n, "arguments": s["arguments"]})
    return out


def check_sigma(text: str, attack: list[str]) -> tuple[str, list[str]]:
    """Parse and normalise a Sigma draft. Returns (yaml_text, problems)."""
    problems = []
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return text, [f"not valid YAML: {exc}"[:300]]
    if not isinstance(doc, dict):
        return text, ["not a YAML mapping"]
    for k in ("title", "logsource", "detection"):
        if k not in doc:
            problems.append(f"missing {k}")
    det = doc.get("detection")
    if isinstance(det, dict) and "condition" not in det:
        problems.append("detection has no condition")
    doc["status"] = "experimental"
    doc.setdefault("id", str(uuid.uuid4()))
    tags = [t for t in doc.get("tags") or [] if isinstance(t, str)]
    for t in attack:
        tag = f"attack.{t.lower()}"
        if tag not in tags:
            tags.append(tag)
    doc["tags"] = tags
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), problems


def draft(llm, h: dict) -> dict:
    v = h.get("verdict") or {}
    native = native_queries(h)
    from .attack_names import check
    attack = check((v.get("attack") or []) + ((h.get("plan") or {}).get("attack") or []))[0]
    benign = [f"{f['claim']} ({f.get('comment', '')})" for f in h.get("feedback") or []
              if f.get("kind") in ("benign", "false_positive")]
    facts = {"hypothesis": h["hypothesis"], "outcome": h.get("outcome"), "summary": v.get("summary", ""),
             "findings": [f["claim"] for f in v.get("findings") or []], "attack": attack,
             "queries_that_found_data": [{"connector": q["connector"], "query": q["query"]} for q in native],
             "known_benign": benign}
    sigma, notes, problems = "", "", []
    if llm is not None:
        try:
            res = llm.for_role("reporter").chat([{"role": "system", "content": SIGMA_SYSTEM},
                                                 {"role": "user", "content": json.dumps(facts)}], max_tokens=1500)
            obj = first_object(res.text or "") if not res.error else None
            if obj and isinstance(obj.get("sigma"), str):
                sigma, problems = check_sigma(obj["sigma"], attack)
                notes = str(obj.get("notes", ""))[:600]
            else:
                problems = [f"the model did not return a rule{': ' + res.error[:200] if res.error else ''}"]
        except Exception as exc:
            problems = [f"model call failed: {exc}"[:300]]
    if not native:
        problems.append("no query in this hunt returned data, so the draft is not grounded in a working query")
    return {"hunt_id": h["id"], "native": native, "sigma": sigma, "notes": notes, "problems": problems,
            "attack": attack, "status": "draft", "valid": bool(sigma) and not [p for p in problems if "YAML" in p
                                                                                or "missing" in p or "condition" in p]}


class DetectionStore:
    def __init__(self, path):
        self.path = path
        with self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS detections (id INTEGER PRIMARY KEY AUTOINCREMENT, hunt_id TEXT, "
                      "created TEXT, body TEXT)")

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def save(self, d: dict) -> dict:
        with self._conn() as c:
            cur = c.execute("INSERT INTO detections (hunt_id, created, body) VALUES (?,?,?)",
                            (d["hunt_id"], datetime.now(timezone.utc).isoformat(timespec="seconds"), json.dumps(d)))
        return {**d, "id": cur.lastrowid}

    def list(self, hunt_id: str | None = None) -> list[dict]:
        q, a = "SELECT * FROM detections", ()
        if hunt_id:
            q, a = q + " WHERE hunt_id=?", (hunt_id,)
        with self._conn() as c:
            return [{**json.loads(r["body"]), "id": r["id"], "created": r["created"]}
                    for r in c.execute(q + " ORDER BY id DESC", a)]
