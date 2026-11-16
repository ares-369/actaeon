"""Response actions: proposed by the AI, approved by a person, then (optionally) run.

Tiers:
  0 observe      the verdict and report only
  1 notify       outputs (webhook, email, ticket) - see outputs.py
  2 contain      reversible actions from ``soc.response.actions`` (isolate a host, disable an account,
                 block an indicator). Proposed by the investigation, never run without approval.
  3 destructive  deleting, wiping, shutting down: never available, whatever the config says.

With ``soc.response.enabled: false`` (the default) actions are only recommendations: the case shows
them, with the exact call, for the analyst to run by hand. With ``enabled: true`` and
``dry_run: true`` (the default when enabled) an approval records what would have been sent. Only with
``dry_run: false`` does an approval call the connector tool. ``two_person: true`` needs two different
approvers. Every approved action stores its undo, if the action has one.

An approval is bound to what was reviewed: the exact call (stored when proposed, never edited) and the
case as it was then. If new alerts join the case or it is investigated again, pending proposals go
stale and must be proposed again.

Config::

    response:
      enabled: false
      dry_run: true
      two_person: false
      actions:
        - name: isolate_host
          description: Cut the host off the network (reversible)
          connector: endpoint-mcp
          tool: isolate_host
          entity: host                       # which kind of case entity the target must be
          arguments: {hostname: "{target}"}  # {target} and {case_id} are filled in
          undo: {tool: release_host, arguments: {hostname: "{target}"}, kind: reversible}   # or compensating
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from ..connectors.policy import is_destructive
from .store import SocStore
from .util import iso

# reversible: the undo puts things back as they were (release a host, re-enable an account).
# compensating: the undo is a follow-up that does not restore everything (sessions already ended, mail
# already removed from inboxes). The case page says which, so nobody approves expecting a clean undo.
UNDO_KINDS = ("reversible", "compensating")
ENTITY_TYPES = ("host", "user", "ip", "domain", "url", "hash", "file", "process")
_NAME = re.compile(r"[a-z][a-z0-9_]{1,39}")
_SAFE_TARGET = re.compile(r"[^\x00-\x1f\"'`;|&$<>\\]{1,300}")


class ResponseError(ValueError):
    pass


def validate_actions(actions: list[dict], connector_names: set[str]) -> None:
    names = set()
    for a in actions:
        if not isinstance(a, dict):
            raise ValueError("soc.response.actions: each action must be a mapping")
        name = str(a.get("name", ""))
        if not _NAME.fullmatch(name):
            raise ValueError(f"soc.response.actions: name {name!r} must be lowercase letters, digits or _")
        if name in names:
            raise ValueError(f"soc.response.actions: duplicate action {name}")
        names.add(name)
        if str(a.get("connector", "")) not in connector_names:
            raise ValueError(f"soc.response.actions.{name}: unknown connector {a.get('connector')!r}")
        for tool in (a.get("tool"), (a.get("undo") or {}).get("tool")):
            if tool is not None and (not isinstance(tool, str) or not tool):
                raise ValueError(f"soc.response.actions.{name}: tool must be a tool name")
            if tool and is_destructive({"name": tool}):
                raise ValueError(f"soc.response.actions.{name}: {tool} is destructive; Actaeon never runs these")
        if not a.get("tool"):
            raise ValueError(f"soc.response.actions.{name}: tool is required")
        if a.get("entity") not in ENTITY_TYPES:
            raise ValueError(f"soc.response.actions.{name}: entity must be one of {ENTITY_TYPES}")
        if not isinstance(a.get("arguments") or {}, dict):
            raise ValueError(f"soc.response.actions.{name}: arguments must be a mapping")
        kind = (a.get("undo") or {}).get("kind", "reversible")
        if kind not in UNDO_KINDS:
            raise ValueError(f"soc.response.actions.{name}: undo.kind must be one of {UNDO_KINDS}")


def catalogue(cfg) -> list[dict]:
    return [{"name": a["name"], "description": str(a.get("description", ""))[:300], "entity": a["entity"],
             "connector": a["connector"], "tool": a["tool"], "undo": undo_kind(a)}
            for a in cfg.soc.response.actions]


def undo_kind(spec: dict) -> str:
    u = spec.get("undo") or {}
    return str(u.get("kind", "reversible")) if u.get("tool") else "none"


def basis(case: dict) -> str:
    """What an approval is bound to: the verdict the analyst reviewed and the alerts it was based on.
    A new verdict or a new alert changes it, and pending proposals become stale."""
    body = json.dumps([case.get("verdict"), case.get("triaged_at"),
                       sorted(a["id"] for a in case.get("alerts") or [])])
    return hashlib.sha256(body.encode()).hexdigest()[:24]


def _fill(obj: Any, target: str, case_id: str) -> Any:
    if isinstance(obj, str):
        return obj.replace("{target}", target).replace("{case_id}", case_id)
    if isinstance(obj, dict):
        return {k: _fill(v, target, case_id) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, target, case_id) for v in obj]
    return obj


def _spec(cfg, name: str) -> dict:
    for a in cfg.soc.response.actions:
        if a["name"] == name:
            return a
    raise ResponseError(f"action {name!r} is not configured in soc.response.actions")


def build(cfg, name: str, target: str, case_id: str) -> dict:
    spec = _spec(cfg, name)
    if not _SAFE_TARGET.fullmatch(target or ""):
        raise ResponseError("the target has characters that are not allowed")
    undo = spec.get("undo") or {}
    return {"name": name, "target": target, "connector": spec["connector"], "tool": spec["tool"],
            "arguments": _fill(dict(spec.get("arguments") or {}), target, case_id),
            "undo": ({"connector": spec["connector"], "tool": undo["tool"],
                      "arguments": _fill(dict(undo.get("arguments") or {}), target, case_id)} if undo.get("tool") else None),
            "description": str(spec.get("description", ""))[:500], "tier": 2, "undo_kind": undo_kind(spec)}


def propose(cfg, store: SocStore, case_id: str, verdict: dict) -> list[int]:
    """Store the verdict's actions as proposals (the engine already checked names and targets)."""
    ids = []
    case = store.get_case(case_id) or {}
    base = basis(case)
    types = {e["value"].lower(): e["type"] for e in (case.get("entities") or [])}
    types.update({e["value"].lower(): e["type"] for e in verdict.get("entities") or []})
    for a in verdict.get("actions") or []:
        try:
            spec = _spec(cfg, a["name"])
            if types.get(a["target"].lower(), spec["entity"]) != spec["entity"]:
                continue
            act = build(cfg, a["name"], a["target"], case_id)
        except ResponseError:
            continue
        ids.append(store.add_action(case_id, **act, reason=a.get("reason", ""), basis=base))
    return ids


def _mode(cfg) -> str:
    if not cfg.soc.response.enabled:
        return "recommend"
    return "dry_run" if cfg.soc.response.dry_run else "live"


def decide(cfg, store: SocStore, hub, action_id: int, *, user: str, approve: bool, note: str = "") -> dict:
    """Approve or reject a proposed action. Approval runs it only in live mode."""
    a = store.get_action(action_id)
    if not a:
        raise ResponseError("no such action")
    if a["status"] != "proposed":
        raise ResponseError(f"the action is already {a['status']}")
    if not user:
        raise ResponseError("an approver name is needed")
    if approve and a.get("basis") and a["basis"] != basis(store.get_case(a["case_id"]) or {}):
        store.set_action(action_id, status="stale", decided_by=user, decided_at=iso(),
                         result="The case changed after this was proposed (new alerts or a new verdict).")
        store.add_note(a["case_id"], user, f"Action {a['name']} on {a['target']} was not run: the case changed "
                       "after it was proposed. Review the case and propose it again.")
        raise ResponseError("the case changed after this action was proposed (new alerts or a new verdict); "
                            "review it and propose the action again")
    if not approve:
        store.set_action(action_id, status="rejected", decided_by=user, decided_at=iso(), result=note[:1000])
        store.add_note(a["case_id"], user, f"Rejected action {a['name']} on {a['target']}. {note}".strip())
        return store.get_action(action_id)
    approvers = [*a["approvers"]]
    if user in approvers:
        raise ResponseError("you already approved this action; a second person must approve it")
    approvers.append(user)
    if cfg.soc.response.two_person and len(approvers) < 2:
        store.set_action(action_id, approvers=approvers)
        store.add_note(a["case_id"], user, f"First approval for {a['name']} on {a['target']}; waiting for a second.")
        return {**store.get_action(action_id), "waiting_for": "a second approver"}
    mode = _mode(cfg)
    if mode == "recommend":
        store.set_action(action_id, status="manual", approvers=approvers, decided_by=user, decided_at=iso(),
                         result="Response actions are turned off (soc.response.enabled: false). Run it by hand: "
                                f"{a['connector']}.{a['tool']} {a['arguments']}")
    elif mode == "dry_run":
        store.set_action(action_id, status="dry_run", approvers=approvers, decided_by=user, decided_at=iso(),
                         result=f"Dry run: would call {a['connector']}.{a['tool']} with {a['arguments']}")
    else:
        from ..connectors.hub import ToolCallError
        try:
            out = hub.call_action(a["connector"], a["tool"], a["arguments"], approved_by=" + ".join(approvers),
                                  case_id=a["case_id"])
            store.set_action(action_id, status="executed" if out["ok"] else "failed", approvers=approvers,
                             decided_by=user, decided_at=iso(), executed_at=iso(), result=out["text"][:2000])
        except ToolCallError as exc:
            store.set_action(action_id, status="failed", approvers=approvers, decided_by=user, decided_at=iso(),
                             result=str(exc)[:2000])
    done = store.get_action(action_id)
    store.add_note(a["case_id"], user, f"Approved action {a['name']} on {a['target']}: {done['status']}. {note}".strip())
    return done


def undo(cfg, store: SocStore, hub, action_id: int, *, user: str) -> dict:
    a = store.get_action(action_id)
    if not a:
        raise ResponseError("no such action")
    if a["status"] not in ("executed", "dry_run"):
        raise ResponseError("only an executed (or dry-run) action can be undone")
    if not a.get("undo"):
        raise ResponseError("this action has no undo")
    u = a["undo"]
    if a["status"] == "dry_run" or _mode(cfg) != "live":
        store.set_action(action_id, status="undone", result=f"Dry run undo: would call {u['connector']}.{u['tool']} "
                         f"with {u['arguments']}")
    else:
        from ..connectors.hub import ToolCallError
        try:
            out = hub.call_action(u["connector"], u["tool"], u["arguments"], approved_by=user, case_id=a["case_id"])
            store.set_action(action_id, status="undone" if out["ok"] else "failed", result=out["text"][:2000])
        except ToolCallError as exc:
            raise ResponseError(str(exc)) from exc
    store.add_note(a["case_id"], user, f"Undid action {a['name']} on {a['target']}.")
    return store.get_action(action_id)


def mode_text(cfg) -> str:
    return {"recommend": "recommend only (soc.response.enabled is false)",
            "dry_run": "dry run (approved actions are recorded, not sent)",
            "live": "live (approved actions are sent to the connector)"}[_mode(cfg)]
