"""Saved hunts and replays.

A saved hunt keeps the successful data calls of a finished hunt. A replay runs
those calls again WITHOUT a model: each is re-validated, run through the hub,
and its hit count compared with the previous run. Relative times such as
``now-24h`` move forward with each replay; absolute times do not, so saving
warns about them. A replay with matches is flagged for review and, if
``escalate`` is set, starts a full model-driven hunt with the replay results as
context.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

import yaml

from ..connectors.hub import ToolCallError
from .signals import fingerprint, hits
from .store import HuntStore
from .validator import TIME_KEYS, ValidationError, validate_call


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def starters() -> list[dict]:
    """Built-in starter hypotheses (no queries; the model writes those for your data)."""
    text = resources.files("actaeon.hunt").joinpath("starters.yaml").read_text()
    return yaml.safe_load(text) or []


class Library:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS saved (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, hypothesis TEXT NOT NULL,
                attack TEXT NOT NULL DEFAULT '[]', calls TEXT NOT NULL, interval_minutes INTEGER NOT NULL DEFAULT 0,
                escalate INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, created TEXT NOT NULL,
                source_hunt_id TEXT, last_run TEXT, last_hits INTEGER, last_fingerprints TEXT,
                last_hunt_id TEXT)""")

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    @staticmethod
    def _row(r) -> dict:
        d = dict(r)
        d["attack"] = json.loads(d["attack"])
        d["calls"] = json.loads(d["calls"])
        d["last_fingerprints"] = json.loads(d["last_fingerprints"]) if d["last_fingerprints"] else None
        d["enabled"], d["escalate"] = bool(d["enabled"]), bool(d["escalate"])
        return d

    def save_from_hunt(self, hunt: dict, *, name: str = "", interval_minutes: int = 0, escalate: bool = False) -> dict:
        calls = [{"connector": s["connector"], "tool": s["tool"], "arguments": s["arguments"] or {}, "evidence": f"E{s['n']}"}
                 for s in hunt.get("steps") or [] if s["kind"] == "call" and s["ok"]]
        if not calls:
            raise ValueError("this hunt has no successful calls to replay")
        warnings = []
        for c in calls:
            for k, v in c["arguments"].items():
                if k.lower() in TIME_KEYS and isinstance(v, str) and not v.strip().startswith("now"):
                    warnings.append(f"{c['connector']}.{c['tool']} uses a fixed time {k}={v}; replays will not move it")
        attack = (hunt.get("verdict") or {}).get("attack") or (hunt.get("plan") or {}).get("attack") or []
        with self._lock, self._conn() as c:
            cur = c.execute("INSERT INTO saved (name, hypothesis, attack, calls, interval_minutes, escalate, created, "
                            "source_hunt_id) VALUES (?,?,?,?,?,?,?,?)",
                            ((name or hunt["hypothesis"])[:200], hunt["hypothesis"], json.dumps(attack),
                             json.dumps(calls), max(0, int(interval_minutes)), int(escalate), _now(), hunt["id"]))
        return {**self.get(cur.lastrowid), "warnings": warnings}

    def get(self, sid: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM saved WHERE id=?", (int(sid),)).fetchone()
        return self._row(r) if r else None

    def list(self) -> list[dict]:
        with self._conn() as c:
            return [self._row(r) for r in c.execute("SELECT * FROM saved ORDER BY id")]

    def set(self, sid: int, **fields) -> dict | None:
        allowed = {k: v for k, v in fields.items() if k in ("name", "interval_minutes", "escalate", "enabled")}
        for k in ("escalate", "enabled"):
            if k in allowed:
                allowed[k] = int(bool(allowed[k]))
        if "interval_minutes" in allowed:
            allowed["interval_minutes"] = max(0, int(allowed["interval_minutes"]))
        if allowed:
            cols = ", ".join(f"{k}=?" for k in allowed)
            with self._lock, self._conn() as c:
                # Column names and placeholders are fixed in code; values are always bound.
                c.execute(f"UPDATE saved SET {cols} WHERE id=?", (*allowed.values(), int(sid)))  # nosec B608
        return self.get(sid)

    def delete(self, sid: int) -> bool:
        with self._lock, self._conn() as c:
            return c.execute("DELETE FROM saved WHERE id=?", (int(sid),)).rowcount > 0

    def due(self, now: datetime) -> list[dict]:
        out = []
        for s in self.list():
            if not s["enabled"] or s["interval_minutes"] <= 0:
                continue
            if not s["last_run"]:
                out.append(s)
                continue
            last = datetime.fromisoformat(s["last_run"])
            if (now - last).total_seconds() >= s["interval_minutes"] * 60:
                out.append(s)
        return out

    def mark_run(self, sid: int, total_hits: int | None, fps: list[str], hunt_id: str) -> None:
        with self._lock, self._conn() as c:
            c.execute("UPDATE saved SET last_run=?, last_hits=?, last_fingerprints=?, last_hunt_id=? WHERE id=?",
                      (_now(), total_hits, json.dumps(fps), hunt_id, int(sid)))


def replay(saved: dict, hub, store: HuntStore, library: Library, *, max_results: int = 200,
           actor: str = "scheduler") -> dict:
    """Run a saved hunt's calls again without a model and record the result as a hunt."""
    hid = store.create(saved["hypothesis"], origin=f"replay:{saved['id']}", actor=actor)
    store.update(hid, status="running")
    tools: dict[tuple[str, str], dict] = {}
    for role in ("log_search", "endpoint", "identity", "email", "asset", "network", "cloud", "intel", "analysis"):
        for t in hub.tools_for_role(role):
            tools.setdefault((t["connector"], t["name"]), {**t, "role": role})
    n, total, ok_calls, err_calls, changed = 0, 0, 0, 0, 0
    unknown_counts = False
    findings, fps = [], []
    prev = saved.get("last_fingerprints") or []
    for i, call in enumerate(saved["calls"]):
        n += 1
        meta = tools.get((call["connector"], call["tool"]))
        if not meta:
            store.add_step(hid, n, "blocked", connector=call["connector"], tool=call["tool"],
                           arguments=call["arguments"], note="tool no longer available or allowed")
            err_calls += 1
            fps.append("")
            continue
        try:
            args, notes = validate_call(meta, call["arguments"], max_results=max_results)
        except ValidationError as exc:
            store.add_step(hid, n, "blocked", connector=call["connector"], tool=call["tool"],
                           arguments=call["arguments"], note=f"validator: {exc}")
            err_calls += 1
            fps.append("")
            continue
        try:
            out = hub.call(call["connector"], call["tool"], args, actor=actor, hunt_id=hid)
            ok, content = not out.get("is_error"), out["content"]
        except ToolCallError as exc:
            ok, content = False, f"call failed: {exc}"
        h = hits(content) if ok else None
        fp = fingerprint(content) if ok else ""
        fps.append(fp)
        if ok:
            ok_calls += 1
            if h is None:
                unknown_counts = True
            total += h or 0
            if i < len(prev) and prev[i] and prev[i] != fp:
                changed += 1
            if h:
                findings.append({"claim": f"{call['connector']}.{call['tool']} returned {h} match(es)",
                                 "evidence": [f"E{n}"]})
        else:
            err_calls += 1
        store.add_step(hid, n, "call", connector=call["connector"], tool=call["tool"], role=meta["role"],
                       arguments=args, why=f"replay of {call.get('evidence', '')}",
                       ok=ok, result=content, note="; ".join(notes) + (f" hits={h}" if h is not None else ""))
    if ok_calls == 0:
        outcome, summary = "logs_missing", "No replayed search succeeded."
    elif total > 0:
        outcome, summary = "inconclusive", f"Replay found {total} match(es); needs review."
    elif unknown_counts and changed:
        outcome, summary = "inconclusive", f"{changed} result(s) changed since the last replay; needs review."
    else:
        outcome, summary = "no_results", "Replayed searches returned no matches."
    if err_calls:
        summary += f" {err_calls} call(s) failed or were blocked."
    verdict = {"outcome": outcome, "confidence": 50 if outcome != "inconclusive" else 30, "summary": summary,
               "findings": findings, "unsupported_claims": [], "attack": saved.get("attack") or [], "gaps": [],
               "next_steps": [], "checks": ["automatic replay without a model"],
               "needs_review": outcome == "inconclusive", "replay": {"saved_id": saved["id"], "hits": total,
                                                                    "changed": changed, "failed": err_calls}}
    store.add_step(hid, n + 1, "verdict", note=json.dumps(verdict))
    store.update(hid, status="done", outcome=outcome, verdict=verdict, steps_used=n, finished=_now())
    library.mark_run(saved["id"], total, fps, hid)
    return store.get(hid) or {}


def replay_context(hunt: dict) -> str:
    """Short context passed to a full hunt when a replay escalates."""
    lines = [f"A scheduled replay of this hunt flagged: {hunt['verdict']['summary']}"]
    for s in hunt.get("steps") or []:
        if s["kind"] == "call" and s["ok"]:
            lines.append(f"- {s['connector']}.{s['tool']} {json.dumps(s['arguments'])[:300]} -> {s['note']}")
    return "\n".join(lines)


