"""Entities across hunts: every host, user, process, IP, domain, hash, URL and email that a hunt's findings
rely on, with the hunts it appeared in.

What is recorded: the entities in the results a finding cites (host, user, process, source and destination
fields, read the same way as the timeline) plus indicators named in the finding text. Raw results are not
indexed wholesale; an entity is here because a conclusion leaned on it.

An entity is **recurring** when it appears in at least ``entities.recurring_hunts`` hunts (default 3) in the
last ``entities.window_days`` days (default 14) and at least one of them is unresolved (inconclusive, or
handed to an analyst). That is the slow, spread-out activity single hunts miss: each hunt alone looked
inconclusive or harmless. Records follow the access rules: a sighting from a restricted hunt is only shown
to people who may see that hunt.
"""

from __future__ import annotations

import json
import re
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .. import db

TYPES = ("host", "user", "process", "ip", "domain", "url", "hash", "email")
PER_HUNT = 60            # at most this many entities of one type from one hunt
_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]{3,}:[0-9a-f:]+$", re.I)
_SKIP = {"", "-", "none", "null", "n/a", "unknown", "localhost", "127.0.0.1", "::1", "system", "root"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _key(v: str) -> str:
    return str(v).strip().lower()


def settings(cfg) -> dict:
    e = ((getattr(cfg, "raw", None) or {}).get("entities") or {})
    return {"recurring_hunts": max(2, int(e.get("recurring_hunts", 3) or 3)),
            "window_days": max(1, int(e.get("window_days", 14) or 14))}


def extract(h: dict) -> dict[str, dict[str, set[str]]]:
    """{type: {value: {evidence ids}}} from what the findings cite and name."""
    from ..intel.extract import extract as ioc
    from .timeline import build
    v = h.get("verdict") or {}
    findings = [f for f in v.get("findings") or [] if isinstance(f, dict)]
    cited = {e for f in findings for e in f.get("evidence") or []}
    out: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    if cited:
        steps = [s for s in h.get("steps") or [] if f"E{s.get('n')}" in cited]
        for ev in build({"steps": steps}, limit=2000)["events"]:
            for field, typ in (("host", "host"), ("user", "user"), ("process", "process"), ("source", None),
                               ("destination", None)):
                val = str(ev.get(field) or "").strip()
                if _key(val) in _SKIP or len(val) > 300:
                    continue
                t = typ or ("ip" if _IP.match(val) else "url" if "://" in val else "domain")
                out[t][val].add(ev["evidence"])
    for f in findings:
        found = ioc(str(f.get("claim", "")))
        for t, keys in (("ip", ("ipv4", "ipv6")), ("domain", ("domain",)), ("url", ("url",)),
                        ("hash", ("md5", "sha1", "sha256")), ("email", ("email",))):
            for k in keys:
                for val in found.get(k, []):
                    out[t][val].update(e for e in f.get("evidence") or [] if isinstance(e, str))
        m = re.match(r"New host in the inventory: (\S+)", str(f.get("claim", "")))   # drift findings
        if m:
            out["host"][m.group(1)].update(f.get("evidence") or [])
        m = re.match(r"New on (\S+):", str(f.get("claim", "")))
        if m:
            out["host"][m.group(1)].update(f.get("evidence") or [])
    return {t: dict(list(vals.items())[:PER_HUNT]) for t, vals in out.items()}


class EntityStore:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        with db.connect(self.path) as c:
            c.execute("""CREATE TABLE IF NOT EXISTS entity_seen (
                type TEXT NOT NULL, value_key TEXT NOT NULL, value TEXT NOT NULL, hunt_id TEXT NOT NULL,
                created TEXT NOT NULL, outcome TEXT, needs_review INTEGER NOT NULL DEFAULT 0, origin TEXT,
                evidence TEXT, restricted TEXT, PRIMARY KEY (type, value_key, hunt_id))""")
            c.execute("CREATE INDEX IF NOT EXISTS entity_seen_value ON entity_seen(value_key)")

    def index_hunt(self, h: dict) -> int:
        """Record the hunt's entities (replacing an earlier record of the same hunt). Returns how many."""
        if not h or h.get("status") not in ("done", "stopped"):
            return 0
        v = h.get("verdict") or {}
        ents = extract(h)
        rows = [(t, _key(val), val[:300], h["id"], h.get("created") or _now(), h.get("outcome"),
                 int(bool(v.get("needs_review"))), h.get("origin", ""), json.dumps(sorted(ev)),
                 json.dumps(sorted(h.get("restricted") or [])) if h.get("restricted") else None)
                for t, vals in ents.items() for val, ev in vals.items()]
        with self._lock, db.connect(self.path) as c:
            c.execute("DELETE FROM entity_seen WHERE hunt_id=?", (h["id"],))
            for r in rows:
                c.execute("INSERT INTO entity_seen (type, value_key, value, hunt_id, created, outcome, needs_review, "
                          "origin, evidence, restricted) VALUES (?,?,?,?,?,?,?,?,?,?)", r)
        return len(rows)

    def _visible_rows(self, where: str = "", args: tuple = ()) -> list[dict]:
        from ..access import can_see
        with db.connect(self.path) as c:
            # where is a fixed clause built in this module; values are bound
            rows = [dict(r) for r in c.execute("SELECT * FROM entity_seen " + where, args)]  # nosec B608
        return [r for r in rows if can_see(json.loads(r["restricted"]) if r.get("restricted") else [])]

    def summary(self, cfg=None, *, type_: str | None = None, q: str = "", recurring_only: bool = False,
                limit: int = 200) -> list[dict]:
        s = settings(cfg)
        since = (datetime.now(timezone.utc) - timedelta(days=s["window_days"])).isoformat(timespec="seconds")
        where, args = [], []
        if type_:
            where.append("type=?")
            args.append(type_)
        if q:
            where.append("value_key LIKE ?")
            args.append(f"%{_key(q)}%")
        rows = self._visible_rows(("WHERE " + " AND ".join(where)) if where else "", tuple(args))
        agg: dict[tuple[str, str], dict] = {}
        for r in rows:
            a = agg.setdefault((r["type"], r["value_key"]), {
                "type": r["type"], "value": r["value"], "hunts": 0, "recent": 0, "unresolved_recent": 0,
                "threat": 0, "first_seen": r["created"], "last_seen": r["created"], "outcomes": defaultdict(int)})
            a["hunts"] += 1
            a["outcomes"][r["outcome"] or "unknown"] += 1
            a["threat"] += r["outcome"] == "threat"
            a["first_seen"] = min(a["first_seen"], r["created"])
            a["last_seen"] = max(a["last_seen"], r["created"])
            if r["created"] >= since:
                a["recent"] += 1
                a["unresolved_recent"] += int(r["outcome"] == "inconclusive" or bool(r["needs_review"]))
        out = []
        for a in agg.values():
            a["outcomes"] = dict(a["outcomes"])
            a["recurring"] = a["recent"] >= s["recurring_hunts"] and a["unresolved_recent"] >= 1
            if recurring_only and not a["recurring"]:
                continue
            out.append(a)
        out.sort(key=lambda a: (not a["recurring"], -a["recent"], -a["hunts"], a["value"]))
        return out[:limit]

    def history(self, type_: str, value: str) -> list[dict]:
        rows = self._visible_rows("WHERE type=? AND value_key=? ORDER BY created DESC", (type_, _key(value)))
        for r in rows:
            r["evidence"] = json.loads(r["evidence"] or "[]")
            r.pop("restricted", None)
        return rows

    def context_for(self, cfg, text: str, limit: int = 8) -> str:
        """Lines for a new hunt: known entities that its hypothesis mentions, with their history."""
        words = {_key(w) for w in re.findall(r"[\w.@:/-]{3,}", text or "")}
        if not words:
            return ""
        hits = [a for a in self.summary(cfg, limit=5000) if _key(a["value"]) in words][:limit]
        if not hits:
            return ""
        lines = ["Entities in this hypothesis that earlier hunts relied on (history, not proof):"]
        for a in hits:
            outs = ", ".join(f"{k} {n}" for k, n in sorted(a["outcomes"].items()))
            lines.append(f"- {a['type']} {a['value']}: {a['hunts']} hunt(s) ({outs})"
                         + ("; recurring in recent unresolved hunts" if a["recurring"] else ""))
        return "\n".join(lines)
