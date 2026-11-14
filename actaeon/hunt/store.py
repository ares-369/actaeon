"""SQLite record of hunts and every step they took."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import db

OUTCOMES = ("threat", "no_results", "logs_missing", "telemetry_found_benign", "inconclusive")
STATUSES = ("queued", "running", "done", "stopped", "error")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class HuntStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS hunts (
                id TEXT PRIMARY KEY, created TEXT NOT NULL, finished TEXT, hypothesis TEXT NOT NULL,
                origin TEXT NOT NULL DEFAULT 'manual', actor TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL, outcome TEXT, plan TEXT, verdict TEXT, error TEXT,
                steps_used INTEGER NOT NULL DEFAULT 0, models TEXT, job_id TEXT, narrative TEXT, feedback TEXT);
            CREATE TABLE IF NOT EXISTS steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT, hunt_id TEXT NOT NULL, n INTEGER NOT NULL,
                ts TEXT NOT NULL, kind TEXT NOT NULL, connector TEXT, tool TEXT, role TEXT,
                arguments TEXT, why TEXT, ok INTEGER, ms INTEGER, result TEXT, note TEXT);
            CREATE INDEX IF NOT EXISTS steps_hunt ON steps(hunt_id, n);
            """)
            for col in ("job_id", "narrative", "feedback", "restricted"):
                db.add_column(c, "hunts", col, "TEXT")

    def _conn(self):
        c = db.connect(self.path)
        return c

    def create(self, hypothesis: str, *, origin: str = "manual", actor: str = "", hunt_id: str | None = None) -> str:
        hid = hunt_id or uuid.uuid4().hex[:12]
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO hunts (id, created, hypothesis, origin, actor, status) VALUES (?,?,?,?,?,?)",
                      (hid, _now(), hypothesis[:4000], origin[:100], actor[:100], "queued"))
        return hid

    def update(self, hid: str, **fields: Any) -> None:
        for k in ("plan", "verdict", "models", "feedback"):
            if k in fields and not isinstance(fields[k], str) and fields[k] is not None:
                fields[k] = json.dumps(fields[k])
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._lock, self._conn() as c:
            # Column names and placeholders are fixed in code; values are always bound.
            c.execute(f"UPDATE hunts SET {cols} WHERE id=?", (*fields.values(), hid))  # nosec B608

    def add_step(self, hid: str, n: int, kind: str, *, connector: str = "", tool: str = "", role: str = "",
                 arguments: Any = None, why: str = "", ok: bool | None = None, ms: int = 0, result: str = "",
                 note: str = "") -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO steps (hunt_id, n, ts, kind, connector, tool, role, arguments, why, ok, ms, "
                      "result, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (hid, n, _now(), kind, connector, tool, role,
                       json.dumps(arguments) if arguments is not None else None, why[:1000],
                       None if ok is None else int(ok), ms, result[:60_000], note[:2000]))

    @staticmethod
    def _hunt(r: sqlite3.Row) -> dict:
        d = dict(r)
        for k in ("plan", "verdict", "models", "feedback", "restricted"):
            d[k] = json.loads(d[k]) if d.get(k) else None
        d["feedback"] = d["feedback"] or []
        d["restricted"] = d["restricted"] or []
        return d

    def add_restricted(self, hid: str, connector: str) -> None:
        """Record that this hunt read a connector with ``access`` limits (see actaeon/access.py)."""
        with self._lock, self._conn() as c:
            r = c.execute("SELECT restricted FROM hunts WHERE id=?", (hid,)).fetchone()
            if not r:
                return
            cur = json.loads(r["restricted"]) if r["restricted"] else []
            if connector not in cur:
                c.execute("UPDATE hunts SET restricted=? WHERE id=?", (json.dumps(sorted([*cur, connector])), hid))

    def restricted_of(self, hid: str) -> list[str]:
        with self._conn() as c:
            r = c.execute("SELECT restricted FROM hunts WHERE id=?", (hid,)).fetchone()
        return json.loads(r["restricted"]) if r and r["restricted"] else []

    def get(self, hid: str, with_steps: bool = True) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM hunts WHERE id=?", (hid,)).fetchone()
            if not r:
                return None
            d = self._hunt(r)
            from ..access import can_see
            if not can_see(d["restricted"]):
                return None
            if with_steps:
                d["steps"] = []
                for s in c.execute("SELECT * FROM steps WHERE hunt_id=? ORDER BY id", (hid,)):
                    s = dict(s)
                    s["arguments"] = json.loads(s["arguments"]) if s["arguments"] else None
                    s["ok"] = None if s["ok"] is None else bool(s["ok"])
                    d["steps"].append(s)
        return d

    def list(self, limit: int = 50, origin: str | None = None) -> list[dict]:
        q, a = "SELECT * FROM hunts", []
        if origin:
            q += " WHERE origin LIKE ?"
            a.append(f"{origin}%")
        q += " ORDER BY created DESC LIMIT ?"
        a.append(int(limit))
        from ..access import can_see
        with self._conn() as c:
            return [h for h in (self._hunt(r) for r in c.execute(q, a)) if can_see(h["restricted"])]

    def mark_orphans(self) -> None:
        """Hunts left running by a restart can never finish; mark them stopped."""
        with self._lock, self._conn() as c:
            c.execute("UPDATE hunts SET status='stopped', error='interrupted by a restart', finished=? "
                      "WHERE status IN ('queued','running')", (_now(),))

    def good_queries(self, connector: str, limit: int = 5) -> list[str]:
        """Recent queries on a connector that returned data (used as examples for later hunts)."""
        from .signals import hits
        out: list[str] = []
        with self._conn() as c:
            rows = c.execute("SELECT arguments, result FROM steps WHERE connector=? AND kind='call' AND ok=1 "
                             "AND tool NOT IN ('get_fields','list_indices') ORDER BY id DESC LIMIT 300", (connector,))
            for r in rows:
                try:
                    args = json.loads(r["arguments"] or "{}")
                except ValueError:
                    continue
                q = args.get("query") if isinstance(args, dict) else None
                if not isinstance(q, str) or not q.strip() or q in out:
                    continue
                if (hits(r["result"] or "") or 0) > 0:
                    out.append(q[:500])
                if len(out) >= limit:
                    break
        return out
