"""SQLite record of hunts and every step they took."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
                steps_used INTEGER NOT NULL DEFAULT 0, models TEXT, job_id TEXT);
            CREATE TABLE IF NOT EXISTS steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT, hunt_id TEXT NOT NULL, n INTEGER NOT NULL,
                ts TEXT NOT NULL, kind TEXT NOT NULL, connector TEXT, tool TEXT, role TEXT,
                arguments TEXT, why TEXT, ok INTEGER, ms INTEGER, result TEXT, note TEXT);
            CREATE INDEX IF NOT EXISTS steps_hunt ON steps(hunt_id, n);
            """)

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def create(self, hypothesis: str, *, origin: str = "manual", actor: str = "", hunt_id: str | None = None) -> str:
        hid = hunt_id or uuid.uuid4().hex[:12]
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO hunts (id, created, hypothesis, origin, actor, status) VALUES (?,?,?,?,?,?)",
                      (hid, _now(), hypothesis[:4000], origin[:100], actor[:100], "queued"))
        return hid

    def update(self, hid: str, **fields: Any) -> None:
        for k in ("plan", "verdict", "models"):
            if k in fields and not isinstance(fields[k], str) and fields[k] is not None:
                fields[k] = json.dumps(fields[k])
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._lock, self._conn() as c:
            c.execute(f"UPDATE hunts SET {cols} WHERE id=?", (*fields.values(), hid))

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
        for k in ("plan", "verdict", "models"):
            d[k] = json.loads(d[k]) if d.get(k) else None
        return d

    def get(self, hid: str, with_steps: bool = True) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM hunts WHERE id=?", (hid,)).fetchone()
            if not r:
                return None
            d = self._hunt(r)
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
        with self._conn() as c:
            return [self._hunt(r) for r in c.execute(q, a)]

    def mark_orphans(self) -> None:
        """Hunts left running by a restart can never finish; mark them stopped."""
        with self._lock, self._conn() as c:
            c.execute("UPDATE hunts SET status='stopped', error='interrupted by a restart', finished=? "
                      "WHERE status IN ('queued','running')", (_now(),))
