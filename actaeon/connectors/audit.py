"""Append-only audit log of every connector tool call (SQLite)."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SECRETISH = re.compile(r"(?i)(pass(word)?|secret|token|api[_-]?key|authorization|cookie)")


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("***" if _SECRETISH.search(str(k)) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


class AuditLog:
    def __init__(self, db_path: Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT, hunt_id TEXT,
                connector TEXT NOT NULL, tool TEXT NOT NULL, arguments TEXT, decision TEXT NOT NULL,
                status TEXT NOT NULL, attempts INTEGER, duration_ms INTEGER, result_bytes INTEGER,
                error TEXT)""")
            c.execute("CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts)")
            # append-only: refuse updates and deletes at the database level
            c.execute("CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit "
                      "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END")
            c.execute("CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit "
                      "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END")

    def _conn(self):
        return sqlite3.connect(self.path, timeout=10)

    def record(self, *, connector: str, tool: str, arguments: dict, decision: str, status: str,
               actor: str = "", hunt_id: str = "", attempts: int = 0, duration_ms: int = 0,
               result_bytes: int = 0, error: str = "") -> None:
        row = (datetime.now(timezone.utc).isoformat(timespec="seconds"), actor, hunt_id, connector, tool,
               json.dumps(redact(arguments), sort_keys=True)[:4000], decision, status, attempts,
               duration_ms, result_bytes, error[:1000])
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO audit (ts, actor, hunt_id, connector, tool, arguments, decision, status, "
                      "attempts, duration_ms, result_bytes, error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", row)

    def recent(self, limit: int = 100, hunt_id: str | None = None) -> list[dict]:
        q = "SELECT * FROM audit"
        args: tuple = ()
        if hunt_id:
            q += " WHERE hunt_id=?"
            args = (hunt_id,)
        q += " ORDER BY id DESC LIMIT ?"
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute(q, (*args, int(limit)))]
