"""Cases: what an analyst works on.

A case opens automatically for every finished hunt, sweep or replay whose result
is a threat or needs review. Life cycle:

    new -> acknowledged (assigned to whoever acknowledges) -> in_progress -> closed
    closed -> reopened (back to acknowledged)

Closing needs a resolution: true_positive, benign_true_positive, false_positive,
duplicate or other, and a comment. Every change is an event with who and when,
and everyone can see every case. Closing as benign or false positive also adds
a memory note, so related hunts later know about it.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

STATUSES = ("new", "acknowledged", "in_progress", "closed")
RESOLUTIONS = ("true_positive", "benign_true_positive", "false_positive", "duplicate", "other")
SEVERITIES = ("critical", "high", "medium", "low")
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def severity_of(h: dict) -> str:
    v = h.get("verdict") or {}
    conf = int(v.get("confidence") or 0)
    if h.get("outcome") == "threat":
        if (v.get("verification") or {}).get("result") == "confirmed" and conf >= 85:
            return "critical"
        return "high" if conf >= 70 else "medium"
    if not v.get("needs_review") or h.get("outcome") == "logs_missing":
        return "low"
    return "medium"


class LeadStore:
    def __init__(self, path):
        self.path = path
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT, hunt_id TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
                severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', assignee TEXT NOT NULL DEFAULT '',
                resolution TEXT NOT NULL DEFAULT '', created TEXT NOT NULL, updated TEXT NOT NULL,
                acknowledged_at TEXT, closed_at TEXT, closed_by TEXT NOT NULL DEFAULT '', origin TEXT,
                outcome TEXT, confidence INTEGER);
            CREATE TABLE IF NOT EXISTS lead_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, lead_id INTEGER NOT NULL, ts TEXT NOT NULL,
                user TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
            CREATE INDEX IF NOT EXISTS lead_status ON leads(status);
            """)

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def _event(self, c, cid: int, user: str, action: str, detail: str = "") -> None:
        c.execute("INSERT INTO lead_events (lead_id, ts, user, action, detail) VALUES (?,?,?,?,?)",
                  (cid, _now(), user or "system", action, detail[:4000]))

    def open_for(self, h: dict) -> dict | None:
        """Open (or refresh) a lead for a finished hunt that is a threat or needs review."""
        v = h.get("verdict") or {}
        if not (h.get("outcome") == "threat" or v.get("needs_review")):
            return None
        sev = severity_of(h)
        label = "needs analyst" if v.get("handoff") and h.get("outcome") != "threat" else (h.get("outcome") or "review")
        title = f"{label.replace('_', ' ')}: {h.get('hypothesis', '')[:160]}"
        with _lock, self._conn() as c:
            row = c.execute("SELECT * FROM leads WHERE hunt_id=?", (h["id"],)).fetchone()
            if not row and v.get("handoff") and h.get("outcome") != "threat":
                # The same unanswered question again (a replay or schedule): note it on the open lead.
                same = c.execute("SELECT * FROM leads WHERE title=? AND status!='closed' ORDER BY id DESC LIMIT 1",
                                 (title,)).fetchone()
                if same:
                    c.execute("UPDATE leads SET updated=? WHERE id=?", (_now(), same["id"]))
                    self._event(c, same["id"], "system", "seen again", f"hunt {h['id']}: {v['handoff']['reason'][:300]}")
                    return self.get(same["id"])
            if row:
                c.execute("UPDATE leads SET severity=?, outcome=?, confidence=?, updated=? WHERE id=?",
                          (sev, h.get("outcome"), int(v.get("confidence") or 0), _now(), row["id"]))
                self._event(c, row["id"], "system", "updated", f"verdict now {h.get('outcome')}")
                cid = row["id"]
            else:
                cur = c.execute("INSERT INTO leads (hunt_id, title, severity, created, updated, origin, outcome, "
                                "confidence) VALUES (?,?,?,?,?,?,?,?)",
                                (h["id"], title, sev, _now(), _now(), h.get("origin", ""), h.get("outcome"),
                                 int(v.get("confidence") or 0)))
                cid = cur.lastrowid
                self._event(c, cid, "system", "opened", v.get("summary", "")[:500])
        return self.get(cid)

    def get(self, cid: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM leads WHERE id=?", (int(cid),)).fetchone()
            if not r:
                return None
            d = dict(r)
            d["events"] = [dict(e) for e in c.execute("SELECT * FROM lead_events WHERE lead_id=? ORDER BY id",
                                                      (int(cid),))]
        return d

    def by_hunt(self, hid: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT id FROM leads WHERE hunt_id=?", (hid,)).fetchone()
        return self.get(r["id"]) if r else None

    def list(self, *, status: str | None = None, assignee: str | None = None, severity: str | None = None,
             open_only: bool = False, limit: int = 500) -> list[dict]:
        q, a = ["SELECT * FROM leads WHERE 1=1"], []
        if status:
            q.append("AND status=?")
            a.append(status)
        if open_only:
            q.append("AND status<>'closed'")
        if assignee is not None:
            q.append("AND assignee=?")
            a.append(assignee)
        if severity:
            q.append("AND severity=?")
            a.append(severity)
        q.append("ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, "
                 "id DESC LIMIT ?")
        a.append(int(limit))
        with self._conn() as c:
            return [dict(r) for r in c.execute(" ".join(q), a)]

    # ---- actions ----
    def _change(self, cid: int, user: str, action: str, detail: str, **fields) -> dict:
        with _lock, self._conn() as c:
            if not c.execute("SELECT 1 FROM leads WHERE id=?", (int(cid),)).fetchone():
                raise LookupError("no such lead")
            fields["updated"] = _now()
            cols = ", ".join(f"{k}=?" for k in fields)
            # Column names and placeholders are fixed in code; values are always bound.
            c.execute(f"UPDATE leads SET {cols} WHERE id=?", (*fields.values(), int(cid)))  # nosec B608
            self._event(c, int(cid), user, action, detail)
        return self.get(cid) or {}

    def acknowledge(self, cid: int, user: str) -> dict:
        lead = self.get(cid)
        if not lead:
            raise LookupError("no such lead")
        if lead["status"] == "closed":
            raise ValueError("lead is closed; reopen it first")
        return self._change(cid, user, "acknowledged", f"assigned to {user}", status="acknowledged", assignee=user,
                            acknowledged_at=lead["acknowledged_at"] or _now())

    def assign(self, cid: int, user: str, to: str) -> dict:
        if not to:
            raise ValueError("assignee is required")
        return self._change(cid, user, "assigned", f"assigned to {to}", assignee=to)

    def set_status(self, cid: int, user: str, status: str) -> dict:
        if status not in ("acknowledged", "in_progress"):
            raise ValueError("status must be acknowledged or in_progress (use close to close)")
        return self._change(cid, user, "status", status, status=status)

    def close(self, cid: int, user: str, resolution: str, comment: str) -> dict:
        if resolution not in RESOLUTIONS:
            raise ValueError(f"resolution must be one of {RESOLUTIONS}")
        if not (comment or "").strip():
            raise ValueError("a closing comment is required")
        lead = self.get(cid)
        if not lead:
            raise LookupError("no such lead")
        return self._change(cid, user, "closed", f"{resolution}: {comment.strip()}", status="closed",
                            resolution=resolution, closed_at=_now(), closed_by=user,
                            assignee=lead["assignee"] or user)

    def reopen(self, cid: int, user: str, comment: str = "") -> dict:
        return self._change(cid, user, "reopened", comment.strip(), status="acknowledged", resolution="",
                            closed_at=None, closed_by="")

    def comment(self, cid: int, user: str, text: str) -> dict:
        if not (text or "").strip():
            raise ValueError("comment is empty")
        return self._change(cid, user, "comment", text.strip())

    def stats(self) -> dict:
        with self._conn() as c:
            rows = [dict(r) for r in c.execute("SELECT status, severity, resolution, created, acknowledged_at, "
                                                "closed_at FROM leads")]

        def mins(a, b):
            try:
                return (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 60
            except (TypeError, ValueError):
                return None
        ack = [m for m in (mins(r["created"], r["acknowledged_at"]) for r in rows) if m is not None]
        res = [m for m in (mins(r["created"], r["closed_at"]) for r in rows) if m is not None]
        by = lambda k: {x: sum(1 for r in rows if r[k] == x) for x in {r[k] for r in rows if r[k]}}  # noqa: E731
        return {"total": len(rows), "open": sum(r["status"] != "closed" for r in rows),
                "new": sum(r["status"] == "new" for r in rows), "by_status": by("status"),
                "by_severity_open": {s: sum(1 for r in rows if r["severity"] == s and r["status"] != "closed")
                                     for s in SEVERITIES},
                "by_resolution": by("resolution"),
                "mean_minutes_to_acknowledge": round(sum(ack) / len(ack), 1) if ack else None,
                "mean_minutes_to_close": round(sum(res) / len(res), 1) if res else None}

    def export_json(self) -> str:
        return json.dumps([self.get(c["id"]) for c in self.list(limit=100000)], indent=1)
