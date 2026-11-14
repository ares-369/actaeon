"""Data retention: delete finished hunts, and what hangs off them, after a number of days.

    retention:
      hunts_days: 0        # 0 = keep everything (default)
      jobs_days: 30        # background job records

What a purge deletes, for each finished (done, stopped or error) hunt older than ``hunts_days``: the hunt,
its steps (the stored tool results), its chat, detection drafts, entity records and hunt-memory entry,
and its lead if that lead is closed. It never deletes:

- a hunt whose lead is still open (work in progress stays, whatever its age);
- analyst notes (they have their own expiry, see memory notes);
- the intel store (indicators have their own expiry);
- the audit log of tool calls, which is append-only and hash-chained on purpose. Archive the audit
  database file instead if it grows too large.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import db


def settings(cfg) -> dict:
    r = ((getattr(cfg, "raw", None) or {}).get("retention") or {})
    return {"hunts_days": max(0, int(r.get("hunts_days", 0) or 0)), "jobs_days": max(0, int(r.get("jobs_days", 30) or 0))}


def _tables(c) -> set[str]:
    if db.is_pg():
        return {r[0] for r in c.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = "
                                        "current_schema()")}
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")}


def purge(cfg, *, dry_run: bool = False) -> dict:
    """Delete what is past retention. Returns counts (what would be deleted, with ``dry_run``)."""
    from .hunt.service import store_for
    s = settings(cfg)
    out = {"hunts": 0, "steps": 0, "leads": 0, "kept_open_lead": 0, "jobs": 0, "dry_run": dry_run,
           "hunts_days": s["hunts_days"]}
    path = store_for(cfg).path
    if s["hunts_days"]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=s["hunts_days"])).isoformat(timespec="seconds")
        with db.connect(path) as c:
            tables = _tables(c)
            old = [r[0] for r in c.execute("SELECT id FROM hunts WHERE created < ? AND status IN ('done','stopped','error')",
                                           (cutoff,))]
            for hid in old:
                lead = c.execute("SELECT status FROM leads WHERE hunt_id=?", (hid,)).fetchone() if "leads" in tables else None
                if lead and lead[0] != "closed":
                    out["kept_open_lead"] += 1
                    continue
                out["hunts"] += 1
                out["steps"] += c.execute("SELECT COUNT(*) FROM steps WHERE hunt_id=?", (hid,)).fetchone()[0]
                out["leads"] += 1 if lead else 0
                if dry_run:
                    continue
                c.execute("DELETE FROM steps WHERE hunt_id=?", (hid,))
                for table, col in (("chat", "hunt_id"), ("detections", "hunt_id"), ("entity_seen", "hunt_id"),
                                   ("mem_hunts", "hunt_id")):
                    if table in tables:
                        # table and column names come from the fixed list above
                        c.execute(f"DELETE FROM {table} WHERE {col}=?", (hid,))  # nosec B608
                if lead and "leads" in tables:
                    lid = c.execute("SELECT id FROM leads WHERE hunt_id=?", (hid,)).fetchone()[0]
                    c.execute("DELETE FROM lead_events WHERE lead_id=?", (lid,))
                    c.execute("DELETE FROM leads WHERE id=?", (lid,))
                c.execute("DELETE FROM hunts WHERE id=?", (hid,))
    if s["jobs_days"]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=s["jobs_days"])).isoformat()
        jobs_db = cfg.data_dir / "actaeon.sqlite"
        with db.connect(jobs_db) as c:
            if "jobs" in _tables(c):
                q = "FROM jobs WHERE created < ? AND status NOT IN ('queued','running')"
                out["jobs"] = c.execute("SELECT COUNT(*) " + q, (cutoff,)).fetchone()[0]  # nosec B608
                if not dry_run:
                    c.execute("DELETE " + q, (cutoff,))  # nosec B608
    return out
