"""Storage for alerts, cases, investigation steps, actions, suppressions and notes (SQLite, or PostgreSQL
through actaeon/db.py; table names start with soc_ because PostgreSQL keeps every store in one schema)."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from .. import db
from .util import ago, dumps, iso, loads, new_id

RESULT_CHARS = 200_000      # per stored tool result (what the case page and the evidence bundle show)
VERDICTS = ("true_positive", "false_positive", "benign", "needs_analyst", "logs_missing")
STATUSES = ("new", "triaging", "triaged", "needs_analyst", "closed", "error")
ACTION_STATES = ("proposed", "rejected", "dry_run", "executed", "failed", "undone", "manual", "stale", "expired")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS soc_alerts (
  id TEXT PRIMARY KEY, source TEXT, rule_id TEXT, rule_name TEXT, title TEXT, description TEXT,
  severity INTEGER, severity_label TEXT, ts TEXT, fingerprint TEXT, entities TEXT, attack TEXT,
  command_line TEXT, raw TEXT, case_id TEXT, status TEXT, received TEXT, dup_count INTEGER DEFAULT 0,
  last_seen TEXT);
CREATE INDEX IF NOT EXISTS soc_alerts_case ON soc_alerts(case_id);
CREATE INDEX IF NOT EXISTS soc_alerts_fp ON soc_alerts(fingerprint);
CREATE INDEX IF NOT EXISTS soc_alerts_ts ON soc_alerts(ts);
CREATE TABLE IF NOT EXISTS soc_cases (
  id TEXT PRIMARY KEY, title TEXT, status TEXT, verdict TEXT, confidence INTEGER, severity INTEGER,
  severity_label TEXT, summary TEXT, report TEXT, attack TEXT, first_look TEXT, created TEXT, updated TEXT,
  first_alert TEXT, last_alert TEXT, triaged_at TEXT, closed_at TEXT, closed_by TEXT, analyst_verdict TEXT,
  analyst_note TEXT, assignee TEXT, usage TEXT, error TEXT, restricted TEXT, job_id TEXT, origin TEXT);
CREATE INDEX IF NOT EXISTS soc_cases_status ON soc_cases(status);
CREATE TABLE IF NOT EXISTS soc_entities (
  case_id TEXT, type TEXT, value TEXT, lvalue TEXT, PRIMARY KEY (case_id, type, lvalue));
CREATE INDEX IF NOT EXISTS soc_case_entities_v ON soc_entities(type, lvalue);
CREATE TABLE IF NOT EXISTS soc_steps (
  case_id TEXT, n INTEGER, kind TEXT, connector TEXT, tool TEXT, role TEXT, arguments TEXT, why TEXT,
  ok INTEGER, result TEXT, note TEXT, ts TEXT, PRIMARY KEY (case_id, n));
CREATE TABLE IF NOT EXISTS soc_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, name TEXT, target TEXT, connector TEXT, tool TEXT,
  arguments TEXT, reason TEXT, tier INTEGER, status TEXT, proposed_at TEXT, approvers TEXT, decided_by TEXT,
  decided_at TEXT, result TEXT, undo TEXT, executed_at TEXT, description TEXT, basis TEXT, undo_kind TEXT,
  requested_by TEXT, expires TEXT);
CREATE INDEX IF NOT EXISTS soc_actions_case ON soc_actions(case_id);
CREATE TABLE IF NOT EXISTS soc_suppressions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT, entity_type TEXT, entity_value TEXT, reason TEXT,
  created_by TEXT, created TEXT, expires TEXT, hits INTEGER DEFAULT 0, case_id TEXT, enabled INTEGER DEFAULT 1,
  high_hits INTEGER DEFAULT 0, last_hit TEXT);
CREATE TABLE IF NOT EXISTS soc_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, author TEXT, text TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS soc_bookmarks (name TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS soc_usage (day TEXT PRIMARY KEY, tokens INTEGER DEFAULT 0, calls INTEGER DEFAULT 0);
"""


def _row(r) -> dict:
    return dict(r) if r is not None else {}


class SocStore:
    def __init__(self, path: Path, *, scratch: bool = False):
        """``scratch``: always a SQLite file at ``path``, even when the deployment uses PostgreSQL (the
        benchmark's throw-away stores must never share tables with the live queue)."""
        self.path = Path(path)
        self.scratch = scratch
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._conn() as c:
            c.executescript(_SCHEMA)
            for col in ("basis", "undo_kind", "requested_by", "expires"):    # stores made by earlier versions
                db.add_column(c, "soc_actions", col, "TEXT")
            for col, ddl in (("high_hits", "INTEGER DEFAULT 0"), ("last_hit", "TEXT")):
                db.add_column(c, "soc_suppressions", col, ddl)

    def _conn(self):
        if self.scratch:
            import sqlite3
            c = sqlite3.connect(self.path, timeout=10)
            c.row_factory = sqlite3.Row
            return c
        return db.connect(self.path)

    # ---- alerts ----
    def get_alert(self, alert_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM soc_alerts WHERE id=?", (alert_id,)).fetchone()
        return self._alert(r) if r else None

    @staticmethod
    def _alert(r) -> dict:
        d = _row(r)
        d["entities"] = loads(d.get("entities"), [])
        d["attack"] = loads(d.get("attack"), [])
        d["raw"] = loads(d.get("raw"), {})
        return d

    def add_alert(self, a: dict, *, status: str = "new") -> tuple[str, bool]:
        """Insert a normalised alert. Returns (id, is_new). A repeat of the same id bumps dup_count."""
        with self._lock, self._conn() as c:
            r = c.execute("SELECT id FROM soc_alerts WHERE id=?", (a["id"],)).fetchone()
            if r:
                c.execute("UPDATE soc_alerts SET dup_count=dup_count+1, last_seen=? WHERE id=?", (iso(), a["id"]))
                c.commit()
                return a["id"], False
            c.execute("INSERT INTO soc_alerts (id, source, rule_id, rule_name, title, description, severity, "
                      "severity_label, ts, fingerprint, entities, attack, command_line, raw, case_id, status, "
                      "received, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (a["id"], a["source"], a["rule_id"], a["rule_name"], a["title"], a.get("description", ""),
                       a["severity"], a["severity_label"], a["ts"], a["fingerprint"], dumps(a["entities"]),
                       dumps(a.get("attack") or []), a.get("command_line", ""), dumps(a.get("raw") or {})[:60000],
                       None, status, iso(), iso()))
            c.commit()
        return a["id"], True

    def set_alert(self, alert_id: str, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)   # keys are fixed names from this module
        with self._lock, self._conn() as c:
            c.execute(f"UPDATE soc_alerts SET {cols} WHERE id=?", (*fields.values(), alert_id))  # nosec B608
            c.commit()

    def alerts(self, *, case_id: str | None = None, status: str | None = None, limit: int = 200,
               since: str | None = None, q: str = "") -> list[dict]:
        sql, args = "SELECT * FROM soc_alerts WHERE 1=1", []
        if case_id:
            sql += " AND case_id=?"
            args.append(case_id)
        if status:
            sql += " AND status=?"
            args.append(status)
        if since:
            sql += " AND ts>=?"
            args.append(since)
        if q:
            sql += " AND (title LIKE ? OR rule_name LIKE ? OR entities LIKE ?)"
            args += [f"%{q}%"] * 3
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(int(limit))
        with self._conn() as c:
            return [self._alert(r) for r in c.execute(sql, args)]

    # ---- cases ----
    @staticmethod
    def _case(r) -> dict:
        d = _row(r)
        for k, dv in (("report", {}), ("attack", []), ("first_look", {}), ("usage", {}), ("restricted", [])):
            d[k] = loads(d.get(k), dv)
        return d

    def new_case(self, title: str, severity: int, severity_label: str, first_alert: str, *, origin: str = "intake") -> str:
        cid = new_id()
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO soc_cases (id, title, status, severity, severity_label, created, updated, first_alert, "
                      "last_alert, origin) VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (cid, title[:300], "new", severity, severity_label, iso(), iso(), first_alert, first_alert, origin))
            c.commit()
        return cid

    def attach(self, case_id: str, alert: dict) -> None:
        """Put an alert in a case: severity and time span follow the alerts; entities are indexed."""
        with self._lock, self._conn() as c:
            c.execute("UPDATE soc_alerts SET case_id=?, status='grouped' WHERE id=?", (case_id, alert["id"]))
            cur = c.execute("SELECT severity, first_alert, last_alert, status FROM soc_cases WHERE id=?", (case_id,)).fetchone()
            if cur:
                from .alerts import severity_label
                sev = max(int(cur["severity"] or 0), int(alert["severity"]))
                first = min(cur["first_alert"] or alert["ts"], alert["ts"])
                last = max(cur["last_alert"] or alert["ts"], alert["ts"])
                c.execute("UPDATE soc_cases SET severity=?, severity_label=?, first_alert=?, last_alert=?, updated=? "
                          "WHERE id=?", (sev, severity_label(sev), first, last, iso(), case_id))
            for e in alert.get("entities") or []:
                c.execute("INSERT INTO soc_entities (case_id, type, value, lvalue) VALUES (?,?,?,?) ON CONFLICT (case_id, type, lvalue) DO NOTHING",
                          (case_id, e["type"], e["value"], e["value"].lower()))
            c.commit()

    def add_entities(self, case_id: str, entities: list[dict]) -> None:
        with self._lock, self._conn() as c:
            for e in entities:
                if e.get("type") and e.get("value"):
                    c.execute("INSERT INTO soc_entities (case_id, type, value, lvalue) VALUES (?,?,?,?) ON CONFLICT (case_id, type, lvalue) DO NOTHING",
                              (case_id, str(e["type"])[:40], str(e["value"])[:512], str(e["value"]).lower()[:512]))
            c.commit()

    def get_case(self, case_id: str, *, full: bool = True) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM soc_cases WHERE id=?", (case_id,)).fetchone()
            if not r:
                return None
            d = self._case(r)
            if full:
                d["entities"] = [dict(x) for x in c.execute(
                    "SELECT type, value FROM soc_entities WHERE case_id=? ORDER BY type, value", (case_id,))]
                d["steps"] = [self._step(x) for x in c.execute("SELECT * FROM soc_steps WHERE case_id=? ORDER BY n",
                                                               (case_id,))]
                d["actions"] = [self._action(x) for x in c.execute(
                    "SELECT * FROM soc_actions WHERE case_id=? ORDER BY id", (case_id,))]
                d["notes"] = [dict(x) for x in c.execute("SELECT * FROM soc_notes WHERE case_id=? ORDER BY id", (case_id,))]
        if full:
            d["alerts"] = self.alerts(case_id=case_id, limit=500)
        return d

    def set_case(self, case_id: str, **fields) -> None:
        enc = {k: (dumps(v) if isinstance(v, (dict, list)) else v) for k, v in fields.items()}
        enc["updated"] = iso()
        cols = ", ".join(f"{k}=?" for k in enc)   # keys are fixed names from this module and service.py
        with self._lock, self._conn() as c:
            c.execute(f"UPDATE soc_cases SET {cols} WHERE id=?", (*enc.values(), case_id))  # nosec B608
            c.commit()

    def cases(self, *, status: str | None = None, verdict: str | None = None, limit: int = 200,
              open_only: bool = False, since: str | None = None) -> list[dict]:
        sql, args = ("SELECT c.*, (SELECT COUNT(*) FROM soc_alerts a WHERE a.case_id=c.id) AS alert_count, "
                     "(SELECT COUNT(*) FROM soc_actions x WHERE x.case_id=c.id AND x.status='proposed') AS pending_actions "
                     "FROM soc_cases c WHERE 1=1"), []
        if status:
            sql += " AND c.status=?"
            args.append(status)
        if verdict:
            sql += " AND c.verdict=?"
            args.append(verdict)
        if open_only:
            sql += " AND c.status!='closed'"
        if since:
            sql += " AND c.created>=?"
            args.append(since)
        sql += " ORDER BY c.severity DESC, c.updated DESC LIMIT ?"
        args.append(int(limit))
        with self._conn() as c:
            return [self._case(r) for r in c.execute(sql, args)]

    def open_case_for(self, *, fingerprint: str, entities: list[dict], since: str, until: str) -> str | None:
        """An open case whose alerts lie within the window (``since`` .. ``until``) and that already holds this
        fingerprint, or shares a grouping entity (see alerts.group_keys)."""
        with self._conn() as c:
            r = c.execute("SELECT a.case_id FROM soc_alerts a JOIN soc_cases c ON c.id=a.case_id WHERE a.fingerprint=? "
                          "AND c.status NOT IN ('closed') AND c.last_alert>=? AND c.first_alert<=? ORDER BY c.updated DESC "
                          "LIMIT 1", (fingerprint, since, until)).fetchone()
            if r:
                return r[0]
            from .alerts import group_keys
            keys = group_keys(entities)
            for t, v in keys:
                r = c.execute("SELECT ce.case_id FROM soc_entities ce JOIN soc_cases c ON c.id=ce.case_id WHERE "
                              "ce.type=? AND ce.lvalue=? AND c.status IN ('new','triaging') AND c.last_alert>=? "
                              "AND c.first_alert<=? ORDER BY c.updated DESC LIMIT 1", (t, v, since, until)).fetchone()
                if r:
                    return r[0]
        return None

    def related_cases(self, case_id: str, limit: int = 10) -> list[dict]:
        """Other cases that share entities with this one (most shared first), with their verdicts."""
        shared: dict[str, list[str]] = {}
        with self._conn() as c:
            for r in c.execute(
                    "SELECT o.case_id, o.type, o.value FROM soc_entities me JOIN soc_entities o ON o.type=me.type "
                    "AND o.lvalue=me.lvalue AND o.case_id!=me.case_id WHERE me.case_id=? AND me.type NOT IN ('process')",
                    (case_id,)):
                shared.setdefault(r[0], []).append(f"{r[1]}:{r[2]}")
            out = []
            for cid, vals in sorted(shared.items(), key=lambda kv: -len(kv[1]))[:int(limit)]:
                cr = c.execute("SELECT id, title, status, verdict, analyst_verdict, confidence, created, summary, "
                               "restricted FROM soc_cases WHERE id=?", (cid,)).fetchone()
                if cr:
                    out.append({**dict(cr), "shared": len(vals), "shared_values": ", ".join(vals)[:300]})
        return out

    def rule_history(self, rule: str, limit: int = 20) -> dict:
        """How earlier cases with this rule ended (AI verdict and the analyst's)."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT DISTINCT c.id, c.verdict, c.analyst_verdict, c.closed_at FROM soc_cases c JOIN soc_alerts a ON a.case_id=c.id "
                "WHERE (a.rule_id=? OR a.rule_name=?) AND c.status='closed' ORDER BY c.closed_at DESC LIMIT ?",
                (rule, rule, int(limit))).fetchall()
        final = [r["analyst_verdict"] or r["verdict"] for r in rows]
        return {"closed": len(final), "true_positive": final.count("true_positive"),
                "false_positive": final.count("false_positive"), "benign": final.count("benign")}

    # ---- steps ----
    @staticmethod
    def _step(r) -> dict:
        d = _row(r)
        d["arguments"] = loads(d.get("arguments"), {})
        d["ok"] = bool(d.get("ok"))
        return d

    def add_step(self, case_id: str, n: int, kind: str, *, connector: str = "", tool: str = "", role: str = "",
                 arguments: dict | None = None, why: str = "", ok: bool = True, result: str = "", note: str = "") -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM soc_steps WHERE case_id=? AND n=?", (case_id, n))
            c.execute("INSERT INTO soc_steps (case_id, n, kind, connector, tool, role, arguments, why, ok, "
                      "result, note, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                      (case_id, n, kind, connector, tool, role, dumps(arguments or {}), why[:1000], int(ok),
                       result[:RESULT_CHARS], (note + (f" (result cut to {RESULT_CHARS} characters)"
                                                     if len(result) > RESULT_CHARS else ""))[:2000], iso()))
            c.commit()

    def clear_steps(self, case_id: str) -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM soc_steps WHERE case_id=?", (case_id,))
            c.execute("DELETE FROM soc_actions WHERE case_id=? AND status IN ('proposed','manual')", (case_id,))
            c.commit()

    # ---- actions ----
    @staticmethod
    def _action(r) -> dict:
        d = _row(r)
        d["arguments"] = loads(d.get("arguments"), {})
        d["approvers"] = loads(d.get("approvers"), [])
        d["undo"] = loads(d.get("undo"), None)
        return d

    def add_action(self, case_id: str, **a) -> int:
        with self._lock, self._conn() as c:
            cur = c.execute("INSERT INTO soc_actions (case_id, name, target, connector, tool, arguments, reason, tier, "
                            "status, proposed_at, approvers, undo, description, basis, undo_kind, requested_by, expires) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (case_id, a.get("name", ""), a.get("target", ""), a.get("connector", ""), a.get("tool", ""),
                             dumps(a.get("arguments") or {}), str(a.get("reason", ""))[:1000], int(a.get("tier", 2)),
                             a.get("status", "proposed"), iso(), "[]", dumps(a.get("undo")) if a.get("undo") else None,
                             str(a.get("description", ""))[:500], a.get("basis", ""), a.get("undo_kind", ""),
                             str(a.get("requested_by", ""))[:100], a.get("expires")))
            c.commit()
            return int(cur.lastrowid)

    def expire_actions(self) -> int:
        """Proposals past their expiry lapse with a recorded outcome instead of waiting for ever."""
        with self._lock, self._conn() as c:
            n = c.execute("UPDATE soc_actions SET status='expired', decided_at=?, result='Not decided before it "
                          "expired; propose it again if it is still needed.' WHERE status='proposed' AND expires IS "
                          "NOT NULL AND expires!='' AND expires<?", (iso(), iso())).rowcount
            c.commit()
        return int(n or 0)

    def get_action(self, action_id: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM soc_actions WHERE id=?", (int(action_id),)).fetchone()
        return self._action(r) if r else None

    def set_action(self, action_id: int, **fields) -> None:
        enc = {k: (dumps(v) if isinstance(v, (dict, list)) else v) for k, v in fields.items()}
        cols = ", ".join(f"{k}=?" for k in enc)   # fixed names from soc/response.py
        with self._lock, self._conn() as c:
            c.execute(f"UPDATE soc_actions SET {cols} WHERE id=?", (*enc.values(), int(action_id)))  # nosec B608
            c.commit()

    def actions(self, *, status: str | None = None, limit: int = 200) -> list[dict]:
        sql, args = "SELECT * FROM soc_actions", []
        if status:
            sql += " WHERE status=?"
            args.append(status)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        with self._conn() as c:
            return [self._action(r) for r in c.execute(sql, args)]

    # ---- suppressions ----
    def add_suppression(self, *, rule: str, entity_type: str = "", entity_value: str = "", reason: str = "",
                        created_by: str = "", days: int = 30, case_id: str = "") -> int:
        if not rule:
            raise ValueError("a suppression needs a rule id or name")
        if entity_type and entity_type not in ("host", "user", "ip", "process", "domain", "hash", "file", "url"):
            raise ValueError("entity_type must be host, user, ip, process, domain, hash, file or url")
        expires = ago(days=-max(1, min(365, int(days))))
        with self._lock, self._conn() as c:
            cur = c.execute("INSERT INTO soc_suppressions (rule, entity_type, entity_value, reason, created_by, created, "
                            "expires, case_id) VALUES (?,?,?,?,?,?,?,?)",
                            (rule[:300], entity_type, entity_value[:512], reason[:500], created_by, iso(), expires,
                             case_id))
            c.commit()
            return int(cur.lastrowid)

    def suppressions(self, *, active_only: bool = True) -> list[dict]:
        sql = "SELECT * FROM soc_suppressions"
        if active_only:
            sql += " WHERE enabled=1 AND expires>?"
        with self._conn() as c:
            rows = c.execute(sql + " ORDER BY id DESC", (iso(),) if active_only else ()).fetchall()
        return [dict(r) for r in rows]

    def disable_suppression(self, sid: int) -> None:
        with self._lock, self._conn() as c:
            c.execute("UPDATE soc_suppressions SET enabled=0 WHERE id=?", (int(sid),))
            c.commit()

    def hit_suppression(self, sid: int, *, high: bool = False) -> None:
        """Count a suppressed alert; ``high``: it was high or critical severity (shown as a warning)."""
        with self._lock, self._conn() as c:
            c.execute("UPDATE soc_suppressions SET hits=hits+1, high_hits=high_hits+?, last_hit=? WHERE id=?",
                      (int(high), iso(), int(sid)))
            c.commit()

    def triaged_today(self) -> int:
        with self._conn() as c:
            return int(c.execute("SELECT COUNT(*) FROM soc_cases WHERE triaged_at>=?", (iso()[:10],)).fetchone()[0])

    # ---- notes, bookmarks, usage, access ----
    def add_note(self, case_id: str, author: str, text: str) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO soc_notes (case_id, author, text, ts) VALUES (?,?,?,?)",
                      (case_id, author[:100], text[:4000], iso()))
            c.commit()

    def bookmark(self, name: str, value: str | None = None) -> str | None:
        with self._lock, self._conn() as c:
            if value is None:
                r = c.execute("SELECT value FROM soc_bookmarks WHERE name=?", (name,)).fetchone()
                return r[0] if r else None
            c.execute("DELETE FROM soc_bookmarks WHERE name=?", (name,))
            c.execute("INSERT INTO soc_bookmarks (name, value) VALUES (?,?)", (name, value))
            c.commit()
            return value

    def add_usage(self, tokens: int, calls: int) -> None:
        day = iso()[:10]
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO soc_usage (day) VALUES (?) ON CONFLICT (day) DO NOTHING", (day,))
            c.execute("UPDATE soc_usage SET tokens=tokens+?, calls=calls+? WHERE day=?", (int(tokens), int(calls), day))
            c.commit()

    def usage_today(self) -> int:
        with self._conn() as c:
            r = c.execute("SELECT tokens FROM soc_usage WHERE day=?", (iso()[:10],)).fetchone()
        return int(r[0]) if r else 0

    def usage_days(self, days: int = 14) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM soc_usage WHERE day>=? ORDER BY day",
                                               (ago(days=days)[:10],))]

    def add_restricted(self, case_id: str, connector: str) -> None:
        cur = (self.get_case(case_id, full=False) or {}).get("restricted") or []
        if connector not in cur:
            self.set_case(case_id, restricted=[*cur, connector])

    def mark_orphans(self) -> int:
        """Cases left 'triaging' by a restart go back to 'new' so they are triaged again."""
        with self._lock, self._conn() as c:
            n = c.execute("UPDATE soc_cases SET status='new', job_id=NULL WHERE status='triaging'").rowcount
            c.commit()
        return int(n or 0)

    def stats_rows(self, since: str) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT c.id, c.verdict, c.analyst_verdict, c.status, c.severity, c.created, c.first_alert, "
                "c.triaged_at, c.closed_at, c.usage, (SELECT a.rule_name FROM soc_alerts a WHERE a.case_id=c.id "
                "ORDER BY a.ts LIMIT 1) AS rule FROM soc_cases c WHERE c.created>=?", (since,))]

    def rule_counts(self, since: str) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT COALESCE(NULLIF(rule_name,''), rule_id) AS rule, COUNT(*) AS alerts, "
                "SUM(CASE WHEN status='suppressed' THEN 1 ELSE 0 END) AS suppressed, SUM(dup_count) AS duplicates "
                "FROM soc_alerts WHERE received>=? GROUP BY 1 ORDER BY 2 DESC LIMIT 50", (since,))]

    def counts(self) -> dict[str, Any]:
        with self._conn() as c:
            st = {r[0]: r[1] for r in c.execute("SELECT status, COUNT(*) FROM soc_cases GROUP BY status")}
            ve = {r[0]: r[1] for r in c.execute("SELECT verdict, COUNT(*) FROM soc_cases WHERE verdict IS NOT NULL "
                                                "GROUP BY verdict")}
            pend = c.execute("SELECT COUNT(*) FROM soc_actions WHERE status='proposed'").fetchone()[0]
            al = c.execute("SELECT COUNT(*) FROM soc_alerts").fetchone()[0]
        return {"status": st, "verdicts": ve, "pending_actions": pend, "alerts": al}
