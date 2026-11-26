"""Storage for investigations (SQLite, or PostgreSQL through actaeon/db.py; tables start with dfir_).

A case holds evidence sources (with their SHA-256), the events parsed from them, detections from Sigma rules
and analyzers, analyst marks (star, tags, comment), notes (hypotheses, questions, findings) and model stories.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .. import db
from ..soc.util import dumps, iso, loads, new_id

NOTE_KINDS = ("hypothesis", "question", "finding", "note")
LEVELS = ("informational", "low", "medium", "high", "critical")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS dfir_cases (
  id TEXT PRIMARY KEY, title TEXT, description TEXT, status TEXT, created TEXT, created_by TEXT, updated TEXT,
  events INTEGER DEFAULT 0, analyzed TEXT);
CREATE TABLE IF NOT EXISTS dfir_sources (
  id TEXT PRIMARY KEY, case_id TEXT, name TEXT, kind TEXT, sha256 TEXT, size INTEGER, events INTEGER,
  errors INTEGER, error_samples TEXT, hosts TEXT, first_ts TEXT, last_ts TEXT, imported TEXT, imported_by TEXT,
  status TEXT, note TEXT);
CREATE INDEX IF NOT EXISTS dfir_sources_case ON dfir_sources(case_id);
CREATE TABLE IF NOT EXISTS dfir_events (
  case_id TEXT, seq INTEGER, source_id TEXT, ts TEXT, host TEXT, channel TEXT, event_id TEXT, usr TEXT,
  process TEXT, summary TEXT, data TEXT, star INTEGER DEFAULT 0, tags TEXT, comment TEXT, level INTEGER DEFAULT 0,
  PRIMARY KEY (case_id, seq));
CREATE INDEX IF NOT EXISTS dfir_events_ts ON dfir_events(case_id, ts);
CREATE INDEX IF NOT EXISTS dfir_events_host ON dfir_events(case_id, host);
CREATE TABLE IF NOT EXISTS dfir_detections (
  case_id TEXT, seq INTEGER, rule_key TEXT, title TEXT, level TEXT, origin TEXT, attack TEXT,
  PRIMARY KEY (case_id, seq, rule_key));
CREATE INDEX IF NOT EXISTS dfir_detections_rule ON dfir_detections(case_id, rule_key);
CREATE TABLE IF NOT EXISTS dfir_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, kind TEXT, text TEXT, author TEXT, ts TEXT, events TEXT,
  status TEXT);
CREATE TABLE IF NOT EXISTS dfir_stories (
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, kind TEXT, ts TEXT, author TEXT, model TEXT, body TEXT);
CREATE TABLE IF NOT EXISTS dfir_analysis (case_id TEXT, name TEXT, ts TEXT, body TEXT, PRIMARY KEY (case_id, name));
"""

ORDER_COLS = {"ts": "ts", "-ts": "ts DESC", "level": "level DESC, ts", "host": "host, ts"}


class DfirStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self):
        return db.connect(self.path)

    # ---- cases ----
    def create_case(self, title: str, description: str, *, actor: str) -> dict:
        cid = new_id()
        t = iso()
        with self._conn() as c:
            c.execute("INSERT INTO dfir_cases (id, title, description, status, created, created_by, updated, events) "
                      "VALUES (?,?,?,?,?,?,?,0)", (cid, title[:300] or "Investigation", description[:4000], "open", t,
                                                   actor, t))
        return self.case(cid)

    def case(self, cid: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM dfir_cases WHERE id=?", (cid,)).fetchone()
        return dict(r) if r else None

    def cases(self) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM dfir_cases ORDER BY updated DESC LIMIT 500")]

    def update_case(self, cid: str, **fields: Any) -> None:
        allowed = {k: v for k, v in fields.items() if k in ("title", "description", "status", "analyzed", "events")}
        if not allowed:
            return
        sets = ", ".join(f"{k}=?" for k in allowed) + ", updated=?"
        with self._conn() as c:
            c.execute(f"UPDATE dfir_cases SET {sets} WHERE id=?", (*allowed.values(), iso(), cid))  # nosec B608

    def delete_case(self, cid: str) -> None:
        with self._lock, self._conn() as c:
            for t in ("dfir_events", "dfir_detections", "dfir_sources", "dfir_notes", "dfir_stories", "dfir_analysis"):
                c.execute(f"DELETE FROM {t} WHERE case_id=?", (cid,))  # nosec B608 - fixed table names
            c.execute("DELETE FROM dfir_cases WHERE id=?", (cid,))

    # ---- sources and events ----
    def add_source(self, cid: str, **f: Any) -> str:
        sid = new_id()
        with self._conn() as c:
            c.execute("INSERT INTO dfir_sources (id, case_id, name, kind, sha256, size, events, errors, imported, "
                      "imported_by, status) VALUES (?,?,?,?,?,?,0,0,?,?,?)",
                      (sid, cid, f["name"][:300], f.get("kind", ""), f["sha256"], int(f["size"]), iso(),
                       f.get("actor", ""), "importing"))
        return sid

    def finish_source(self, sid: str, **f: Any) -> None:
        with self._conn() as c:
            c.execute("UPDATE dfir_sources SET kind=?, events=?, errors=?, error_samples=?, hosts=?, first_ts=?, "
                      "last_ts=?, status=?, note=? WHERE id=?",
                      (f.get("kind", ""), f["events"], f["errors"], dumps(f.get("error_samples", [])[:20]),
                       dumps(sorted(f.get("hosts", []))[:200]), f.get("first_ts", ""), f.get("last_ts", ""),
                       f.get("status", "done"), f.get("note", "")[:500], sid))

    def sources(self, cid: str) -> list[dict]:
        with self._conn() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM dfir_sources WHERE case_id=? ORDER BY imported", (cid,))]
        for r in rows:
            r["hosts"] = loads(r.get("hosts"), [])
            r["error_samples"] = loads(r.get("error_samples"), [])
        return rows

    def find_source(self, cid: str, sha256: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM dfir_sources WHERE case_id=? AND sha256=? AND status='done'",
                          (cid, sha256)).fetchone()
        return dict(r) if r else None

    def next_seq(self, cid: str) -> int:
        with self._conn() as c:
            r = c.execute("SELECT MAX(seq) AS m FROM dfir_events WHERE case_id=?", (cid,)).fetchone()
        return int((r["m"] if r else None) or 0) + 1

    def add_events(self, cid: str, sid: str, rows: Iterable[tuple[int, dict]]) -> int:
        vals = [(cid, seq, sid, e["ts"], e["host"], e["channel"], e["event_id"], e["user"], e["process"],
                 e["summary"], dumps(e["data"])) for seq, e in rows]
        if not vals:
            return 0
        sql = ("INSERT INTO dfir_events (case_id, seq, source_id, ts, host, channel, event_id, usr, process, summary, "
               "data) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
        with self._lock, self._conn() as c:
            if hasattr(c, "executemany"):
                c.executemany(sql, vals)
            else:
                for v in vals:
                    c.execute(sql, v)
        return len(vals)

    def count(self, cid: str) -> int:
        with self._conn() as c:
            return int(c.execute("SELECT COUNT(*) AS n FROM dfir_events WHERE case_id=?", (cid,)).fetchone()["n"])

    @staticmethod
    def _ev(r) -> dict:
        d = dict(r)
        d["user"] = d.pop("usr", "")
        d["data"] = loads(d.get("data"), {})
        d["tags"] = loads(d.get("tags"), [])
        return d

    def iter_events(self, cid: str, batch: int = 5000):
        last = 0
        while True:
            with self._conn() as c:
                rows = list(c.execute("SELECT * FROM dfir_events WHERE case_id=? AND seq>? ORDER BY seq LIMIT ?",
                                      (cid, last, batch)))
            if not rows:
                return
            for r in rows:
                yield self._ev(r)
            last = rows[-1]["seq"]

    def event(self, cid: str, seq: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM dfir_events WHERE case_id=? AND seq=?", (cid, int(seq))).fetchone()
        if not r:
            return None
        e = self._ev(r)
        e["detections"] = self.detections_of(cid, [e["seq"]]).get(e["seq"], [])
        return e

    def events_by_seq(self, cid: str, seqs: list[int]) -> list[dict]:
        out = []
        for i in range(0, len(seqs), 500):
            part = seqs[i:i + 500]
            q = ",".join("?" * len(part))
            with self._conn() as c:
                out += [self._ev(r) for r in c.execute(
                    f"SELECT * FROM dfir_events WHERE case_id=? AND seq IN ({q})", (cid, *part))]  # nosec B608
        return sorted(out, key=lambda e: (e["ts"] or "", e["seq"]))

    def search(self, cid: str, *, q: str = "", host: str = "", since: str = "", until: str = "", rule: str = "",
               starred: bool = False, detected: bool = False, tag: str = "", event_id: str = "",
               order: str = "ts", limit: int = 200, offset: int = 0) -> tuple[list[dict], int]:
        where, args = ["e.case_id=?"], [cid]
        if q:
            for term in q.split()[:8]:
                if ":" in term and not term.startswith(("http", "\\")) and term.split(":", 1)[0].isidentifier():
                    k, v = term.split(":", 1)                 # field:value searches the stored fields
                    where.append("e.data LIKE ?")
                    args.append(f'%"{k}": %{v}%')
                else:
                    where.append("(e.summary LIKE ? OR e.data LIKE ?)")
                    args += [f"%{term}%", f"%{term}%"]
        for col, val in (("host", host), ("event_id", event_id)):
            if val:
                where.append(f"e.{col}=?")
                args.append(val)
        if since:
            where.append("e.ts>=?")
            args.append(since)
        if until:
            where.append("e.ts<=?")
            args.append(until)
        if starred:
            where.append("e.star=1")
        if tag:
            where.append("e.tags LIKE ?")
            args.append(f'%"{tag}"%')
        if detected:
            where.append("e.level>0")
        if rule:
            where.append("EXISTS (SELECT 1 FROM dfir_detections d WHERE d.case_id=e.case_id AND d.seq=e.seq "
                         "AND d.rule_key=?)")
            args.append(rule)
        w = " AND ".join(where)
        with self._conn() as c:
            total = int(c.execute(f"SELECT COUNT(*) AS n FROM dfir_events e WHERE {w}", args).fetchone()["n"])  # nosec B608
            rows = [self._ev(r) for r in c.execute(
                f"SELECT * FROM dfir_events e WHERE {w} ORDER BY {ORDER_COLS.get(order, 'ts')}, seq LIMIT ? OFFSET ?",  # nosec B608
                (*args, int(limit), int(offset)))]
        dets = self.detections_of(cid, [r["seq"] for r in rows])
        for r in rows:
            r["detections"] = dets.get(r["seq"], [])
        return rows, total

    def mark(self, cid: str, seq: int, *, star: bool | None = None, tags: list[str] | None = None,
             comment: str | None = None) -> dict | None:
        sets, args = [], []
        if star is not None:
            sets.append("star=?")
            args.append(1 if star else 0)
        if tags is not None:
            sets.append("tags=?")
            args.append(dumps(sorted({t.strip()[:40] for t in tags if t.strip()})[:20]))
        if comment is not None:
            sets.append("comment=?")
            args.append(comment[:4000])
        if sets:
            with self._conn() as c:
                c.execute(f"UPDATE dfir_events SET {', '.join(sets)} WHERE case_id=? AND seq=?",  # nosec B608
                          (*args, cid, int(seq)))
        return self.event(cid, seq)

    def hosts(self, cid: str) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT host, COUNT(*) AS n, MIN(ts) AS first, MAX(ts) AS last FROM dfir_events WHERE case_id=? "
                "GROUP BY host ORDER BY n DESC LIMIT 500", (cid,))]

    def span(self, cid: str) -> dict:
        with self._conn() as c:
            r = c.execute("SELECT MIN(ts) AS first, MAX(ts) AS last FROM dfir_events WHERE case_id=? AND ts<>''",
                          (cid,)).fetchone()
        return {"first": r["first"], "last": r["last"]} if r else {}

    # ---- detections ----
    def clear_detections(self, cid: str, origins: tuple[str, ...]) -> None:
        q = ",".join("?" * len(origins))
        with self._lock, self._conn() as c:
            c.execute(f"DELETE FROM dfir_detections WHERE case_id=? AND origin IN ({q})", (cid, *origins))  # nosec B608
            c.execute("UPDATE dfir_events SET level=0 WHERE case_id=?", (cid,))

    def add_detections(self, cid: str, rows: list[tuple[int, str, str, str, str, list[str]]]) -> None:
        if not rows:
            return
        sql = ("INSERT INTO dfir_detections (case_id, seq, rule_key, title, level, origin, attack) VALUES "
               "(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING")
        vals = [(cid, s, k, t[:300], lv, o, dumps(a)) for s, k, t, lv, o, a in rows]
        with self._lock, self._conn() as c:
            if hasattr(c, "executemany"):
                c.executemany(sql, vals)
            else:
                for v in vals:
                    c.execute(sql, v)

    def refresh_levels(self, cid: str) -> None:
        """events.level = the highest detection level on the event (0 none .. 5 critical)."""
        case = " ".join(f"WHEN '{lv}' THEN {i + 1}" for i, lv in enumerate(LEVELS))
        with self._lock, self._conn() as c:
            c.execute("UPDATE dfir_events SET level=0 WHERE case_id=?", (cid,))
            c.execute(f"UPDATE dfir_events SET level=(SELECT MAX(CASE d.level {case} ELSE 1 END) FROM dfir_detections d "  # nosec B608
                      "WHERE d.case_id=dfir_events.case_id AND d.seq=dfir_events.seq) WHERE case_id=? AND EXISTS "
                      "(SELECT 1 FROM dfir_detections d WHERE d.case_id=dfir_events.case_id AND d.seq=dfir_events.seq)",
                      (cid,))

    def detections_of(self, cid: str, seqs: list[int]) -> dict[int, list[dict]]:
        out: dict[int, list[dict]] = {}
        for i in range(0, len(seqs), 500):
            part = seqs[i:i + 500]
            if not part:
                continue
            q = ",".join("?" * len(part))
            with self._conn() as c:
                for r in c.execute(f"SELECT seq, rule_key, title, level, origin FROM dfir_detections WHERE case_id=? "  # nosec B608
                                   f"AND seq IN ({q})", (cid, *part)):
                    out.setdefault(r["seq"], []).append({k: r[k] for k in ("rule_key", "title", "level", "origin")})
        return out

    def detection_summary(self, cid: str) -> list[dict]:
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT d.rule_key, d.title, d.level, d.origin, d.attack, COUNT(*) AS n, MIN(e.ts) AS first, "
                "MAX(e.ts) AS last, COUNT(DISTINCT e.host) AS hosts, MIN(e.seq) AS sample FROM dfir_detections d "
                "JOIN dfir_events e ON e.case_id=d.case_id AND e.seq=d.seq WHERE d.case_id=? "
                "GROUP BY d.rule_key, d.title, d.level, d.origin, d.attack", (cid,))]
        rank = {lv: i for i, lv in enumerate(LEVELS)}
        for r in rows:
            r["attack"] = loads(r.get("attack"), [])
        return sorted(rows, key=lambda r: (-rank.get(r["level"], 0), r["first"] or ""))

    # ---- analysis, notes, stories ----
    def save_analysis(self, cid: str, name: str, body: Any) -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM dfir_analysis WHERE case_id=? AND name=?", (cid, name))
            c.execute("INSERT INTO dfir_analysis (case_id, name, ts, body) VALUES (?,?,?,?)", (cid, name, iso(), dumps(body)))

    def analysis(self, cid: str) -> dict:
        with self._conn() as c:
            return {r["name"]: loads(r["body"], None) for r in c.execute(
                "SELECT name, body FROM dfir_analysis WHERE case_id=?", (cid,))}

    def add_note(self, cid: str, kind: str, text: str, *, author: str, events: list[int] | None = None) -> dict:
        if kind not in NOTE_KINDS:
            raise ValueError(f"kind must be one of {NOTE_KINDS}")
        if not text.strip():
            raise ValueError("a note needs text")
        with self._conn() as c:
            cur = c.execute("INSERT INTO dfir_notes (case_id, kind, text, author, ts, events, status) "
                            "VALUES (?,?,?,?,?,?,?)", (cid, kind, text[:4000], author, iso(), dumps(events or []), "open"))
        return {"id": cur.lastrowid, "kind": kind, "text": text}

    def notes(self, cid: str) -> list[dict]:
        with self._conn() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM dfir_notes WHERE case_id=? ORDER BY id", (cid,))]
        for r in rows:
            r["events"] = loads(r.get("events"), [])
        return rows

    def set_note_status(self, cid: str, nid: int, status: str) -> None:
        if status not in ("open", "confirmed", "refuted", "answered", "closed"):
            raise ValueError("status must be open, confirmed, refuted, answered or closed")
        with self._conn() as c:
            c.execute("UPDATE dfir_notes SET status=? WHERE case_id=? AND id=?", (status, cid, int(nid)))

    def save_story(self, cid: str, kind: str, body: dict, *, author: str, model: str) -> int:
        with self._conn() as c:
            cur = c.execute("INSERT INTO dfir_stories (case_id, kind, ts, author, model, body) VALUES (?,?,?,?,?,?)",
                            (cid, kind, iso(), author, model, dumps(body)))
        return int(cur.lastrowid or 0)

    def stories(self, cid: str, kind: str = "story", limit: int = 10) -> list[dict]:
        with self._conn() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM dfir_stories WHERE case_id=? AND kind=? ORDER BY id DESC "
                                               "LIMIT ?", (cid, kind, limit))]
        for r in rows:
            r["body"] = loads(r["body"], {})
        return rows
