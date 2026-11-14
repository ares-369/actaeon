"""Hunt memory: past verdicts and analyst notes, searched with SQLite full-text search.

Before a hunt starts, the most related past hunts and notes are added to the
model's context (for example "this admin tool on these hosts is known and
benign"). Notes are written by analysts only, never by a model or a data source.

A note can expire (``expires``): a wrong "benign" call should not blind every
later hunt for good. Notes made from a benign / false-positive verdict get
``memory.benign_note_days`` (default 90; 0 = never) unless the analyst says otherwise.
Expired notes stay listed but are no longer used.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import db

_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,}")
_STOP = {"the", "and", "for", "any", "last", "days", "hours", "from", "with", "that", "this", "was", "were", "has",
         "have", "into", "host", "hosts", "user", "users", "or", "not", "are", "all", "one", "in", "on"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _words(text: str) -> list[str]:
    return list(dict.fromkeys(w.lower() for w in _WORD.findall(text or "") if w.lower() not in _STOP))[:30]


def _fts_query(text: str) -> str:
    """SQLite FTS5 query: any of the words."""
    return " OR ".join('"' + w.replace('"', "") + '"' for w in _words(text))


def _ts_query(text: str) -> str:
    """PostgreSQL tsquery: any of the words, each quoted as one lexeme."""
    return " | ".join("'" + w.replace("'", "").replace("\\", "") + "'" for w in _words(text))


# PostgreSQL: plain tables searched with to_tsvector (the 'simple' configuration: no stemming, like FTS5's default)


class HuntMemory:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            if db.is_pg():
                c.executescript("""
                CREATE TABLE IF NOT EXISTS mem_hunts (hunt_id TEXT, created TEXT, outcome TEXT, hypothesis TEXT,
                    summary TEXT, findings TEXT, attack TEXT);
                CREATE TABLE IF NOT EXISTS mem_notes (note_id INTEGER, text TEXT, tags TEXT);
                CREATE INDEX IF NOT EXISTS mem_hunts_id ON mem_hunts(hunt_id);
                CREATE INDEX IF NOT EXISTS mem_notes_id ON mem_notes(note_id);
                """)
            else:
                c.executescript("""
                CREATE VIRTUAL TABLE IF NOT EXISTS mem_hunts USING fts5(hunt_id UNINDEXED, created UNINDEXED,
                    outcome UNINDEXED, hypothesis, summary, findings, attack);
                CREATE VIRTUAL TABLE IF NOT EXISTS mem_notes USING fts5(note_id UNINDEXED, text, tags);
                """)
            c.executescript("""
            CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT NOT NULL,
                author TEXT NOT NULL DEFAULT '', text TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '[]',
                active INTEGER NOT NULL DEFAULT 1);
            """)
            db.add_column(c, "notes", "expires", "TEXT")

    def _conn(self):
        c = db.connect(self.path)
        return c

    def remember(self, hunt: dict) -> None:
        v = hunt.get("verdict") or {}
        if not v or hunt.get("status") not in ("done", "stopped"):
            return
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM mem_hunts WHERE hunt_id=?", (hunt["id"],))
            c.execute("INSERT INTO mem_hunts VALUES (?,?,?,?,?,?,?)",
                      (hunt["id"], hunt.get("created", ""), v.get("outcome", ""), hunt.get("hypothesis", ""),
                       v.get("summary", ""), " | ".join(f["claim"] for f in v.get("findings") or []),
                       " ".join(v.get("attack") or [])))

    def add_note(self, text: str, *, author: str = "", tags: list[str] | None = None,
                 expires_days: int | None = None) -> dict:
        """``expires_days``: the note stops being used after this many days (None or 0 = never)."""
        text = (text or "").strip()[:2000]
        if not text:
            raise ValueError("note text is required")
        tags = [str(t).strip()[:40] for t in tags or [] if str(t).strip()]
        days = int(expires_days or 0)
        if days < 0 or days > 3650:
            raise ValueError("expires_days must be between 0 and 3650")
        expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds") if days else None
        with self._lock, self._conn() as c:
            cur = c.execute("INSERT INTO notes (created, author, text, tags, expires) VALUES (?,?,?,?,?)",
                            (_now(), author[:100], text, json.dumps(tags), expires))
            c.execute("INSERT INTO mem_notes VALUES (?,?,?)", (cur.lastrowid, text, " ".join(tags)))
        return {"id": cur.lastrowid, "text": text, "tags": tags, "author": author[:100], "expires": expires}

    def notes(self, limit: int = 100) -> list[dict]:
        now = _now()
        with self._conn() as c:
            return [{**dict(r), "tags": json.loads(r["tags"]),
                     "expired": bool(r["expires"] and r["expires"] <= now),
                     "active": bool(r["active"]) and not (r["expires"] and r["expires"] <= now)}
                    for r in c.execute("SELECT * FROM notes ORDER BY id DESC LIMIT ?", (int(limit),))]

    def retire_note(self, nid: int) -> bool:
        with self._lock, self._conn() as c:
            ok = c.execute("UPDATE notes SET active=0 WHERE id=?", (int(nid),)).rowcount > 0
            c.execute("DELETE FROM mem_notes WHERE note_id=?", (int(nid),))
        return ok

    def related(self, text: str, k: int = 3) -> dict:
        pg = db.is_pg()
        q = _ts_query(text) if pg else _fts_query(text)
        if not q:
            return {"hunts": [], "notes": []}
        from ..access import can_see
        if pg:
            hunt_sql = ("SELECT hunt_id, created, outcome, hypothesis, summary, findings FROM mem_hunts "
                        "WHERE to_tsvector('simple', coalesce(hypothesis,'') || ' ' || coalesce(summary,'') "
                        "|| ' ' || coalesce(findings,'') || ' ' || coalesce(attack,'')) "
                        "@@ to_tsquery('simple', ?) "
                        "ORDER BY ts_rank(to_tsvector('simple', coalesce(hypothesis,'') || ' ' || "
                        "coalesce(summary,'') || ' ' || coalesce(findings,'') || ' ' || coalesce(attack,'')), "
                        "to_tsquery('simple', ?)) DESC LIMIT ?")
            hunt_args: tuple = (q, q, int(k) * 4)
            note_sql = ("SELECT n.id, n.text, n.tags, n.author, n.created, n.expires "
                        "FROM mem_notes m JOIN notes n ON n.id = m.note_id "
                        "WHERE to_tsvector('simple', coalesce(m.text,'') || ' ' || coalesce(m.tags,'')) "
                        "@@ to_tsquery('simple', ?) AND n.active=1 AND (n.expires IS NULL OR n.expires > ?) "
                        "ORDER BY ts_rank(to_tsvector('simple', coalesce(m.text,'') || ' ' || "
                        "coalesce(m.tags,'')), to_tsquery('simple', ?)) DESC LIMIT ?")
            note_args: tuple = (q, _now(), q, int(k) + 2)
        else:
            hunt_sql = ("SELECT hunt_id, created, outcome, hypothesis, summary, findings FROM mem_hunts "
                        "WHERE mem_hunts MATCH ? ORDER BY rank LIMIT ?")
            hunt_args = (q, int(k) * 4)
            note_sql = ("SELECT n.id, n.text, n.tags, n.author, n.created, n.expires FROM mem_notes m "
                        "JOIN notes n ON n.id = m.note_id WHERE mem_notes MATCH ? AND n.active=1 "
                        "AND (n.expires IS NULL OR n.expires > ?) ORDER BY rank LIMIT ?")
            note_args = (q, _now(), int(k) + 2)
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(hunt_sql, hunt_args)]
            hunts = []
            for h in rows:
                try:
                    r = c.execute("SELECT restricted FROM hunts WHERE id=?", (h["hunt_id"],)).fetchone()
                except sqlite3.OperationalError:
                    r = None
                if can_see(json.loads(r["restricted"]) if r and r["restricted"] else []):
                    hunts.append(h)
            hunts = hunts[:int(k)]
            notes = [dict(r) for r in c.execute(note_sql, note_args)]
        return {"hunts": hunts, "notes": notes}

    def context(self, text: str, exclude: str = "") -> str:
        r = self.related(text)
        lines = []
        if r["notes"]:
            lines.append("Analyst notes that may apply (written by people on this team):")
            lines += [f"- {n['text']} (by {n['author'] or 'unknown'}, {n['created'][:10]}"
                      + (f", until {n['expires'][:10]})" if n.get("expires") else ")") for n in r["notes"]]
        hunts = [h for h in r["hunts"] if h["hunt_id"] != exclude]
        if hunts:
            lines.append("Related past hunts (for context only; re-check, data changes):")
            lines += [f"- {h['created'][:10]} {h['outcome']}: {h['hypothesis'][:150]} -> {h['summary'][:200]}"
                      for h in hunts]
        return "\n".join(lines)
