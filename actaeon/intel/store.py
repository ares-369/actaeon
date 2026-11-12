"""SQLite store for indicators and advisories.

Each indicator is one row per (type, value) with first_seen, last_seen and
seen_count, so adding the same IOC again updates it instead of duplicating it.
Scheduled hunts (phase 5) use ``changed_since`` to re-hunt only new or updated
indicators. Writes come only from the user (UI, API, CLI, feeds); the MCP side
is read-only.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .extract import TYPES, extract, guess_type, normalize


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class IntelStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, value TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual', confidence INTEGER NOT NULL DEFAULT 50,
                tags TEXT NOT NULL DEFAULT '[]', note TEXT NOT NULL DEFAULT '', advisory_id INTEGER,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, updated TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1, expires TEXT, active INTEGER NOT NULL DEFAULT 1,
                UNIQUE(type, value));
            CREATE INDEX IF NOT EXISTS ind_value ON indicators(value);
            CREATE INDEX IF NOT EXISTS ind_updated ON indicators(updated);
            CREATE TABLE IF NOT EXISTS advisories (
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, text TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual', url TEXT NOT NULL DEFAULT '', added TEXT NOT NULL,
                techniques TEXT NOT NULL DEFAULT '[]', cves TEXT NOT NULL DEFAULT '[]',
                indicator_count INTEGER NOT NULL DEFAULT 0);
            """)

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    # ---- writes (user side only) ----
    def add(self, value: str, kind: str | None = None, *, source: str = "manual", confidence: int = 50,
            tags: list[str] | None = None, note: str = "", advisory_id: int | None = None,
            ttl_days: int | None = None) -> dict:
        kind = kind or guess_type(value)
        if kind not in TYPES:
            raise ValueError(f"{value!r} is not a recognised indicator (types: {', '.join(TYPES)})")
        v = normalize(kind, value)
        conf = max(0, min(100, int(confidence)))
        now = _now()
        expires = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat(timespec="seconds") if ttl_days else None
        tags = sorted({str(t).strip()[:40] for t in tags or [] if str(t).strip()})
        with self._lock, self._conn() as c:
            row = c.execute("SELECT * FROM indicators WHERE type=? AND value=?", (kind, v)).fetchone()
            if row:
                merged = sorted(set(json.loads(row["tags"])) | set(tags))
                c.execute("""UPDATE indicators SET last_seen=?, updated=?, seen_count=seen_count+1, active=1,
                             confidence=MAX(confidence, ?), tags=?, source=CASE WHEN instr(source, ?) THEN source
                             ELSE source || ',' || ? END, expires=COALESCE(?, expires),
                             note=CASE WHEN ?<>'' THEN ? ELSE note END,
                             advisory_id=COALESCE(?, advisory_id) WHERE id=?""",
                          (now, now, conf, json.dumps(merged), source, source, expires, note, note,
                           advisory_id, row["id"]))
                status = "updated"
                iid = row["id"]
            else:
                cur = c.execute("""INSERT INTO indicators (type, value, source, confidence, tags, note, advisory_id,
                                   first_seen, last_seen, updated, expires) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                                (kind, v, source, conf, json.dumps(tags), note[:500], advisory_id, now, now, now,
                                 expires))
                status = "new"
                iid = cur.lastrowid
        return {"id": iid, "type": kind, "value": v, "status": status}

    def add_text(self, text: str, **kw) -> dict:
        """Extract every indicator from ``text`` and add them. Techniques and CVEs are kept too."""
        found = extract(text)
        results = [self.add(v, k, **kw) for k, vals in found.items() for v in vals]
        return {"found": {k: len(v) for k, v in found.items()},
                "new": sum(r["status"] == "new" for r in results),
                "updated": sum(r["status"] == "updated" for r in results), "items": results}

    def add_advisory(self, title: str, text: str, *, source: str = "manual", url: str = "",
                     confidence: int = 50, tags: list[str] | None = None, strict_links: bool = False) -> dict:
        """Store an advisory and its indicators.

        ``strict_links`` (used for web pulls and imports): domains, URLs and emails are kept only if the
        text defanged them (hxxp, [.]), which is how advisories mark real indicators; plain links are
        usually references. The publisher's own domain is never kept. IPs and hashes are unaffected.
        """
        found = extract(text)
        dropped: list[str] = []
        if strict_links:
            from urllib.parse import urlparse
            own = (urlparse(url).hostname or "").lower().removeprefix("www.")
            low = text.lower()

            def keep(kind: str, v: str) -> bool:
                host = (urlparse(v).hostname or "") if kind == "url" else v.split("@")[-1]
                host = host.lower().removeprefix("www.")
                if own and (host == own or host.endswith("." + own)):
                    return False
                return v.lower() not in low          # only present after refanging = it was defanged
            for kind in ("domain", "url", "email"):
                if kind in found:
                    kept = [v for v in found[kind] if keep(kind, v)]
                    dropped += [v for v in found[kind] if v not in kept]
                    found[kind] = kept
            found = {k: v for k, v in found.items() if v}
        with self._lock, self._conn() as c:
            cur = c.execute("INSERT INTO advisories (title, text, source, url, added, techniques, cves) "
                            "VALUES (?,?,?,?,?,?,?)",
                            (title[:300] or "Untitled advisory", text[:200_000], source, url, _now(),
                             json.dumps(found.get("technique", [])), json.dumps(found.get("cve", []))))
            aid = cur.lastrowid
        items = [self.add(v, k, source=source, confidence=confidence, tags=[*(tags or []), f"advisory:{aid}"],
                          advisory_id=aid) for k, vals in found.items() for v in vals]
        with self._lock, self._conn() as c:
            c.execute("UPDATE advisories SET indicator_count=? WHERE id=?", (len(items), aid))
        return {"advisory_id": aid, "found": {k: len(v) for k, v in found.items()},
                "new": sum(i["status"] == "new" for i in items), "updated": sum(i["status"] == "updated" for i in items),
                "skipped_links": dropped[:50]}

    def deactivate(self, indicator_id: int) -> bool:
        with self._lock, self._conn() as c:
            return c.execute("UPDATE indicators SET active=0, updated=? WHERE id=?",
                             (_now(), int(indicator_id))).rowcount > 0

    # ---- reads (also served over MCP) ----
    @staticmethod
    def _row(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["tags"] = json.loads(d["tags"])
        d["active"] = bool(d["active"])
        return d

    def lookup(self, value: str) -> dict:
        kind = guess_type(value)
        v = normalize(kind, value) if kind else value.strip()
        with self._conn() as c:
            exact = [self._row(r) for r in c.execute("SELECT * FROM indicators WHERE value=?", (v,))]
            related = []
            if kind == "domain":
                parts = v.split(".")
                parents = [".".join(parts[i:]) for i in range(1, len(parts) - 1)]
                if parents:
                    marks = ",".join("?" * len(parents))  # placeholders only; values are bound
                    q = f"SELECT * FROM indicators WHERE type='domain' AND value IN ({marks})"
                    related = [self._row(r) for r in c.execute(q, parents)]
            if kind in ("domain", "ipv4"):
                related += [self._row(r) for r in c.execute(
                    "SELECT * FROM indicators WHERE type='url' AND value LIKE ? LIMIT 50", (f"%://{v}%",))]
        return {"value": v, "type": kind, "found": bool(exact), "matches": exact, "related": related}

    def list(self, *, kind: str | None = None, tag: str | None = None, min_confidence: int = 0,
             changed_since: str | None = None, changed_after: str | None = None, active_only: bool = True, search: str = "", limit: int = 100,
             offset: int = 0) -> list[dict]:
        q, a = ["SELECT * FROM indicators WHERE confidence >= ?"], [int(min_confidence)]
        if kind:
            q.append("AND type=?")
            a.append(kind)
        if tag:
            q.append("AND tags LIKE ?")
            a.append(f'%"{tag}"%')
        if changed_since:
            q.append("AND updated >= ?")
            a.append(changed_since)
        if changed_after:
            q.append("AND updated > ?")
            a.append(changed_after)
        if active_only:
            q.append("AND active=1 AND (expires IS NULL OR expires > ?)")
            a.append(_now())
        if search:
            q.append("AND (value LIKE ? OR note LIKE ?)")
            a += [f"%{search}%", f"%{search}%"]
        q.append("ORDER BY updated DESC LIMIT ? OFFSET ?")
        a += [max(1, min(int(limit), 5000)), max(0, int(offset))]
        with self._conn() as c:
            return [self._row(r) for r in c.execute(" ".join(q), a)]

    def advisories(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT id, title, source, url, added, techniques, cves, indicator_count "
                             "FROM advisories ORDER BY id DESC LIMIT ?", (int(limit),))
            return [{**dict(r), "techniques": json.loads(r["techniques"]), "cves": json.loads(r["cves"])} for r in rows]

    def advisory(self, aid: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM advisories WHERE id=?", (int(aid),)).fetchone()
            if not r:
                return None
            inds = [self._row(x) for x in c.execute("SELECT * FROM indicators WHERE advisory_id=?", (int(aid),))]
        d = dict(r)
        d["techniques"], d["cves"] = json.loads(d["techniques"]), json.loads(d["cves"])
        d["indicators"] = inds
        return d

    def stats(self) -> dict[str, Any]:
        with self._conn() as c:
            by_type = {r["type"]: r["n"] for r in c.execute(
                "SELECT type, COUNT(*) n FROM indicators WHERE active=1 GROUP BY type")}
            adv = c.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
        return {"indicators": sum(by_type.values()), "by_type": by_type, "advisories": adv}
