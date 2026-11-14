"""SQLite store for indicators and advisories.

Each indicator is one row per (type, value) with first_seen, last_seen and
seen_count, so adding the same IOC again updates it instead of duplicating it.
Scheduled hunts (phase 5) use ``changed_since`` to re-hunt only new or updated
indicators. Writes come only from the user (UI, API, CLI, feeds); the MCP side
is read-only.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .. import db
from .extract import TYPES, extract, guess_type, normalize


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


_NON_ROUTABLE = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


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
            CREATE TABLE IF NOT EXISTS actors (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, slug TEXT NOT NULL UNIQUE,
                aliases TEXT NOT NULL DEFAULT '[]', description TEXT NOT NULL DEFAULT '',
                techniques TEXT NOT NULL DEFAULT '[]', tools TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL DEFAULT 'manual', added TEXT NOT NULL, updated TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS advisories (
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, text TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual', url TEXT NOT NULL DEFAULT '', added TEXT NOT NULL,
                techniques TEXT NOT NULL DEFAULT '[]', cves TEXT NOT NULL DEFAULT '[]',
                indicator_count INTEGER NOT NULL DEFAULT 0);
            """)
            cols = {r[1] for r in c.execute("PRAGMA table_info(advisories)")}
            if "relevance" not in cols:   # ledger of the relevance decision per advisory (added later)
                c.execute("ALTER TABLE advisories ADD COLUMN relevance TEXT NOT NULL DEFAULT ''")
            if "hunt_id" not in cols:
                c.execute("ALTER TABLE advisories ADD COLUMN hunt_id TEXT NOT NULL DEFAULT ''")

    def _conn(self):
        c = db.connect(self.path)
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
                # computed here, not in SQL, so the statement is the same on SQLite and PostgreSQL
                new_conf = max(int(row["confidence"]), int(conf))
                old_src = str(row["source"] or "")
                new_src = old_src if source in old_src else (f"{old_src},{source}" if old_src else source)
                c.execute("""UPDATE indicators SET last_seen=?, updated=?, seen_count=seen_count+1, active=1,
                             confidence=?, tags=?, source=?, expires=COALESCE(?, expires),
                             note=CASE WHEN ?<>'' THEN ? ELSE note END,
                             advisory_id=COALESCE(?, advisory_id) WHERE id=?""",
                          (now, now, new_conf, json.dumps(merged), new_src, expires, note, note,
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
        # Loopback, private, shared, link-local, multicast and unspecified addresses are never indicators:
        # they are examples, lab addresses or victims' internal hosts in a write-up.
        def routable(kind: str, v: str) -> bool:
            host = v
            if kind == "url":
                from urllib.parse import urlparse
                host = urlparse(v).hostname or ""
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                return True
            return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
                        or any(ip in n for n in _NON_ROUTABLE if n.version == ip.version))
        for kind in ("ipv4", "ipv6", "url"):
            if kind in found:
                kept = [v for v in found[kind] if routable(kind, v)]
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
                    # Column names and placeholders are fixed in code; values are always bound.
                    q = f"SELECT * FROM indicators WHERE type='domain' AND value IN ({marks})"  # nosec B608
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
            rows = c.execute("SELECT id, title, source, url, added, techniques, cves, indicator_count, relevance, "
                             "hunt_id FROM advisories ORDER BY id DESC LIMIT ?", (int(limit),))
            return [{**dict(r), "techniques": json.loads(r["techniques"]), "cves": json.loads(r["cves"]),
                     "relevance": json.loads(r["relevance"]) if r["relevance"] else None} for r in rows]

    def set_relevance(self, aid: int, decision: dict, hunt_id: str = "") -> None:
        """Record why an advisory was (or was not) hunted, and the hunt it started."""
        with self._lock, self._conn() as c:
            c.execute("UPDATE advisories SET relevance=?, hunt_id=? WHERE id=?",
                      (json.dumps(decision, ensure_ascii=False), hunt_id or "", int(aid)))

    def advisory(self, aid: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM advisories WHERE id=?", (int(aid),)).fetchone()
            if not r:
                return None
            inds = [self._row(x) for x in c.execute("SELECT * FROM indicators WHERE advisory_id=?", (int(aid),))]
        d = dict(r)
        d["techniques"], d["cves"] = json.loads(d["techniques"]), json.loads(d["cves"])
        d["relevance"] = json.loads(d["relevance"]) if d.get("relevance") else None
        d["indicators"] = inds
        return d

    def stats(self) -> dict[str, Any]:
        with self._conn() as c:
            by_type = {r["type"]: r["n"] for r in c.execute(
                "SELECT type, COUNT(*) n FROM indicators WHERE active=1 GROUP BY type")}
            adv = c.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
        return {"indicators": sum(by_type.values()), "by_type": by_type, "advisories": adv}

    # ---- threat actors ----
    @staticmethod
    def slug(name: str) -> str:
        import re
        return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "actor"

    def save_actor(self, name: str, *, aliases: list[str] | None = None, description: str = "",
                   techniques: list[str] | None = None, tools: list[str] | None = None, indicators_text: str = "",
                   confidence: int = 70, source: str = "manual") -> dict:
        """Create or update an actor profile. Indicators found in ``indicators_text`` are added and tagged actor:<slug>."""
        import re
        name = (name or "").strip()[:120]
        if not name:
            raise ValueError("actor name is required")
        sl = self.slug(name)
        found = extract(f"{description}\n{indicators_text}")
        techs = sorted({t.strip().upper() for t in (techniques or []) if re.fullmatch(r"(?i)T\d{4}(\.\d{3})?", t.strip())}
                       | set(found.get("technique", [])))
        clean = lambda xs: sorted({str(x).strip()[:80] for x in xs or [] if str(x).strip()})  # noqa: E731
        now = _now()
        with self._lock, self._conn() as c:
            row = c.execute("SELECT * FROM actors WHERE slug=?", (sl,)).fetchone()
            if row:
                techs = sorted(set(json.loads(row["techniques"])) | set(techs))
                c.execute("UPDATE actors SET aliases=?, description=?, techniques=?, tools=?, updated=? WHERE id=?",
                          (json.dumps(sorted(set(json.loads(row["aliases"])) | set(clean(aliases)))),
                           description[:5000] or row["description"], json.dumps(techs),
                           json.dumps(sorted(set(json.loads(row["tools"])) | set(clean(tools)))), now, row["id"]))
            else:
                c.execute("INSERT INTO actors (name, slug, aliases, description, techniques, tools, source, added, "
                          "updated) VALUES (?,?,?,?,?,?,?,?,?)",
                          (name, sl, json.dumps(clean(aliases)), description[:5000], json.dumps(techs),
                           json.dumps(clean(tools)), source, now, now))
        added = [self.add(v, k, source=source, confidence=confidence, tags=[f"actor:{sl}"])
                 for k, vals in found.items() if k != "technique" for v in vals]
        return {**(self.actor(sl) or {}), "indicators_added": len(added)}

    def actor(self, key: str) -> dict | None:
        sl = self.slug(str(key))
        with self._conn() as c:
            r = c.execute("SELECT * FROM actors WHERE slug=? OR name=?", (sl, key)).fetchone()
        if not r:
            return None
        d = dict(r)
        for k in ("aliases", "techniques", "tools"):
            d[k] = json.loads(d[k])
        d["indicators"] = self.list(tag=f"actor:{d['slug']}", limit=2000)
        return d

    def actors(self) -> list[dict]:
        with self._conn() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM actors ORDER BY name")]
        for d in rows:
            for k in ("aliases", "techniques", "tools"):
                d[k] = json.loads(d[k])
            d["indicator_count"] = len(self.list(tag=f"actor:{d['slug']}", limit=5000))
        return rows
