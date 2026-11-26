"""Storage for the rule library (SQLite, or PostgreSQL through actaeon/db.py; tables start with rules_).

A rule is a Sigma rule with a status, versions, sample-event tests and test runs:

    draft -> testing -> ready -> retired       (an edit of a ready rule sends it back to testing)
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path

import yaml

from .. import db
from ..soc.util import dumps, iso, loads

STATUSES = ("draft", "testing", "ready", "retired")
EXPECT = ("match", "no_match")
ORIGINS = ("real", "synthetic")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules_rules (
  id TEXT PRIMARY KEY, title TEXT, status TEXT, level TEXT, attack TEXT, sigma TEXT, version INTEGER,
  source TEXT, created TEXT, created_by TEXT, updated TEXT, updated_by TEXT, approved_by TEXT, approved_at TEXT,
  notes TEXT, last_run TEXT, restricted TEXT, fingerprint TEXT);
CREATE INDEX IF NOT EXISTS rules_rules_status ON rules_rules(status);
CREATE TABLE IF NOT EXISTS rules_versions (
  rule_id TEXT, version INTEGER, sigma TEXT, author TEXT, ts TEXT, note TEXT, PRIMARY KEY (rule_id, version));
CREATE TABLE IF NOT EXISTS rules_tests (
  id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT, name TEXT, expect TEXT, origin TEXT, event TEXT,
  source TEXT, created TEXT, created_by TEXT);
CREATE INDEX IF NOT EXISTS rules_tests_rule ON rules_tests(rule_id);
CREATE TABLE IF NOT EXISTS rules_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT, version INTEGER, ts TEXT, actor TEXT, result TEXT);
CREATE INDEX IF NOT EXISTS rules_runs_rule ON rules_runs(rule_id);
"""


def detection_fingerprint(sigma: str) -> str:
    """Same detection logic (logsource + detection), whatever the title or tags say."""
    try:
        doc = yaml.safe_load(sigma) or {}
    except yaml.YAMLError:
        return ""
    if not isinstance(doc, dict):
        return ""
    core = {"logsource": doc.get("logsource"), "detection": doc.get("detection")}
    return hashlib.sha256(dumps(core).encode()).hexdigest()[:16]


def meta(sigma: str) -> dict:
    """id, title, level and ATT&CK technique tags read from the rule text."""
    try:
        doc = yaml.safe_load(sigma) or {}
    except yaml.YAMLError:
        doc = {}
    doc = doc if isinstance(doc, dict) else {}
    tags = [str(t) for t in doc.get("tags") or [] if isinstance(t, str)]
    attack = []
    for t in tags:
        t = t.lower()
        if t.startswith("attack.t") and t[8:9].isdigit():
            tid = t[7:].upper()
            if tid not in attack:
                attack.append(tid)
    return {"id": str(doc.get("id") or ""), "title": str(doc.get("title") or "")[:300],
            "level": str(doc.get("level") or "")[:20], "attack": attack}


class RuleStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self):
        return db.connect(self.path)

    @staticmethod
    def _rule(r) -> dict:
        d = dict(r)
        d["attack"] = loads(d.get("attack"), [])
        d["source"] = loads(d.get("source"), {})
        d["last_run"] = loads(d.get("last_run"), None)
        d["restricted"] = loads(d.get("restricted"), [])
        return d

    # ---- rules ----
    def create(self, rule_id: str, sigma: str, *, actor: str, source: dict | None = None, notes: str = "",
               restricted: list[str] | None = None) -> dict:
        m = meta(sigma)
        t = iso()
        with self._lock, self._conn() as c:
            if c.execute("SELECT id FROM rules_rules WHERE id=?", (rule_id,)).fetchone():
                raise ValueError(f"a rule with id {rule_id} already exists")
            c.execute("INSERT INTO rules_rules (id, title, status, level, attack, sigma, version, source, created, "
                      "created_by, updated, updated_by, notes, restricted, fingerprint) "
                      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (rule_id, m["title"], "draft", m["level"], dumps(m["attack"]), sigma, 1, dumps(source or {}), t,
                       actor, t, actor, notes[:2000], dumps(restricted or []), detection_fingerprint(sigma)))
            c.execute("INSERT INTO rules_versions (rule_id, version, sigma, author, ts, note) VALUES (?,?,?,?,?,?)",
                      (rule_id, 1, sigma, actor, t, "created"))
        return self.get(rule_id)

    def get(self, rule_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM rules_rules WHERE id=?", (rule_id,)).fetchone()
        return self._rule(r) if r else None

    def list(self, *, status: str | None = None, q: str = "", technique: str = "", limit: int = 500) -> list[dict]:
        sql, args = "SELECT * FROM rules_rules WHERE 1=1", []
        if status:
            sql += " AND status=?"
            args.append(status)
        if q:
            sql += " AND (title LIKE ? OR id LIKE ?)"
            args += [f"%{q}%", f"%{q}%"]
        if technique:
            sql += " AND attack LIKE ?"
            args.append(f'%"{technique}%')
        sql += " ORDER BY updated DESC LIMIT ?"
        args.append(int(limit))
        with self._conn() as c:
            rows = [self._rule(r) for r in c.execute(sql, tuple(args))]
        for r in rows:
            r.pop("sigma", None)
        return rows

    def all_full(self) -> list[dict]:
        with self._conn() as c:
            return [self._rule(r) for r in c.execute("SELECT * FROM rules_rules ORDER BY id")]

    def update_sigma(self, rule_id: str, sigma: str, *, actor: str, note: str = "") -> dict:
        r = self.get(rule_id)
        if not r:
            raise KeyError(rule_id)
        if r["status"] == "retired":
            raise ValueError("reopen a retired rule before editing it")
        if sigma == r["sigma"]:
            return r
        m = meta(sigma)
        if m["id"] and m["id"] != rule_id:
            raise ValueError("the rule id in the YAML cannot change; create a new rule instead")
        v = int(r["version"]) + 1
        status = "testing" if r["status"] == "ready" else r["status"]
        t = iso()
        with self._lock, self._conn() as c:
            c.execute("UPDATE rules_rules SET sigma=?, title=?, level=?, attack=?, version=?, status=?, updated=?, "
                      "updated_by=?, approved_by=NULL, approved_at=NULL, fingerprint=? WHERE id=?",
                      (sigma, m["title"], m["level"], dumps(m["attack"]), v, status, t, actor,
                       detection_fingerprint(sigma), rule_id))
            c.execute("INSERT INTO rules_versions (rule_id, version, sigma, author, ts, note) VALUES (?,?,?,?,?,?)",
                      (rule_id, v, sigma, actor, t, note[:500]))
        return self.get(rule_id)

    def set_status(self, rule_id: str, status: str, *, actor: str) -> dict:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        t = iso()
        with self._lock, self._conn() as c:
            if status == "ready":
                c.execute("UPDATE rules_rules SET status=?, approved_by=?, approved_at=?, updated=? WHERE id=?",
                          (status, actor, t, t, rule_id))
            else:
                c.execute("UPDATE rules_rules SET status=?, approved_by=NULL, approved_at=NULL, updated=? "
                          "WHERE id=?", (status, t, rule_id))
        return self.get(rule_id)

    def set_notes(self, rule_id: str, notes: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE rules_rules SET notes=? WHERE id=?", (notes[:2000], rule_id))

    def versions(self, rule_id: str) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM rules_versions WHERE rule_id=? ORDER BY version DESC",
                                               (rule_id,))]

    def delete(self, rule_id: str) -> None:
        with self._lock, self._conn() as c:
            for t in ("rules_tests", "rules_runs", "rules_versions"):
                c.execute(f"DELETE FROM {t} WHERE rule_id=?", (rule_id,))
            c.execute("DELETE FROM rules_rules WHERE id=?", (rule_id,))

    def by_fingerprint(self, fp: str) -> list[str]:
        if not fp:
            return []
        with self._conn() as c:
            return [r["id"] for r in c.execute("SELECT id FROM rules_rules WHERE fingerprint=? AND status<>?",
                                               (fp, "retired"))]

    # ---- tests ----
    def add_test(self, rule_id: str, *, name: str, expect: str, event: dict, origin: str, source: str = "",
                 actor: str = "", max_tests: int = 200) -> dict:
        if expect not in EXPECT:
            raise ValueError(f"expect must be one of {EXPECT}")
        if origin not in ORIGINS:
            raise ValueError(f"origin must be one of {ORIGINS}")
        if not isinstance(event, dict) or not event:
            raise ValueError("a test event must be a non-empty JSON object")
        body = dumps(event)
        if len(body) > 200_000:
            raise ValueError("a test event is limited to 200 KB")
        with self._lock, self._conn() as c:
            n = c.execute("SELECT COUNT(*) AS n FROM rules_tests WHERE rule_id=?", (rule_id,)).fetchone()["n"]
            if n >= max_tests:
                raise ValueError(f"this rule already has {n} tests (rules.max_tests)")
            cur = c.execute("INSERT INTO rules_tests (rule_id, name, expect, origin, event, source, created, created_by) "
                            "VALUES (?,?,?,?,?,?,?,?)", (rule_id, name[:200] or expect, expect, origin, body,
                                                         source[:300], iso(), actor))
        return {"id": cur.lastrowid, "rule_id": rule_id, "name": name, "expect": expect, "origin": origin,
                "event": event, "source": source}

    def tests(self, rule_id: str) -> list[dict]:
        with self._conn() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM rules_tests WHERE rule_id=? ORDER BY id", (rule_id,))]
        for r in rows:
            r["event"] = loads(r["event"], {})
        return rows

    def delete_test(self, rule_id: str, test_id: int) -> bool:
        with self._lock, self._conn() as c:
            cur = c.execute("DELETE FROM rules_tests WHERE rule_id=? AND id=?", (rule_id, int(test_id)))
        return bool(cur.rowcount)

    # ---- runs ----
    def save_run(self, rule_id: str, version: int, result: dict, *, actor: str) -> None:
        summary = {k: result.get(k) for k in ("version", "ts", "passed", "failed", "total", "unsupported", "ok")}
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO rules_runs (rule_id, version, ts, actor, result) VALUES (?,?,?,?,?)",
                      (rule_id, version, result.get("ts") or iso(), actor, dumps(result)))
            c.execute("UPDATE rules_rules SET last_run=? WHERE id=?", (dumps(summary), rule_id))

    def last_run(self, rule_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT result FROM rules_runs WHERE rule_id=? ORDER BY id DESC LIMIT 1", (rule_id,)).fetchone()
        return loads(r["result"], None) if r else None

    def counts(self) -> dict[str, int]:
        with self._conn() as c:
            return {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) AS n FROM rules_rules GROUP BY status")}
