"""Inventory drift: what is new on each host since the last snapshot. No model needed.

Point it at a current-state inventory source (a search-index bridge started with ``--snapshot``, or any
connector with ``search`` and ``top_values`` tools) and say what an item is::

    drift:
      interval_minutes: 0          # > 0: run on a schedule
      escalate: false              # true: start a model hunt for the new items (needs a model)
      targets:
        - name: listening-ports
          connector: inventory
          index: "inventory-ports-*"
          host_field: host.name
          item_fields: [source.port, network.transport, process.name]
          query: ""                # optional query_string filter
          ignore: ["^6[0-9]{4} "]  # optional regexes on the item text; matches are not reported

Each run lists the hosts (``top_values`` on ``host_field``), reads every host's items (``search``) and
compares them with what was stored last time. The first run records a baseline and reports nothing.
After that, an item that was not there before on that host is a finding (a host seen for the first
time is one finding, with its items as its baseline): the run is stored as a hunt
(origin ``drift:<name>``) whose findings cite the result each item came from, and it is handed to an
analyst. Items that disappear are counted, not reported. A host whose items were cut off at the size
limit is reported as incomplete rather than compared, so missing data never looks like "nothing new".
"""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from typing import Any

from .. import db

MAX_HOSTS = 200
MAX_ITEMS = 500
READ_BYTES = 2_000_000    # drift reads results itself (no model), so it may read far more than a prompt holds


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_target(t: Any) -> dict:
    if not isinstance(t, dict):
        raise ValueError("drift.targets entries must be mappings")
    name = str(t.get("name", ""))
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", name):
        raise ValueError(f"drift target name {name!r}: lowercase letters, digits, _ or -")
    for k in ("connector", "index", "host_field"):
        if not str(t.get(k, "")).strip():
            raise ValueError(f"drift target {name}: {k} is required")
    items = t.get("item_fields")
    if not isinstance(items, list) or not items or not all(isinstance(x, str) and x for x in items):
        raise ValueError(f"drift target {name}: item_fields must be a non-empty list of field names")
    ignore = t.get("ignore") or []
    for rx in ignore:
        re.compile(rx)
    return {"name": name, "connector": str(t["connector"]), "index": str(t["index"]),
            "host_field": str(t["host_field"]), "item_fields": list(items), "query": str(t.get("query", "") or ""),
            "ignore": list(ignore), "label": str(t.get("label", "") or name)}


def targets(cfg) -> list[dict]:
    d = ((getattr(cfg, "raw", None) or {}).get("drift") or {})
    return [validate_target(t) for t in d.get("targets") or []]


class DriftStore:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        with db.connect(self.path) as c:
            c.execute("""CREATE TABLE IF NOT EXISTS drift_items (
                target TEXT NOT NULL, host TEXT NOT NULL, item TEXT NOT NULL, first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL, present INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (target, host, item))""")
            c.execute("""CREATE TABLE IF NOT EXISTS drift_hosts (
                target TEXT NOT NULL, host TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                PRIMARY KEY (target, host))""")

    def known_hosts(self, target: str) -> set[str]:
        with db.connect(self.path) as c:
            return {r[0] for r in c.execute("SELECT host FROM drift_hosts WHERE target=?", (target,))}

    def items(self, target: str, host: str) -> set[str]:
        with db.connect(self.path) as c:
            return {r[0] for r in c.execute("SELECT item FROM drift_items WHERE target=? AND host=? AND present=1",
                                            (target, host))}

    def record(self, target: str, host: str, items: set[str]) -> tuple[set[str], set[str]]:
        """Store this host's items. Returns (new, gone) compared with what was present before."""
        now = _now()
        with self._lock, db.connect(self.path) as c:
            before = {r[0] for r in c.execute(
                "SELECT item FROM drift_items WHERE target=? AND host=? AND present=1", (target, host))}
            ever = {r[0] for r in c.execute("SELECT item FROM drift_items WHERE target=? AND host=?", (target, host))}
            for it in items:
                if it in ever:
                    c.execute("UPDATE drift_items SET last_seen=?, present=1 WHERE target=? AND host=? AND item=?",
                              (now, target, host, it))
                else:
                    c.execute("INSERT INTO drift_items (target, host, item, first_seen, last_seen) VALUES (?,?,?,?,?)",
                              (target, host, it, now, now))
            gone = before - items
            for it in gone:
                c.execute("UPDATE drift_items SET present=0 WHERE target=? AND host=? AND item=?", (target, host, it))
            if c.execute("SELECT 1 FROM drift_hosts WHERE target=? AND host=?", (target, host)).fetchone():
                c.execute("UPDATE drift_hosts SET last_seen=? WHERE target=? AND host=?", (now, target, host))
            else:
                c.execute("INSERT INTO drift_hosts (target, host, first_seen, last_seen) VALUES (?,?,?,?)",
                          (target, host, now, now))
        return items - before, gone

    def status(self) -> list[dict]:
        with db.connect(self.path) as c:
            return [dict(r) for r in c.execute(
                "SELECT target, COUNT(DISTINCT host) AS hosts, SUM(present) AS items, MAX(last_seen) AS last_seen "
                "FROM drift_items GROUP BY target ORDER BY target")]


def _body(content: str) -> Any:
    """JSON inside the untrusted-data wrapper."""
    text = content.split("\n", 1)[1].rsplit("\n", 1)[0] if content.startswith("<<UNTRUSTED-DATA") else content
    try:
        return json.loads(text)
    except ValueError:
        return None


def _flat(d: Any, prefix: str = "") -> dict:
    out: dict = {}
    if isinstance(d, dict):
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(_flat(v, key))
            else:
                out[key] = v
    return out


def rows(result: Any) -> list[dict]:
    """Hits from a search result, as flat dotted-field rows (compacted results are re-expanded)."""
    if not isinstance(result, dict):
        return []
    common = _flat(result.get("common") or {})
    return [{**common, **_flat(h)} for h in result.get("hits") or [] if isinstance(h, dict)]


def item_text(row: dict, fields: list[str]) -> str:
    return " | ".join(str(row.get(f, "")) for f in fields)


def _call(hub, connector, tool, args, **kw) -> dict:
    try:
        return hub.call(connector, tool, args, max_bytes=READ_BYTES, **kw)
    except TypeError:          # a hub without max_bytes (tests, older code): normal size limit
        return hub.call(connector, tool, args, **kw)


def run(cfg, hub, store, *, only: str | None = None, actor: str = "drift") -> list[dict]:
    """Run every drift target (or one). Returns the hunts recorded."""
    from ..connectors.hub import ToolCallError
    ds = DriftStore(store.path)
    out = []
    for t in targets(cfg):
        if only and t["name"] != only:
            continue
        hid = store.create(f"Inventory drift: what is new on each host ({t['label']})", origin=f"drift:{t['name']}",
                           actor=actor)
        store.update(hid, status="running")
        n = 0
        q_host = t["query"]
        known_before = ds.known_hosts(t["name"])
        first_run = not known_before
        findings, incomplete, failed, new_total, gone_total, hosts_seen = [], [], [], 0, 0, 0
        n += 1
        try:
            r = _call(hub, t["connector"], "top_values", {"index": t["index"], "field": t["host_field"],
                                                          "size": MAX_HOSTS, "query": q_host}, actor=actor, hunt_id=hid)
            ok = not r.get("is_error")
            res = _body(r["content"]) if ok else None
        except ToolCallError as exc:
            ok, res, r = False, None, {"content": f"call failed: {exc}"}
        store.add_step(hid, n, "call", connector=t["connector"], tool="top_values", ok=ok, result=r["content"],
                       arguments={"index": t["index"], "field": t["host_field"]}, why="list the hosts")
        hosts = [str(b.get("value")) for b in (res or {}).get("buckets") or [] if b.get("value") not in (None, "")]
        if not ok or not hosts:
            verdict = {"outcome": "logs_missing", "confidence": 90,
                       "summary": f"No host inventory could be read from {t['connector']} ({t['index']}).",
                       "findings": [], "needs_review": True}
            store.add_step(hid, n + 1, "verdict", note=json.dumps(verdict))
            store.update(hid, status="done", outcome=verdict["outcome"], verdict=verdict, finished=_now())
            out.append(store.get(hid))
            continue
        ignore = [re.compile(x) for x in t["ignore"]]
        for host in hosts:
            n += 1
            query = f'{t["host_field"]}:"{host}"' + (f" AND ({q_host})" if q_host else "")
            args = {"index": t["index"], "query": query, "size": MAX_ITEMS, "fields": [t["host_field"], *t["item_fields"]]}
            try:
                r = _call(hub, t["connector"], "search", args, actor=actor, hunt_id=hid)
                ok = not r.get("is_error")
                res = _body(r["content"]) if ok else None
            except ToolCallError as exc:
                ok, res, r = False, None, {"content": f"call failed: {exc}"}
            store.add_step(hid, n, "call", connector=t["connector"], tool="search", ok=ok, arguments=args,
                           result=r["content"], why=f"items on {host}")
            if ok and r.get("truncated"):
                incomplete.append(f"{host} (result larger than {READ_BYTES} bytes)")
                continue
            if not ok or res is None:
                failed.append(host)
                continue
            hosts_seen += 1
            got = {item_text(x, t["item_fields"]) for x in rows(res)}
            got = {i for i in got if not any(rx.search(i) for rx in ignore)}
            total = res.get("total")
            if isinstance(total, int) and total > len(rows(res)):
                incomplete.append(f"{host} ({len(rows(res))} of {total})")
                continue
            new, gone = ds.record(t["name"], host, got)
            gone_total += len(gone)
            if first_run:
                continue
            if host not in known_before:
                # a host seen for the first time: its items are its baseline, the host itself is the finding
                findings.append({"claim": f"New host in the inventory: {host} ({len(got)} item(s))",
                                 "evidence": [f"E{n}"]})
                continue
            for it in sorted(new):
                new_total += 1
                findings.append({"claim": f"New on {host}: {it}", "evidence": [f"E{n}"]})
        if first_run:
            summary = (f"Baseline recorded for {hosts_seen} host(s); nothing is compared on the first run.")
            outcome, needs = "no_results", False
        elif findings:
            new_hosts = sum(1 for f in findings if f["claim"].startswith("New host"))
            item_hosts = len({f["claim"].split(":")[0] for f in findings if not f["claim"].startswith("New host")})
            parts = ([f"{new_total} new item(s) on {item_hosts} host(s)"] if new_total else []) + \
                    ([f"{new_hosts} host(s) seen for the first time"] if new_hosts else [])
            summary = (f"Since the last snapshot: {' and '.join(parts)}; {gone_total} item(s) disappeared. "
                       "New is not necessarily malicious: check who added them.")
            outcome, needs = "inconclusive", True
        else:
            summary = f"Nothing new on {hosts_seen} host(s) since the last snapshot; {gone_total} item(s) disappeared."
            outcome, needs = "no_results", False
        gaps = ([f"cut off at {MAX_ITEMS} items, not compared: " + ", ".join(incomplete[:20])] if incomplete else []) + \
               ([f"could not be read: {', '.join(failed[:20])}"] if failed else [])
        verdict = {"outcome": outcome, "confidence": 90 if not gaps else 60, "summary": summary,
                   "findings": findings[:200], "gaps": gaps, "attack": [],
                   "next_steps": ["Confirm each new item with its owner or a change record; a new listener, "
                                  "service or account no one expected is worth a full hunt."] if findings else []}
        if needs or gaps:
            verdict["needs_review"] = True
        store.add_step(hid, n + 1, "verdict", note=json.dumps(verdict))
        store.update(hid, status="done", outcome=outcome, verdict=verdict, finished=_now(),
                     steps_used=n)
        out.append(store.get(hid))
    return out
