"""Demo bridge: the search-index tools over built-in SAMPLE events (see actaeon/demo/data.py).

Supports a small subset of query_string syntax: ``field:value`` (``*`` wildcards),
bare words, quoted phrases, ``AND`` / ``OR`` / ``NOT`` and parentheses. Matching
is case-insensitive. It is for trying Actaeon, not a search engine.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
from collections import Counter
from datetime import datetime

from ..demo.data import LABEL, events
from .common import baseline_window, cap, time_window
from .search_index import TIME_SCHEMA
from .server import McpServer, ToolInputError

INDEX = "demo-events"
_TOKEN = re.compile(r'\s*(\(|\)|"[^"]*"|[^\s()]+)')


def _flat(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flat(v, key + "."))
        else:
            out[key] = v
    return out


class _Q:
    def __init__(self, q: str):
        self.toks = [t for t in _TOKEN.findall(q or "") if t]
        self.i = 0

    def parse(self):
        if not self.toks:
            return lambda e: True
        node = self._or()
        if self.i < len(self.toks):
            raise ToolInputError(f"could not parse the query near {self.toks[self.i]!r}")
        return node

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _or(self):
        left = self._and()
        while self._peek() in ("OR", "||"):
            self.i += 1
            right = self._and()
            left = (lambda a, b: lambda e: a(e) or b(e))(left, right)
        return left

    def _and(self):
        left = self._not()
        while self._peek() not in (None, ")", "OR", "||"):
            if self._peek() in ("AND", "&&"):
                self.i += 1
            right = self._not()
            left = (lambda a, b: lambda e: a(e) and b(e))(left, right)
        return left

    def _not(self):
        if self._peek() in ("NOT", "!"):
            self.i += 1
            inner = self._not()
            return lambda e: not inner(e)
        return self._atom()

    def _atom(self):
        t = self._peek()
        if t is None:
            raise ToolInputError("query ended early")
        self.i += 1
        if t == "(":
            node = self._or()
            if self._peek() != ")":
                raise ToolInputError("missing )")
            self.i += 1
            return node
        neg = t.startswith("-") and len(t) > 1
        if neg:
            t = t[1:]
        m = re.match(r'^([A-Za-z0-9_.@]+):(.+)$', t)
        if m:
            field, val = m.group(1), m.group(2).strip('"').lower()

            def f(e, field=field, val=val):
                v = e.get(field)
                return v is not None and fnmatch.fnmatchcase(str(v).lower(), val)
        else:
            val = t.strip('"').lower()

            def f(e, val=val):
                pat = val if "*" in val else f"*{val}*"
                return any(fnmatch.fnmatchcase(str(v).lower(), pat) for v in e.values())
        return (lambda e: not f(e)) if neg else f


class DemoBridge:
    def __init__(self, max_days: int = 30, max_size: int = 500):
        self.flat = [_flat(e) for e in events()]
        self.max_days, self.max_size = max_days, max_size

    def _select(self, a: dict, window=None) -> list[dict]:
        idx = str(a.get("index", ""))
        if not fnmatch.fnmatchcase(INDEX, idx or "x"):
            raise ToolInputError(f"index {idx!r} not found; the demo has one index: {INDEX}")
        start, end = window or time_window(a, self.max_days)
        match = _Q(str(a.get("query", "") or "")).parse()
        out = []
        for e in self.flat:
            ts = datetime.fromisoformat(e["@timestamp"].replace("Z", "+00:00"))
            if start <= ts <= end and match(e):
                out.append(e)
        return out

    def list_indices(self, a):
        return {"indices": [{"index": INDEX, "docs.count": len(self.flat)}], "note": LABEL}

    def get_fields(self, a):
        fields = sorted({k for e in self.flat for k in e})
        return {"index": INDEX, "time_field": "@timestamp", "fields": {f: "keyword" for f in fields}, "note": LABEL}

    def search(self, a):
        hits = self._select(a)
        if a.get("order") == "asc":
            hits = list(reversed(hits))
        size = cap(a.get("size"), 50, self.max_size)
        fields = a.get("fields")
        rows = [{k: v for k, v in e.items() if not fields or k in fields or k == "sample"} for e in hits[:size]]
        return {"index": INDEX, "total": len(hits), "returned": len(rows), "hits": rows}

    def count(self, a):
        return {"index": INDEX, "count": len(self._select(a))}

    def top_values(self, a):
        field = str(a.get("field", ""))
        if not field:
            raise ToolInputError("field is required")
        c = Counter(str(e.get(field)) for e in self._select(a) if e.get(field) is not None)
        items = sorted(c.items(), key=lambda kv: (kv[1], kv[0]), reverse=not a.get("rare"))
        n = cap(a.get("size"), 20, 200)
        return {"index": INDEX, "field": field, "order": "rarest" if a.get("rare") else "most common",
                "buckets": [{"value": v, "count": k} for v, k in items[:n]]}

    def first_seen(self, a):
        field = str(a.get("field", ""))
        if not field:
            raise ToolInputError("field is required")
        b0, r0, r1 = baseline_window(a, self.max_days)
        recent = Counter(str(e.get(field)) for e in self._select(a, (r0, r1)) if e.get(field) is not None)
        old = {str(e.get(field)) for e in self._select(a, (b0, r0)) if e.get(field) is not None}
        new = sorted(((v, c) for v, c in recent.items() if v not in old), key=lambda kv: (kv[1], kv[0]))
        return {"index": INDEX, "field": field, "recent_values": len(recent),
                "new": [{"value": v, "count": c} for v, c in new[:cap(a.get("size"), 50, 500)]]}

    def build(self) -> McpServer:
        srv = McpServer("actaeon-demo", instructions=(
            f"DEMO data source with synthetic events ({LABEL}). One index: {INDEX}. Time field @timestamp. "
            "Queries use a small query_string subset: field:value, wildcards, AND/OR/NOT, quotes, parentheses."))
        idx = {"index": {"type": "string", "description": f"use {INDEX}"}}
        q = {"query": {"type": "string", "description": "query_string subset; empty = all"}}
        srv.tool("list_indices", "List indices (demo).", {"type": "object", "properties": {}})(self.list_indices)
        srv.tool("get_fields", "List field names (demo).",
                 {"type": "object", "properties": idx, "required": ["index"]})(self.get_fields)
        srv.tool("search", "Search demo events in a time window, newest first.",
                 {"type": "object", "properties": {**idx, **q, **TIME_SCHEMA, "size": {"type": "integer"},
                  "fields": {"type": "array", "items": {"type": "string"}},
                  "order": {"type": "string", "enum": ["desc", "asc"]}}, "required": ["index"]})(self.search)
        srv.tool("count", "Count demo events.", {"type": "object", "properties": {**idx, **q, **TIME_SCHEMA},
                                                  "required": ["index"]})(self.count)
        srv.tool("top_values", "Most common (or rare=true, rarest) values of a field.",
                 {"type": "object", "properties": {**idx, **q, **TIME_SCHEMA, "field": {"type": "string"},
                  "size": {"type": "integer"}, "rare": {"type": "boolean"}}, "required": ["index", "field"]})(self.top_values)
        srv.tool("first_seen", "Values of a field in the window that never appear in the baseline_days before it.",
                 {"type": "object", "properties": {**idx, **q, **TIME_SCHEMA, "field": {"type": "string"},
                  "baseline_days": {"type": "number"}, "size": {"type": "integer"}}, "required": ["index", "field"]})(self.first_seen)
        return srv


def add_args(p: argparse.ArgumentParser) -> None:
    pass


def run(a: argparse.Namespace) -> None:
    DemoBridge().build().serve()
