"""Search-index bridge: read-only access to an index with the common ``_search`` JSON API.

Only these endpoints are ever called: ``GET _cat/indices``, ``GET <index>/_mapping``,
``POST <index>/_search`` and ``POST <index>/_count``. Every search has a time
bound, a size cap and an index allowlist. Scripts are refused.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
from typing import Any
from urllib.parse import quote

from .common import cap, check_status, session_from_env, time_window
from .server import McpServer, ToolInputError

_INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9._*-]{0,254}$")
TIME_SCHEMA = {
    "time_from": {"type": "string", "description": "start, ISO-8601 or relative like now-24h (default now-24h)"},
    "time_to": {"type": "string", "description": "end, ISO-8601 or now (default now)"},
}


class SearchIndexBridge:
    def __init__(self, url: str, indices: list[str], time_field: str = "@timestamp", max_days: int = 30,
                 max_size: int = 500, verify_tls: bool = True, ca_bundle: str = "", timeout: float = 30,
                 session=None):
        self.url = url.rstrip("/")
        self.indices = indices or ["*"]
        self.time_field = time_field
        self.max_days, self.max_size, self.timeout = max_days, max_size, timeout
        self.http = session or session_from_env("BRIDGE", verify_tls, ca_bundle)

    # ---- guards ----
    def _index(self, value: Any) -> str:
        parts = [p.strip() for p in str(value or "").split(",") if p.strip()]
        if not parts:
            raise ToolInputError("index is required")
        for p in parts:
            if not _INDEX_RE.match(p):
                raise ToolInputError(f"index {p!r} is not a valid index name or pattern")
            if not any(fnmatch.fnmatchcase(p, allowed) for allowed in self.indices):
                raise ToolInputError(f"index {p!r} is outside the allowed indices {self.indices}")
        return ",".join(parts)

    @staticmethod
    def _no_scripts(obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if "script" in str(k).lower():
                    raise ToolInputError("scripts are not allowed in queries")
                SearchIndexBridge._no_scripts(v)
        elif isinstance(obj, list):
            for v in obj:
                SearchIndexBridge._no_scripts(v)

    def _query(self, args: dict) -> dict:
        start, end = time_window(args, self.max_days)
        must: list[dict] = []
        q = str(args.get("query", "") or "").strip()
        if q:
            must.append({"query_string": {"query": q, "analyze_wildcard": True, "allow_leading_wildcard": False}})
        dsl = args.get("dsl")
        if dsl:
            if isinstance(dsl, str):
                try:
                    dsl = json.loads(dsl)
                except ValueError as exc:
                    raise ToolInputError("dsl must be a JSON query clause") from exc
            if not isinstance(dsl, dict):
                raise ToolInputError("dsl must be a JSON object (a query clause)")
            self._no_scripts(dsl)
            must.append(dsl)
        rng = {"range": {self.time_field: {"gte": start.isoformat(), "lte": end.isoformat()}}}
        return {"bool": {"must": must or [{"match_all": {}}], "filter": [rng]}}

    def _post(self, path: str, body: dict) -> dict:
        r = self.http.post(f"{self.url}/{path}", json=body, timeout=self.timeout)
        check_status(r)
        return r.json()

    # ---- tools ----
    def list_indices(self, args: dict) -> dict:
        r = self.http.get(f"{self.url}/_cat/indices", params={"format": "json", "h": "index,docs.count,store.size"},
                          timeout=self.timeout)
        check_status(r)
        rows = [i for i in r.json() if not str(i.get("index", "")).startswith(".")
                and any(fnmatch.fnmatchcase(i.get("index", ""), a) for a in self.indices)]
        rows.sort(key=lambda i: i.get("index", ""))
        return {"indices": rows[:500], "allowed_patterns": self.indices}

    def get_fields(self, args: dict) -> dict:
        idx = self._index(args.get("index"))
        r = self.http.get(f"{self.url}/{quote(idx, safe=',*')}/_mapping", timeout=self.timeout)
        check_status(r)
        fields: dict[str, str] = {}

        def walk(props: dict, prefix: str = ""):
            for name, spec in (props or {}).items():
                full = f"{prefix}{name}"
                if "properties" in spec:
                    walk(spec["properties"], full + ".")
                else:
                    fields.setdefault(full, spec.get("type", "object"))
        for m in r.json().values():
            walk((m.get("mappings") or {}).get("properties") or {})
        names = sorted(fields)
        flt = str(args.get("contains", "") or "").lower()
        if flt:
            names = [n for n in names if flt in n.lower()]
        return {"index": idx, "time_field": self.time_field, "count": len(names),
                "fields": {n: fields[n] for n in names[:1500]}, "truncated": len(names) > 1500}

    def search(self, args: dict) -> dict:
        idx = self._index(args.get("index"))
        size = cap(args.get("size"), 50, self.max_size)
        body: dict[str, Any] = {"query": self._query(args), "size": size, "track_total_hits": True,
                                "sort": [{self.time_field: {"order": "desc" if args.get("order") != "asc" else "asc"}}]}
        fields = args.get("fields")
        if fields:
            if not isinstance(fields, list) or not all(isinstance(f, str) for f in fields):
                raise ToolInputError("fields must be a list of field names")
            body["_source"] = fields[:100]
        res = self._post(f"{quote(idx, safe=',*')}/_search", body)
        hits = res.get("hits") or {}
        total = hits.get("total")
        total = total.get("value") if isinstance(total, dict) else total
        return {"index": idx, "total": total, "returned": len(hits.get("hits") or []),
                "hits": [{"_index": h.get("_index"), "_id": h.get("_id"), **(h.get("_source") or {})}
                         for h in hits.get("hits") or []]}

    def count(self, args: dict) -> dict:
        idx = self._index(args.get("index"))
        res = self._post(f"{quote(idx, safe=',*')}/_count", {"query": self._query(args)})
        return {"index": idx, "count": res.get("count")}

    def top_values(self, args: dict) -> dict:
        idx = self._index(args.get("index"))
        field = str(args.get("field", "") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,200}", field):
            raise ToolInputError("field is required and must be a plain field name")
        n = cap(args.get("size"), 20, 200)
        order = "asc" if args.get("rare") else "desc"
        body = {"query": self._query(args), "size": 0,
                "aggs": {"v": {"terms": {"field": field, "size": n, "order": {"_count": order}}}}}
        res = self._post(f"{quote(idx, safe=',*')}/_search", body)
        b = ((res.get("aggregations") or {}).get("v") or {})
        return {"index": idx, "field": field, "order": "rarest" if order == "asc" else "most common",
                "buckets": [{"value": x.get("key"), "count": x.get("doc_count")} for x in b.get("buckets") or []],
                "other_count": b.get("sum_other_doc_count")}

    def build(self) -> McpServer:
        srv = McpServer("actaeon-search-index", instructions=(
            f"Read-only search index bridge. Queries use query_string (Lucene) syntax. Every search is "
            f"bounded by time on field {self.time_field} (max {self.max_days} days) and capped at "
            f"{self.max_size} hits. Call get_fields first to learn field names."))
        idx = {"index": {"type": "string", "description": f"index name or pattern within {self.indices}"}}
        q = {"query": {"type": "string", "description": "query_string (Lucene) query; empty = all"},
             "dsl": {"type": "object", "description": "optional JSON query clause, ANDed with query"}}
        srv.tool("list_indices", "List the indices this bridge may search.", {"type": "object", "properties": {}})(self.list_indices)
        srv.tool("get_fields", "List field names and types of an index.",
                 {"type": "object", "properties": {**idx, "contains": {"type": "string"}}, "required": ["index"]})(self.get_fields)
        srv.tool("search", "Search events in a time window. Returns the newest hits first.",
                 {"type": "object", "properties": {**idx, **q, **TIME_SCHEMA,
                  "size": {"type": "integer", "description": f"max hits (default 50, max {self.max_size})"},
                  "fields": {"type": "array", "items": {"type": "string"}, "description": "fields to return"},
                  "order": {"type": "string", "enum": ["desc", "asc"]}}, "required": ["index"]})(self.search)
        srv.tool("count", "Count events matching a query in a time window.",
                 {"type": "object", "properties": {**idx, **q, **TIME_SCHEMA}, "required": ["index"]})(self.count)
        srv.tool("top_values", "Most common (or with rare=true, rarest) values of a field. Useful for stacking.",
                 {"type": "object", "properties": {**idx, **q, **TIME_SCHEMA, "field": {"type": "string"},
                  "size": {"type": "integer"}, "rare": {"type": "boolean"}}, "required": ["index", "field"]})(self.top_values)
        return srv


def add_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--url", required=True, help="base URL of the search index API")
    p.add_argument("--index", action="append", default=[], help="allowed index pattern (repeatable)")
    p.add_argument("--time-field", default="@timestamp")
    p.add_argument("--max-days", type=int, default=30)
    p.add_argument("--max-size", type=int, default=500)
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (lab only)")
    p.add_argument("--ca-bundle", default="")


def run(a: argparse.Namespace) -> None:
    SearchIndexBridge(a.url, a.index, a.time_field, a.max_days, a.max_size,
                      verify_tls=not a.insecure, ca_bundle=a.ca_bundle).build().serve()
