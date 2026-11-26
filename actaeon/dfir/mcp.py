"""Read-only investigation tools for Actaeon's MCP server."""

from __future__ import annotations

from typing import Any

from ..bridges.server import ToolInputError


def add_tools(add, cfg) -> None:
    from . import service as S
    from .config import of

    def need(a: dict) -> str:
        if not of(cfg).enabled:
            raise ToolInputError("investigations are off (dfir.enabled: false)")
        cid = str(a.get("id", ""))
        if cid and not S.store_for(cfg).case(cid):
            raise ToolInputError("no such investigation")
        return cid

    def list_inv(a: dict) -> Any:
        need({})
        return {"investigations": [{k: c[k] for k in ("id", "title", "status", "events", "updated")}
                                   for c in S.store_for(cfg).cases()]}

    def get_inv(a: dict) -> Any:
        cid = need(a)
        o = S.overview(cfg, cid)
        return {k: o.get(k) for k in ("id", "title", "description", "events", "span", "attack", "notes")} | {
            "sources": [{k: s[k] for k in ("name", "kind", "sha256", "events", "status")} for s in o["sources"]],
            "detections": [{k: d[k] for k in ("title", "level", "n", "hosts", "first", "last")} for d in o["detections"][:60]],
            "story": (S.store_for(cfg).stories(cid, "story", 1) or [{}])[0].get("body")}

    def search(a: dict) -> Any:
        cid = need(a)
        rows, total = S.store_for(cfg).search(cid, q=str(a.get("q", ""))[:300], host=str(a.get("host", ""))[:200],
                                              since=str(a.get("since", ""))[:40], until=str(a.get("until", ""))[:40],
                                              detected=bool(a.get("detected")), limit=min(200, int(a.get("limit", 50))))
        return {"total": total, "events": [{"id": f"E{e['seq']}", "ts": e["ts"], "host": e["host"],
                                            "summary": e["summary"], "rules": [d["title"] for d in e["detections"]]}
                                           for e in rows]}

    add("list_investigations", "Offline investigations (evidence cases) and their size.", {}, list_inv)
    add("get_investigation", "One investigation: evidence with hashes, detections, notes and the latest story.",
        {"id": {"type": "string"}}, get_inv, required=["id"])
    add("search_investigation", "Search the events of one investigation (words or field:value).",
        {"id": {"type": "string"}, "q": {"type": "string"}, "host": {"type": "string"}, "since": {"type": "string"},
         "until": {"type": "string"}, "detected": {"type": "boolean"}, "limit": {"type": "integer"}}, search,
        required=["id"])
