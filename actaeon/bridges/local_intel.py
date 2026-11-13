"""Local intel bridge: serves Actaeon's own intel store over MCP, read-only.

Adding intel happens in the UI, API or CLI; this bridge only reads.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ..intel.extract import TYPES, extract
from ..intel.store import IntelStore
from .common import cap, parse_time
from .server import McpServer, ToolInputError


def build(store: IntelStore) -> McpServer:
    srv = McpServer("actaeon-local-intel", instructions=(
        "Read-only access to indicators and advisories the analyst added. Each indicator has a "
        "confidence (0-100), tags, source, first_seen, last_seen and seen_count."))

    def lookup(a):
        v = str(a.get("value", "")).strip()
        if not v:
            raise ToolInputError("value is required")
        return store.lookup(v)

    def list_indicators(a):
        kind = a.get("type")
        if kind and kind not in TYPES:
            raise ToolInputError(f"type must be one of {TYPES}")
        since = parse_time(str(a["changed_since"]), default="now-7d").isoformat(timespec="seconds") \
            if a.get("changed_since") else None
        rows = store.list(kind=kind, tag=a.get("tag"), min_confidence=int(a.get("min_confidence", 0)),
                          changed_since=since, limit=cap(a.get("limit"), 100, 1000))
        return {"count": len(rows), "indicators": rows}

    def get_advisory(a):
        d = store.advisory(int(a.get("id", 0)))
        if not d:
            raise ToolInputError("no advisory with that id")
        d["text"] = d["text"][:20_000]
        return d

    def extract_indicators(a):
        return extract(str(a.get("text", ""))[:200_000])

    srv.tool("lookup", "Is this value (IP, domain, URL, hash, email, CVE) in the intel store?",
             {"type": "object", "properties": {"value": {"type": "string", "description": "the value to look up"}},
              "required": ["value"]})(lookup)
    srv.tool("list_indicators", "List indicators, filtered by type, tag, confidence or change time.",
             {"type": "object", "properties": {"type": {"type": "string", "enum": list(TYPES),
                                                          "description": "indicator type"},
              "tag": {"type": "string", "description": "only indicators with this tag"},
              "min_confidence": {"type": "integer", "description": "0-100"},
              "changed_since": {"type": "string", "description": "ISO-8601 or now-7d"},
              "limit": {"type": "integer", "description": "max rows"}}})(list_indicators)
    srv.tool("list_advisories", "List advisories with their ATT&CK techniques and CVEs.",
             {"type": "object", "properties": {"limit": {"type": "integer", "description": "max rows"}}})(
        lambda a: {"advisories": store.advisories(cap(a.get("limit"), 50, 500))})
    srv.tool("get_advisory", "Get one advisory with its text and indicators.",
             {"type": "object", "properties": {"id": {"type": "integer", "description": "advisory id"}},
              "required": ["id"]})(get_advisory)
    srv.tool("extract_indicators", "Extract indicators and technique IDs from text (does not save).",
             {"type": "object", "properties": {"text": {"type": "string", "description": "text to scan"}},
              "required": ["text"]})(extract_indicators)
    srv.tool("intel_stats", "Counts of indicators by type and of advisories.",
             {"type": "object", "properties": {}})(lambda a: store.stats())
    return srv


def add_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--db", required=True, help="path to intel.sqlite")


def run(a: argparse.Namespace) -> None:
    build(IntelStore(Path(a.db))).serve()
