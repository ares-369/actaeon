"""A read-only MCP connector for Actaeon, in one file. Copy it, fill in _search().

Run it as a stdio connector:

    connectors:
      - name: my-source
        roles: [log_search]
        transport: stdio
        command: python3
        args: ["/path/to/connector_template.py"]
        env: {MY_SOURCE_TOKEN: "${MY_SOURCE_TOKEN}"}     # secrets only from the environment

Then: actaeon connectors check my-source

Rules a good hunting connector follows (the check looks for them):
  * every tool is read-only and says so (readOnlyHint: true)
  * search tools take a time range and a result cap, and enforce both themselves
  * tools and arguments have descriptions; errors are short and say what to fix
No dependencies: plain JSON-RPC over stdin/stdout (MCP stdio transport).
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

MAX_DAYS, MAX_ROWS = 30, 500


def _search(query: str, start: datetime, end: datetime, limit: int) -> list[dict]:
    """Replace with a call to your source, using a READ-ONLY account (token from os.environ)."""
    _token = os.environ.get("MY_SOURCE_TOKEN", "")
    return [{"time": end.isoformat(), "message": f"example row for {query!r}"}][:limit]


def search(args: dict) -> dict:
    q = str(args.get("query") or "").strip()
    if not q:
        raise ValueError("query is required")
    end = datetime.fromisoformat(args["time_to"]) if args.get("time_to") else datetime.now(timezone.utc)
    start = datetime.fromisoformat(args["time_from"]) if args.get("time_from") else end - timedelta(days=1)
    if end - start > timedelta(days=MAX_DAYS):
        raise ValueError(f"time range is longer than {MAX_DAYS} days; narrow it")
    limit = max(1, min(int(args.get("limit") or 100), MAX_ROWS))
    rows = _search(q, start, end, limit)
    return {"total": len(rows), "rows": rows}


TOOLS = {
    "search": (search, {
        "description": "Search events in my source. Returns matching rows, newest first.",
        "inputSchema": {"type": "object", "required": ["query", "time_from"], "properties": {
            "query": {"type": "string", "description": "query in the source's language"},
            "time_from": {"type": "string", "description": "ISO 8601 start (UTC)"},
            "time_to": {"type": "string", "description": "ISO 8601 end (UTC); default now"},
            "limit": {"type": "integer", "description": f"rows to return, at most {MAX_ROWS}"}}},
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}}),
}


def handle(msg: dict):
    method, rid = msg.get("method"), msg.get("id")
    if rid is None:
        return None                                       # a notification
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "my-source", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": n, **meta} for n, (_fn, meta) in TOOLS.items()]}
    elif method == "tools/call":
        name = (msg.get("params") or {}).get("name")
        if name not in TOOLS:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": f"unknown tool {name}"}}
        try:
            data = TOOLS[name][0]((msg.get("params") or {}).get("arguments") or {})
            result = {"content": [{"type": "text", "text": json.dumps(data, default=str)}]}
        except (ValueError, KeyError) as exc:
            result = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            reply = handle(json.loads(line))
            if reply is not None:
                print(json.dumps(reply), flush=True)
