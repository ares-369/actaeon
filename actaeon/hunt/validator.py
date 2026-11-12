"""Checks every tool call the model proposes BEFORE it is sent.

This is a basic sanity check, not a guarantee:
  * arguments match the tool's input schema (required fields, basic types, size)
  * a tool that takes a time range must be given one (no unbounded searches)
  * result-size arguments are capped at ``max_results``
  * query text that looks like it writes, deletes or runs code is refused
The connector policy (read-only tools) and the source's own permissions are
the other layers.
"""

from __future__ import annotations

import json
import re
from typing import Any

TIME_KEYS = ("time_from", "from", "start", "start_time", "starttime", "earliest", "since", "after", "begin",
             "time_range", "timerange", "time_window", "start_date", "lookback")
CAP_KEYS = ("size", "limit", "max_results", "maxresults", "count", "top", "page_size", "pagesize", "rows")
QUERY_KEYS = ("query", "q", "search", "filter", "expression", "statement", "sql", "dsl", "pattern")
MAX_QUERY = 4000
MAX_ARGS_BYTES = 20_000

_BAD_QUERY = [
    (re.compile(r"_(delete|update)_by_query|_reindex|_bulk|_close|_shrink|_forcemerge", re.I), "index-changing endpoint"),
    (re.compile(r"\bdelete\s+(from|index|table)\b", re.I), "delete statement"),
    (re.compile(r"\b(drop|truncate|alter)\s+(table|index|database|schema)\b", re.I), "schema change"),
    (re.compile(r"\binsert\s+into\b|\bupdate\s+\w+\s+set\b", re.I), "write statement"),
    (re.compile(r"\|\s*(delete|outputlookup|outputcsv|collect|sendemail|sendalert|script|run|map|tscollect)\b", re.I),
     "pipeline command that writes or runs code"),
    (re.compile(r"\b(exec|eval|system|os\.popen|subprocess)\s*\(", re.I), "code execution"),
    (re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"), "control characters"),
]


class ValidationError(ValueError):
    pass


def _schema_props(tool: dict) -> tuple[dict, list[str]]:
    s = tool.get("inputSchema") or {}
    return (s.get("properties") or {}), list(s.get("required") or [])


def _type_ok(value: Any, typ: str) -> bool:
    return {
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
    }.get(typ, True)


def _strings(obj: Any, key: str = ""):
    if isinstance(obj, str):
        yield key, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, str(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v, key)


def validate_call(tool: dict, arguments: Any, *, max_results: int = 200) -> tuple[dict, list[str]]:
    """Return (possibly capped arguments, notes) or raise ValidationError with a reason the model can act on."""
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise ValidationError("arguments must be a JSON object")
    if len(json.dumps(arguments, default=str)) > MAX_ARGS_BYTES:
        raise ValidationError("arguments are too large")
    props, required = _schema_props(tool)
    notes: list[str] = []
    args = dict(arguments)

    missing = [r for r in required if r not in args or args[r] in (None, "")]
    if missing:
        raise ValidationError(f"missing required argument(s): {', '.join(missing)}")
    for k, v in args.items():
        typ = (props.get(k) or {}).get("type")
        if isinstance(typ, str) and not _type_ok(v, typ):
            if typ == "integer" and isinstance(v, str) and v.strip().isdigit():
                args[k] = int(v)
                continue
            raise ValidationError(f"argument {k!r} must be of type {typ}")
        enum = (props.get(k) or {}).get("enum")
        if enum and v not in enum:
            raise ValidationError(f"argument {k!r} must be one of {enum}")

    time_params = [k for k in props if k.lower() in TIME_KEYS]
    if time_params and not any(args.get(k) not in (None, "") for k in time_params):
        raise ValidationError(f"this tool takes a time range; set {time_params[0]!r} (for example now-24h)")

    for k in list(args):
        if k.lower() in CAP_KEYS and isinstance(args[k], int) and args[k] > max_results:
            notes.append(f"{k} capped from {args[k]} to {max_results}")
            args[k] = max_results

    for key, text in _strings(args):
        if key.lower() in QUERY_KEYS and len(text) > MAX_QUERY:
            raise ValidationError(f"{key} is longer than {MAX_QUERY} characters")
        for rx, why in _BAD_QUERY:
            if rx.search(text):
                raise ValidationError(f"refused: {key or 'argument'} contains a {why}; hunts are read-only")
    return args, notes
