"""Connector contract check: is this MCP server fit for hunting?

``actaeon connectors check [name]`` runs it against a configured connector. It
lists tools, applies Actaeon's policy and reports:

  FAIL  the connector cannot be used (no connection, no tools allowed, bad schemas)
  WARN  it works, but hunts will be weaker or less safe (no read-only hints, a
        search tool that takes no time range or result cap, no TLS, long timeout)
  OK    the check passed

It does not prove the source account is read-only: use a read-only account on
the source as well.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..hunt.validator import CAP_KEYS, QUERY_KEYS, TIME_KEYS

_SEARCHY = re.compile(r"search|query|count|find|events|logs|hunt|lookup_events|top_values|aggregate", re.I)


def _props(tool: dict) -> dict:
    s = tool.get("inputSchema") or {}
    return s.get("properties") or {} if isinstance(s, dict) else {}


def check(hub, name: str) -> list[dict]:
    spec = hub.specs[name]
    out: list[dict] = []

    def add(level: str, what: str, detail: str = "") -> None:
        out.append({"level": level, "check": what, "detail": detail})

    t = hub.test(name)
    if not t["ok"]:
        add("FAIL", "connect and list tools", t.get("error", ""))
        return out
    add("OK", "connect and list tools", f"{t['tools']} tools, {t['ms']} ms"
        + (f", probe {t['probe']} answered" if t.get("probe") else ""))
    tools = hub.tools(name)
    if not tools:
        add("FAIL", "tools", "the server offers no tools")
        return out
    allowed = [x for x in tools if x["allowed"]]
    if not allowed:
        add("FAIL", "allowed tools", "the policy blocks every tool; see 'actaeon connectors tools " + name + "'")
    else:
        add("OK", "allowed tools", f"{len(allowed)} of {len(tools)} allowed")

    bad_schema = [x["name"] for x in tools
                  if not isinstance(x.get("inputSchema"), dict) or x["inputSchema"].get("type", "object") != "object"]
    add("FAIL" if bad_schema else "OK", "input schemas are JSON objects", ", ".join(bad_schema[:10]))
    no_desc = [x["name"] for x in allowed if len((x.get("description") or "").strip()) < 15]
    add("WARN" if no_desc else "OK", "tools describe themselves",
        ("models pick tools from descriptions; missing or very short: " + ", ".join(no_desc[:10])) if no_desc else "")
    undocumented = [f"{x['name']}.{k}" for x in allowed for k, v in _props(x).items()
                    if isinstance(v, dict) and not v.get("description") and k not in TIME_KEYS + CAP_KEYS]
    if len(undocumented) > 3:
        add("WARN", "arguments are described", f"{len(undocumented)} arguments have no description, e.g. "
            + ", ".join(undocumented[:5]))

    no_hint = [x["name"] for x in allowed if (x.get("annotations") or {}).get("readOnlyHint") is not True]
    add("WARN" if no_hint else "OK", "read-only hints",
        ("allowed by name only, the server does not mark them readOnlyHint: " + ", ".join(no_hint[:10]))
        if no_hint else "every allowed tool is marked read-only")
    writes = [x["name"] for x in allowed if (x.get("annotations") or {}).get("readOnlyHint") is False
              or (x.get("annotations") or {}).get("destructiveHint")]
    if writes or spec.allow_write:
        add("WARN", "write access", "allow_write is on" + (f"; write tools allowed: {', '.join(writes)}" if writes
                                                             else ""))
    blocked = [x["name"] for x in tools if not x["allowed"]]
    if blocked:
        add("OK", "blocked by policy", ", ".join(blocked[:15]))

    for x in allowed:
        props = _props(x)
        keys = {k.lower() for k in props}
        if not (_SEARCHY.search(x["name"]) and keys & set(QUERY_KEYS)):
            continue
        snapshot = re.search(r"inventory|current[- ]state|snapshot", x.get("description") or "", re.I)
        if not keys & set(TIME_KEYS) and not snapshot:
            add("WARN", f"{x['name']}: time range", "a search tool with no time argument: hunts cannot bound "
                "how far back it reads, so cost and load depend on the server")
        if not keys & set(CAP_KEYS) and not x["name"].lower().startswith("count"):
            add("WARN", f"{x['name']}: result cap", "no size/limit argument: the result size is up to the server "
                "(Actaeon still cuts what the model sees)")

    if spec.transport == "http":
        u = urlparse(spec.url)
        local = u.hostname in ("localhost", "127.0.0.1", "::1")
        if u.scheme != "https" and not local:
            add("WARN", "transport security", "plain http to a remote host; use https")
        if not spec.verify_tls:
            add("WARN", "transport security", "verify_tls is off")
    if spec.timeout_sec > 300:
        add("WARN", "timeout", f"timeout_sec {spec.timeout_sec:g} is long; hunt.max_query_sec still caps each call")
    if not spec.query_notes and any(_SEARCHY.search(x["name"]) for x in allowed):
        add("WARN", "query notes", "no query_notes: models write better queries when told the source's query "
            "language, field names and examples (see docs/templates/query-notes.md)")
    return out
