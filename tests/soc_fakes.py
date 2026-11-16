"""Fakes for SOC tests: a scripted LLM and an in-memory connector hub."""

from __future__ import annotations

import json

from actaeon.connectors.untrusted import wrap
from actaeon.providers.base import LLMResult


class FakeBound:
    def __init__(self, llm, role):
        self.llm, self.role = llm, role
        self.provider = type("P", (), {"name": "fake"})()
        self.model = "fake"

    def chat(self, messages, **kw):
        self.llm.seen.append((self.role, messages))
        script = self.llm.scripts.get(self.role) or self.llm.scripts.get("analyst") or []
        i = self.llm.pos.get(self.role, 0)
        self.llm.pos[self.role] = i + 1
        reply = script[min(i, len(script) - 1)] if script else {"action": "case", "verdict": "needs_analyst",
                                                                  "confidence": 0, "summary": "none"}
        u = self.llm.usage.setdefault("fake/fake", {"calls": 0, "tokens_in": 0, "tokens_out": 0})
        u["calls"] += 1
        u["tokens_in"] += 100
        u["tokens_out"] += 10
        return LLMResult(text=reply if isinstance(reply, str) else json.dumps(reply), model="fake")


class FakeLLM:
    def __init__(self, analyst=None, planner=None):
        self.scripts = {"analyst": analyst or [], "planner": planner or [{"priority": "P2", "likely": "unclear",
                                                                                 "questions": ["q1"]}]}
        self.pos: dict[str, int] = {}
        self.seen: list = []
        self.usage: dict = {}

    def for_role(self, role):
        return FakeBound(self, role)

    def usage_summary(self):
        u = self.usage.get("fake/fake", {"calls": 0, "tokens_in": 0, "tokens_out": 0})
        return {"calls": u["calls"], "tokens_in": u["tokens_in"], "tokens_out": u["tokens_out"]}


SEARCH = {"name": "search", "description": "search logs", "allowed": True, "reason": "allowed",
          "inputSchema": {"type": "object", "properties": {"query": {"type": "string"},
                                                           "time_from": {"type": "string"}}}}


class FakeSpec:
    def __init__(self, name, roles):
        self.name, self.roles, self.query_notes, self.enabled, self.access = name, roles, "", True, []


class FakeHub:
    def __init__(self, results=None, fail=False):
        self.results = results or {}
        self.fail = fail
        self.calls: list = []
        self.actions: list = []
        self.specs = {"logs": FakeSpec("logs", ["log_search"]), "edr": FakeSpec("edr", ["response"])}

    def tools_for_role(self, role):
        if role == "log_search":
            return [{**SEARCH, "connector": "logs", "dialect": "lucene"}]
        return []

    def call(self, name, tool, args, **kw):
        from actaeon.connectors.hub import ToolCallError
        self.calls.append((name, tool, args))
        if self.fail:
            raise ToolCallError("down")
        text = self.results.get(args.get("query"), '{"total": 3, "hits": [{"host.name": "WS1"}]}')
        return {**wrap(name, tool, text, 8000), "is_error": False}

    def call_action(self, name, tool, args, *, approved_by, case_id=""):
        self.actions.append((name, tool, args, approved_by))
        return {"ok": True, "text": "done"}

    def close(self):
        pass


def call(q="host.name:WS1", thought="look"):
    return {"action": "call", "connector": "logs", "tool": "search", "thought": thought,
            "arguments": {"query": q, "time_from": "now-24h"}}


def verdict(v="true_positive", ev=("E1",), **kw):
    return {"action": "case", "verdict": v, "confidence": 85, "summary": "s",
            "findings": [{"text": "f", "evidence": list(ev)}], **kw}


class SourcesHub(FakeHub):
    """Logs (time-bounded), inventory (snapshot), intel and a decoder, answering like the search-index bridge."""

    def __init__(self, *, processes=(), ports=(), users=(), events=(), intel=(), fields=None, fail=False):
        super().__init__(fail=fail)
        self.processes, self.ports, self.users, self.events = list(processes), list(ports), list(users), list(events)
        self.intel = set(intel)
        self.kw: list[dict] = []
        self.field_names = fields or ["agent.name", "data.srcip", "data.dstip", "data.srcuser", "process.name",
                                      "process.command_line", "full_log", "event.outcome", "user.name", "user.id",
                                      "source.port", "interface.state"]
        idx = {"type": "object", "properties": {"index": {"type": "string"}, "query": {"type": "string"},
                                                "size": {"type": "integer"}}}
        timed = {"type": "object", "properties": {**idx["properties"], "time_from": {"type": "string"},
                                                  "time_to": {"type": "string"}, "field": {"type": "string"}}}
        self._tools = {
            "logs": [{"name": n, "inputSchema": timed} for n in ("search", "count", "top_values")]
            + [{"name": "get_fields", "inputSchema": idx}, {"name": "list_indices", "inputSchema": {"type": "object"}}],
            "inv": [{"name": "search", "inputSchema": idx}, {"name": "get_fields", "inputSchema": idx},
                    {"name": "list_indices", "inputSchema": {"type": "object"}}],
            "intel": [{"name": "lookup", "inputSchema": {"type": "object", "properties": {"value": {"type": "string"}}}}],
            "tools": [{"name": "decode_command", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}],
        }
        roles = {"logs": "log_search", "inv": "asset", "intel": "intel", "tools": "analysis"}
        self.specs = {n: type("S", (), {"name": n, "roles": [roles[n]], "query_notes": "", "enabled": True, "access": [],
                                        "dialect": "query_string (Lucene)", "raw_fields": {}})() for n in roles}
        self._roles = roles

    def tools_for_role(self, role):
        out = []
        for conn, r in self._roles.items():
            if r == role:
                out += [{**t, "connector": conn, "description": "", "allowed": True, "reason": "",
                         "dialect": "query_string (Lucene)"} for t in self._tools[conn]]
        return out

    def call(self, name, tool, args, **kw):
        import json as _json

        from actaeon.connectors.hub import ToolCallError
        from actaeon.connectors.untrusted import wrap
        self.calls.append((name, tool, args))
        self.kw.append(kw)
        if self.fail:
            raise ToolCallError("down")
        if tool == "list_indices":
            pats = ["inv-processes", "inv-ports", "inv-users"] if name == "inv" else ["alerts-*", "events-*"]
            body = {"indices": [], "allowed_patterns": pats}
        elif tool == "get_fields":
            body = {"fields": {f: "keyword" for f in self.field_names}}
        elif tool == "lookup":
            body = {"value": args["value"], "found": args["value"] in self.intel,
                    "matches": [{"value": args["value"], "tags": ["campaign"]}] if args["value"] in self.intel else []}
        elif tool == "decode_command":
            from actaeon.decode import decode
            body = decode(args["text"])
        elif name == "inv":
            rows = {"process": self.processes, "port": self.ports, "user": self.users}[
                next(k for k in ("process", "port", "user") if k in args["index"])]
            body = {"total": len(rows), "hits": rows}
        elif tool == "count":
            body = {"count": 0}
        elif tool == "top_values":
            body = {"buckets": []}
        else:
            body = {"total": len(self.events), "hits": self.events}
        return {**wrap(name, tool, _json.dumps(body), int(kw.get("max_bytes") or 8000)), "is_error": False}
