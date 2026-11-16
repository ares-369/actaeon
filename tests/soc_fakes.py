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
