"""Common LLM provider interface.

Every provider implements the same surface so the engine never cares which
model is behind a role. Tool-calling (``chat_with_tools``) is defined here and
used by the Phase 3 agent loop; providers that lack native tool use fall back
to a ReAct-style prompt.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

Message = dict[str, str]  # {"role": "system|user|assistant", "content": "..."}

ACTION_TOOLS: list[dict[str, Any]] = [
    {
        "name": "call_tool",
        "description": "Call one read-only connector tool.",
        "parameters": {
            "type": "object",
            "properties": {
                "thought": {"type": "string"},
                "connector": {"type": "string"},
                "tool": {"type": "string"},
                "arguments": {"type": "object"},
            },
            "required": ["connector", "tool", "arguments"],
        },
    },
    {
        "name": "submit_verdict",
        "description": "Submit the final hunt verdict.",
        "parameters": {
            "type": "object",
            "properties": {
                "outcome": {"type": "string"},
                "confidence": {"type": "integer"},
                "summary": {"type": "string"},
                "findings": {"type": "array", "items": {"type": "object"}},
                "attack": {"type": "array", "items": {"type": "string"}},
                "gaps": {"type": "array", "items": {"type": "string"}},
                "needed_data_present": {"type": "boolean",
                                        "description": "false if the kind of event the hypothesis needs exists in no source"},
                "next_steps": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["outcome", "confidence", "summary"],
        },
    },
]


CASE_TOOL: dict[str, Any] = {
    "name": "submit_case",
    "description": "Submit the final verdict on the alert case. This ends the investigation.",
    "parameters": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "benign", "needs_analyst",
                                                    "logs_missing"]},
            "confidence": {"type": "integer"},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "title": {"type": "string"},
            "summary": {"type": "string"},
            "findings": {"type": "array", "items": {"type": "object"}},
            "timeline": {"type": "array", "items": {"type": "object"}},
            "entities": {"type": "array", "items": {"type": "object"}},
            "relations": {"type": "array", "items": {"type": "object"}},
            "attack": {"type": "array", "items": {"type": "string"}},
            "fix": {"type": "object"},
            "actions": {"type": "array", "items": {"type": "object"}},
            "gaps": {"type": "array", "items": {"type": "string"}},
            "next_steps": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["verdict", "confidence", "summary"],
    },
}


_ACTION_RE = re.compile(r'"action":\s*"(\w+)"')


def loop_final_action(system: str) -> str | None:
    """The action that ends a tool loop ("verdict" for hunts, "answer" for chat, "verify" for the second
    look), or None when the prompt does not use Actaeon's call/<final> action protocol."""
    acts = _ACTION_RE.findall(system or "")
    if "call" not in acts:
        return None
    others = [a for a in acts if a != "call"]
    return others[0] if others else None


def is_tool_loop_system(system: str) -> bool:
    """True when the system prompt uses Actaeon's call/<final action> protocol."""
    return loop_final_action(system) is not None


def action_tools(system: str) -> list[dict[str, Any]]:
    """Native tool declarations for a tool loop: call_tool plus the loop's final action. Declaring the final
    action as a tool matters: newer models, given tools described only in text, emit their own tool calls
    and fail with a malformed function call."""
    final = loop_final_action(system) or "verdict"
    if final == "verdict":
        return ACTION_TOOLS
    if final == "case":
        return [ACTION_TOOLS[0], CASE_TOOL]
    return [ACTION_TOOLS[0], {
        "name": f"submit_{final}",
        "description": f"Give the final {final}. This ends the investigation.",
        "parameters": {"type": "object", "properties": {
            "text": {"type": "string", "description": "the answer in plain language"},
            "answer": {"type": "string", "description": "the specific value asked for, if any"},
            "result": {"type": "string", "description": "for a second look: confirmed, refuted or unconfirmed"},
            "reason": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "string"}, "description": "evidence ids such as E3"},
        }},
    }]


def action_json(tool_name: str, args: dict[str, Any] | None) -> str:
    """Translate a native call_tool / submit_<final> call into Actaeon's JSON action."""
    args = dict(args or {})
    if tool_name.startswith("submit_") and len(tool_name) > 7:
        return json.dumps({"action": tool_name[7:], **args})
    if tool_name != "call_tool":
        # The model called a connector tool by its own name instead of call_tool.
        args = {"tool": tool_name, "arguments": args}
    return json.dumps({"action": "call", **args})


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResult:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    model: str = ""
    error: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    tokens_cached: int = 0      # part of tokens_in the provider served from its prompt cache (billed lower)


class LLMProvider(ABC):
    name: str = "base"

    def __init__(self, cfg: dict[str, Any], secret: str = ""):
        self.cfg = cfg or {}
        self.secret = secret
        self.default_model = self.cfg.get("default_model", "")

    @abstractmethod
    def chat(
        self,
        messages: list[Message],
        *,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 900,
    ) -> LLMResult:
        ...

    def chat_with_tools(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]],
        *,
        model: str | None = None,
    ) -> LLMResult:
        # Default: providers without native tool use just answer in text.
        # The agent loop (Phase 3) handles ReAct parsing for these.
        return self.chat(messages, model=model)

    def available_models(self) -> list[str]:
        return [self.default_model] if self.default_model else []

    def health(self) -> bool:
        return True
