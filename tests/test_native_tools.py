"""Native tool calling: translation to the JSON action protocol and fallback when tools are rejected."""
import json
from types import SimpleNamespace as NS

from actaeon.providers.base import action_json
from actaeon.providers.openai_compat import OpenAICompatProvider

SYSTEM = 'Reply with {"action": "call", ...} or {"action": "verdict", ...}'


def test_action_json_mapping():
    assert json.loads(action_json("submit_verdict", {"outcome": "threat"}))["action"] == "verdict"
    c = json.loads(action_json("call_tool", {"connector": "logs", "tool": "search", "arguments": {}}))
    assert c["action"] == "call" and c["tool"] == "search"
    # An unknown name is a tool call, never a silent verdict.
    u = json.loads(action_json("search", {"query": "x"}))
    assert u == {"action": "call", "tool": "search", "arguments": {"query": "x"}}


class _Completions:
    def __init__(self, reject_tools, reply):
        self.calls, self.reject_tools, self.reply = [], reject_tools, reply

    def create(self, **kw):
        self.calls.append(kw)
        if self.reject_tools and "tools" in kw:
            raise RuntimeError("model does not support tools")
        return NS(choices=[NS(message=self.reply)])


def _provider(comp, **cfg):
    p = OpenAICompatProvider({"default_model": "m", "base_url": "http://x", **cfg}, "k")
    p._client = lambda: NS(chat=NS(completions=comp))
    return p


def _msgs():
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hunt"}]


def test_openai_native_tool_call():
    fn = NS(name="call_tool", arguments=json.dumps({"connector": "a", "tool": "b", "arguments": {}}))
    comp = _Completions(False, NS(content=None, tool_calls=[NS(function=fn)]))
    r = _provider(comp).chat(_msgs())
    assert json.loads(r.text)["action"] == "call" and "tools" in comp.calls[0]


def test_openai_falls_back_without_tools():
    comp = _Completions(True, NS(content='{"action": "verdict"}', tool_calls=None))
    r = _provider(comp).chat(_msgs())
    assert r.error is None and r.text == '{"action": "verdict"}'
    assert len(comp.calls) == 2 and "tools" not in comp.calls[1]


def test_openai_native_off_and_bad_arguments():
    comp = _Completions(False, NS(content="hi", tool_calls=None))
    _provider(comp, native_tools=False).chat(_msgs())
    assert "tools" not in comp.calls[0]
    fn = NS(name="call_tool", arguments="{not json")
    comp = _Completions(False, NS(content=None, tool_calls=[NS(function=fn)]))
    assert json.loads(_provider(comp).chat(_msgs()).text)["action"] == "call"


def test_gemini_retries_without_tools_on_malformed_call(monkeypatch):
    pytest = __import__("pytest")
    types = pytest.importorskip("google.genai").types
    from actaeon.providers.gemini import GeminiProvider
    calls = []

    class Models:
        def generate_content(self, model, contents, config):
            calls.append(config)
            if config.tools:
                return NS(function_calls=None, text=None, prompt_feedback=None,
                          candidates=[NS(finish_reason="FinishReason.MALFORMED_FUNCTION_CALL")])
            return NS(function_calls=None, text='{"action": "verdict"}', prompt_feedback=None, candidates=[])
    p = GeminiProvider({"default_model": "m", "auth": "api_key"}, "k")
    p._client = NS(models=Models())
    r = p.chat(_msgs())
    assert r.error is None and r.text == '{"action": "verdict"}'
    assert len(calls) == 2 and calls[0].tools and not calls[1].tools
    assert isinstance(calls[1], types.GenerateContentConfig)


def test_gemini_empty_stop_reply_is_retried():
    import pytest
    pytest.importorskip("google.genai")
    from actaeon.providers.gemini import GeminiProvider
    n = []

    class Models:
        def generate_content(self, model, contents, config):
            n.append(1)
            if len(n) == 1:
                return NS(function_calls=None, text="", prompt_feedback=None, candidates=[NS(finish_reason="FinishReason.STOP")])
            return NS(function_calls=None, text='{"action": "verdict"}', prompt_feedback=None, candidates=[])
    p = GeminiProvider({"default_model": "m", "auth": "api_key"}, "k")
    p._client = NS(models=Models())
    r = p.chat(_msgs())
    assert r.error is None and r.text == '{"action": "verdict"}' and len(n) == 2


def test_gemini_repeated_malformed_call_is_an_unusable_reply_not_an_error():
    import pytest
    pytest.importorskip("google.genai")
    from actaeon.providers.gemini import GeminiProvider

    class Models:
        def generate_content(self, model, contents, config):
            return NS(function_calls=None, text=None, prompt_feedback=None,
                      candidates=[NS(finish_reason="FinishReason.MALFORMED_FUNCTION_CALL")])
    p = GeminiProvider({"default_model": "m", "auth": "api_key"}, "k")
    p._client = NS(models=Models())
    r = p.chat(_msgs())
    assert r.error is None and r.text == ""      # the hunt loop asks again instead of failing the hunt


def test_gemini_thinking_config_is_passed():
    import pytest
    pytest.importorskip("google.genai")
    from actaeon.providers.gemini import GeminiProvider
    seen = []

    class Models:
        def generate_content(self, model, contents, config):
            seen.append(config)
            return NS(function_calls=None, text='{"action": "verdict"}', prompt_feedback=None, candidates=[])
    p = GeminiProvider({"default_model": "m", "auth": "api_key", "thinking_budget": 512}, "k")
    p._client = NS(models=Models())
    p.chat(_msgs())
    assert seen[0].thinking_config.thinking_budget == 512


def test_final_action_tools_for_every_loop():
    import json as _j

    from actaeon.hunt.chat import CHAT_SYSTEM
    from actaeon.hunt.verify import VERIFY_SYSTEM
    from actaeon.providers.base import action_json, action_tools, is_tool_loop_system, loop_final_action
    assert loop_final_action('{"action": "call"} or {"action": "verdict"}') == "verdict"
    assert loop_final_action('{"action": "call"} ... {"action": "answer"}') == "answer"
    assert loop_final_action('{"action": "start_hunt"} {"action": "answer"}') is None    # no call: not a tool loop
    for system, final in ((CHAT_SYSTEM, "answer"), (VERIFY_SYSTEM, "verify")):
        assert is_tool_loop_system(system) and loop_final_action(system) == final
        names = [t["name"] for t in action_tools(system)]
        assert names == ["call_tool", f"submit_{final}"]
    assert [t["name"] for t in action_tools('{"action": "call"} {"action": "verdict"}')] == ["call_tool", "submit_verdict"]
    assert _j.loads(action_json("submit_answer", {"text": "x", "evidence": ["E2"]})) == {
        "action": "answer", "text": "x", "evidence": ["E2"]}
    assert _j.loads(action_json("submit_verdict", {"outcome": "threat"}))["action"] == "verdict"
