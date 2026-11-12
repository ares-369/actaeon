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
