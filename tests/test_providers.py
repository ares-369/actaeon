import pytest

from actaeon import config
from actaeon.providers import LLM, _build
from tests.conftest import write_cfg


def test_role_resolution_defaults_to_provider_model(home):
    llm = LLM(config.get_config(reload=True))
    bm = llm.for_role("planner")
    assert bm.provider.__class__.__name__ == "OllamaProvider"
    assert bm.model == "qwen2.5:7b"


def test_role_model_override(home):
    write_cfg(home, lambda d: d["llm"]["roles"]["analyst"].update(model="other:3b"))
    assert LLM(config.get_config(reload=True)).for_role("analyst").model == "other:3b"


def test_unknown_provider():
    with pytest.raises(ValueError):
        _build("nope", {}, "")


def test_every_listed_provider_builds_without_sdk():
    # Providers import their SDK lazily, so construction must not need it.
    for name in config.PROVIDERS:
        try:
            _build(name, {"base_url": "http://localhost:1"}, "x")
        except ImportError:
            pass


def test_provider_cfg_expands_env(home, monkeypatch):
    monkeypatch.setenv("OLLAMA_URL", "http://model-host:11434")
    write_cfg(home, lambda d: d["llm"]["providers"]["ollama"].update(base_url="${OLLAMA_URL}"))
    assert config.load_config().provider_cfg("ollama")["base_url"] == "http://model-host:11434"


def test_fallback_on_quota(home):
    from actaeon.providers import _COOLDOWN, BoundModel
    from actaeon.providers.base import LLMProvider, LLMResult

    class P(LLMProvider):
        def __init__(self, name, err=None):
            super().__init__({})
            self.name, self.err, self.calls = name, err, 0

        def chat(self, messages, *, model=None, **kw):
            self.calls += 1
            return LLMResult(text="" if self.err else "hi", model=model, error=self.err)
    _COOLDOWN.clear()
    a, b = P("a", "RESOURCE_EXHAUSTED (code 429): quota reached. Resets in 54h"), P("b")
    bound = BoundModel(a, "big", [BoundModel(b, "small")])
    r = bound.chat([])
    assert r.text == "hi" and "fallback" in r.model
    bound.chat([])
    assert a.calls == 1 and b.calls == 2            # exhausted model skipped while cooling down
    c = P("c", "connection refused")
    assert BoundModel(c, "x").chat([]).error == "connection refused"
    both = BoundModel(P("d", "quota"), "1", [BoundModel(P("e", "quota"), "2")]).chat([])
    assert "d/1" in both.error and "e/2" in both.error
    _COOLDOWN.clear()


def test_fallback_config(home):
    from actaeon.providers import LLM
    write_cfg(home, lambda d: d["llm"]["roles"]["analyst"].update(fallback=[{"provider": "ollama", "model": "m2"}]))
    b = LLM(config.get_config(reload=True)).for_role("analyst")
    assert [f.model for f in b.fallbacks] == ["m2"]
    import pytest
    with pytest.raises(ValueError):
        config.preview_llm_update({"analyst": {"provider": "ollama", "fallback": [{"provider": "zzz"}]}})
