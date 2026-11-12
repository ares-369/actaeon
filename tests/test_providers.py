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
