import pytest
import yaml

from actaeon import config
from tests.conftest import ROOT, write_cfg


def test_example_config_loads(home):
    c = config.get_config(reload=True)
    assert c.bind_host == "127.0.0.1"
    assert c.auth.mode == "none"
    assert c.connectors == []
    assert set(c.llm["roles"]) == set(config.LLM_ROLES)
    assert c.data_dir == home / "data"


def test_packaged_example_matches_root():
    assert (ROOT / "config.example.yaml").read_text() == (ROOT / "actaeon" / "config.example.yaml").read_text()


def test_no_lab_addresses_in_example():
    text = (ROOT / "config.example.yaml").read_text()
    for bad in ("10.0.", "192.168.", "172.16."):
        assert bad not in text


def test_missing_config(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTAEON_CONFIG", str(tmp_path / "nope.yaml"))
    with pytest.raises(FileNotFoundError):
        config.load_config()


def test_bad_auth_mode(home):
    write_cfg(home, lambda d: d["auth"].update(mode="magic"))
    with pytest.raises(ValueError):
        config.load_config()


def test_env_overrides(home, monkeypatch):
    monkeypatch.setenv("ACTAEON_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("ACTAEON_AUTH_PASSWORD", "pw")
    c = config.load_config()
    assert c.bind_host == "0.0.0.0" and c.auth.password == "pw"


def test_hunt_limits_clamped(home):
    write_cfg(home, lambda d: d["hunt"].update(max_steps=0, max_runtime_sec=1))
    c = config.load_config()
    assert c.hunt.max_steps == 1 and c.hunt.max_runtime_sec == 10


def test_model_picker_update(home):
    config.get_config(reload=True)
    prev = config.preview_llm_update({"analyst": {"provider": "anthropic", "model": "some-model"}})
    assert prev["changed"] and "anthropic" in prev["diff"]
    c = config.apply_llm_update({"analyst": {"provider": "anthropic", "model": "some-model"}})
    assert c.role_cfg("analyst") == {"provider": "anthropic", "model": "some-model"}
    assert (home / "config.yaml.bak").exists()
    assert yaml.safe_load((home / "config.yaml").read_text())["llm"]["roles"]["planner"]["provider"] == "ollama"


@pytest.mark.parametrize("roles", [
    {"nope": {"provider": "ollama"}},
    {"analyst": {"provider": "unknown"}},
    {"analyst": {"provider": "ollama", "model": "bad model; rm -rf"}},
    {"analyst": "ollama"},
])
def test_model_picker_rejects(home, roles):
    with pytest.raises(ValueError):
        config.preview_llm_update(roles)


def test_redact():
    assert "hunter2" not in config._redact("api_key: hunter2\n")
