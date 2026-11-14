"""Plan only: the planning step without any data query or stored hunt."""
import pytest

from actaeon import config
from actaeon.hunt import HuntEngine, HuntStore, service
from tests.test_hunt import LLM, PLAN, Hub


def test_plan_only_queries_nothing(tmp_path):
    hub = Hub()
    store = HuntStore(tmp_path / "h.sqlite")
    r = HuntEngine(LLM(PLAN, []), hub, store).plan_only("encoded powershell launched from office")
    assert hub.calls == [] and store.list() == []
    assert r["plan"]["steps"][0]["role"] == "log_search"
    assert r["plan"]["missing_roles"] == ["identity"]            # PLAN asks for identity; the fake hub has none
    assert r["tools_by_role"]["log_search"] == ["logs.search"]
    assert r["plan"]["attack"] == ["T1059.001"]                    # "bogus" dropped by the ATT&CK check
    with pytest.raises(ValueError):
        HuntEngine(LLM(PLAN, []), hub, store).plan_only("  ")
    with pytest.raises(RuntimeError):
        HuntEngine(LLM("not json", []), hub, store).plan_only("x happened")


def test_plan_only_api_and_cli(home, capsys, monkeypatch):
    cfg = config.get_config(reload=True)
    monkeypatch.setattr(service, "make_engine", lambda c, **kw: HuntEngine(LLM(PLAN, []), Hub(), service.store_for(c)))
    from actaeon.web import create_app
    c = create_app(cfg).test_client()
    r = c.post("/api/hunts/plan", json={"hypothesis": "office spawned encoded powershell"})
    assert r.status_code == 200 and r.json["plan"]["steps"]
    assert c.post("/api/hunts/plan", json={"hypothesis": ""}).status_code == 400
    assert service.store_for(cfg).list() == []
    from actaeon import cli
    with pytest.raises(SystemExit) as e:
        cli.cli_main(["hunt", "office spawned encoded powershell", "--plan-only"])
    out = capsys.readouterr().out
    assert e.value.code == 0 and "no connector for: identity" in out and "Nothing was queried" in out
