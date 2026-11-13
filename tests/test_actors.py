import pytest

from actaeon import config
from actaeon.hunt import service
from actaeon.intel import IntelStore

REPORT = "Uses hxxps://cdn-upd[.]example/a and 203.0.113.90 with a custom loader. Techniques T1566.001 and T1105."


def test_save_and_merge_actor(tmp_path):
    s = IntelStore(tmp_path / "i.sqlite")
    a = s.save_actor("Sample Bear", aliases=["SB-1"], techniques=["t1059.001", "bad"], tools=["LoaderX"],
                     indicators_text=REPORT)
    assert a["slug"] == "sample-bear" and a["techniques"] == ["T1059.001", "T1105", "T1566.001"]
    assert {"cdn-upd.example", "203.0.113.90"} <= {i["value"] for i in a["indicators"]}
    assert all("actor:sample-bear" in i["tags"] for i in a["indicators"])
    b = s.save_actor("Sample Bear", aliases=["Bear Two"], tools=["ToolY"])
    assert b["aliases"] == ["Bear Two", "SB-1"] and b["tools"] == ["LoaderX", "ToolY"]
    assert s.actors()[0]["indicator_count"] == len(a["indicators"])
    with pytest.raises(ValueError):
        s.save_actor(" ")


def test_actor_campaign(home, monkeypatch):
    cfg = config.get_config(reload=True)
    service.intel_for(cfg).save_actor("Sample Bear", tools=["LoaderX"], indicators_text=REPORT)
    started, jobs_started = [], []
    monkeypatch.setattr(service, "start_hunt", lambda jobs, cfg, hyp, **kw: started.append((hyp, kw)) or "h1")
    monkeypatch.setattr(service, "start_job", lambda jobs, kind, meta, fn, **kw: jobs_started.append((kind, fn)) or "j1")
    r = service.actor_campaign(cfg, object(), "sample bear")
    assert r == {"actor": "Sample Bear", "sweep_job": "j1", "hunt_id": "h1"}
    hyp, kw = started[0]
    assert "Sample Bear" in hyp and "LoaderX" in hyp and "T1105 Ingress Tool Transfer" in hyp
    assert kw["origin"] == "actor:sample-bear" and "203.0.113.90" in kw["context"]
    with pytest.raises(ValueError):
        service.actor_campaign(cfg, object(), "nobody")


def test_sweep_by_actor_tag(tmp_path):
    from actaeon.hunt import HuntStore
    from actaeon.hunt.sweep import Sweep
    from tests.test_triage import StateHub
    intel = IntelStore(tmp_path / "i.sqlite")
    intel.add("203.0.113.1", confidence=10, tags=["actor:x"])      # low confidence is still swept for an actor
    intel.add("203.0.113.2", confidence=90)                         # not the actor's
    t = {"connector": "logs", "tool": "search", "arguments": {"index": "e", "query": "{values}", "time_from": "now-7d"}}
    hub = StateHub()
    r = Sweep(hub, intel, HuntStore(tmp_path / "h.sqlite"), {"targets": [t]}).run(tag="actor:x", origin="actor:x")
    assert hub.calls == ['"203.0.113.1"'] and r["origin"] == "actor:x" and r["outcome"] == "threat"


def test_actor_api(home):
    from actaeon.web import create_app
    c = create_app(config.get_config(reload=True)).test_client()
    r = c.post("/api/intel/actors", json={"name": "Sample Bear", "aliases": "SB-1, SB-2", "indicators": REPORT}).json
    assert r["aliases"] == ["SB-1", "SB-2"] and r["indicators_added"] >= 2
    assert c.get("/api/intel/actors").json[0]["name"] == "Sample Bear"
    assert c.get("/api/intel/actors/sample-bear").json["slug"] == "sample-bear"
    assert c.get("/api/intel/actors/zzz").status_code == 404
    assert c.post("/api/intel/actors", json={"name": ""}).status_code == 400
