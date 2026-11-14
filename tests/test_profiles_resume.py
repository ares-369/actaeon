"""Hunt profiles and resuming interrupted hunts."""
import json

import pytest

from actaeon import config
from actaeon.hunt import HuntEngine, HuntStore, service
from tests.test_hunt import LLM, PLAN, Hub, call


def test_profiles(home):
    cfg = config.get_config(reload=True)
    q = service.limits_for(cfg, profile="quick")
    assert q.max_steps == 10 and q.compact and q.max_tokens == 150_000
    d = service.limits_for(cfg, profile="deep")
    assert d.max_steps == 40 and d.max_runtime_sec == 1800
    s = service.limits_for(cfg, profile="standard")
    assert s.max_steps == cfg.hunt.max_steps
    assert service.limits_for(cfg, max_steps=5, profile="deep").max_steps == 5
    cfg.raw["hunt"]["profiles"] = {"triage": {"max_steps": 6, "verify": False}}
    assert service.limits_for(cfg, profile="triage").max_steps == 6
    with pytest.raises(ValueError, match="unknown hunt profile"):
        service.profile_settings(cfg, "nope")
    cfg.raw["hunt"]["profiles"] = {"bad": {"colour": "red"}}
    with pytest.raises(ValueError, match="unknown settings"):
        service.profile_settings(cfg, "bad")


def test_quick_profile_skips_second_look(home, monkeypatch):
    cfg = config.get_config(reload=True)
    called = []
    monkeypatch.setattr("actaeon.hunt.verify.verify", lambda *a, **k: called.append(1) or {})
    h = {"id": "x", "outcome": "threat", "profile": "quick", "verdict": {}}
    assert service.maybe_verify(cfg, h) is h and called == []


def test_api_profile(home):
    from actaeon.web import create_app
    c = create_app(config.get_config(reload=True)).test_client()
    assert c.post("/api/hunts", json={"hypothesis": "x happened", "profile": "nope"}).status_code == 400


def _interrupted(store):
    """A hunt whose process died after two tool calls: plan and steps stored, no verdict."""
    hid = store.create("encoded powershell launched from office")
    store.update(hid, status="running", plan=json.dumps({"summary": "s", "attack": [], "steps": [], "data_needed": []}))
    store.add_step(hid, 1, "plan", ok=True, note="{}")
    for n in (2, 3):
        store.add_step(hid, n, "call", connector="logs", tool="search", role="log_search",
                       arguments={"index": "e", "time_from": f"now-{n}h"}, ok=True, result='{"total": 1}')
    return hid


def test_resume_continues_from_stored_steps(tmp_path):
    store = HuntStore(tmp_path / "h.sqlite")
    hid = _interrupted(store)
    hub = Hub(results={"search": '{"total": 1}'})
    llm = LLM(PLAN, [call(index="e", time_from="now-9h"),
                     {"action": "verdict", "outcome": "no_results", "summary": "nothing", "findings": []}])
    h = HuntEngine(llm, hub, store).run("encoded powershell launched from office", hunt_id=hid, resume=True)
    assert h["status"] == "done" and len(hub.calls) == 1               # only the new call, not the two old ones
    assert llm.roles["planner"].seen == []                             # the stored plan is reused
    first_prompt = llm.roles["analyst"].seen[0]
    assert any("E2 result of logs.search" in m["content"] for m in first_prompt)
    assert any("resuming" in m["content"] for m in first_prompt)
    ids = [s["n"] for s in h["steps"] if s["kind"] == "call"]
    assert ids[:2] == [2, 3] and ids[2] > 3                            # evidence ids keep counting
    assert any("resumed after an interruption with 2" in (s["note"] or "") for s in h["steps"])


def test_resume_respects_step_budget(tmp_path):
    from actaeon.hunt import HuntLimits
    store = HuntStore(tmp_path / "h.sqlite")
    hid = _interrupted(store)
    hub = Hub()
    llm = LLM(PLAN, [call(index="e", time_from="now-9h"), {"action": "verdict", "outcome": "inconclusive", "summary": "x"}])
    HuntEngine(llm, hub, store, HuntLimits(max_steps=2)).run("x", hunt_id=hid, resume=True)
    assert hub.calls == []                                             # the 2 stored calls already used the budget


def test_resume_interrupted_rules(home, monkeypatch):
    cfg = config.get_config(reload=True)
    st = service.store_for(cfg)
    a = _interrupted(st)
    b = st.create("replay of something", origin="replay:3")
    st.update(b, status="running")
    c = _interrupted(st)
    st.update(c, resumes=service.MAX_RESUMES)
    queued = []
    monkeypatch.setattr(service, "resume_hunt", lambda jobs, cfg, h, **kw: queued.append(h["id"]) or "j")

    class Jobs:
        def get(self, jid):
            return None
    assert service.resume_interrupted(cfg, Jobs()) == [a] and queued == [a]
    assert st.get(b)["status"] == "stopped" and st.get(c)["status"] == "stopped"
    assert st.get(a, with_steps=False)["resumes"] == 1
    cfg.raw["hunt"]["resume_on_restart"] = False
    d = _interrupted(st)
    assert service.resume_interrupted(cfg, Jobs()) == [] and st.get(d)["status"] == "stopped"
