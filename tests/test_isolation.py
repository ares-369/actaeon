"""Permission boundaries across schedules, saved hunts and memory notes."""
import json

import pytest

from actaeon import access, config
from actaeon.hunt import service
from tests.test_connectors import make_hub, stdio_spec


def _users(specs):
    tier1 = access.build(specs, user="ann", role="operator", groups=["tier1"])
    insider = access.build(specs, user="eve", role="operator", groups=["insider"])
    return tier1, insider


def _saved_hunt(cfg, store_restricted, calls, owner):
    st = service.store_for(cfg)
    hid = st.create("check host A")
    for n, (conn, tool) in enumerate(calls, 1):
        st.add_step(hid, n, "call", connector=conn, tool=tool, arguments={}, ok=True, result="{}")
    for r in store_restricted:
        st.add_restricted(hid, r)
    st.update(hid, status="done", outcome="no_results", verdict=json.dumps({"outcome": "no_results"}))
    h = st.get(hid)
    return access.run_as(owner, service.library_for(cfg).save_from_hunt, h, name="x", interval_minutes=5)


def test_saved_hunts_hidden_and_owner_recorded(home, tmp_path):
    cfg = config.get_config(reload=True)
    hub = make_hub(tmp_path, stdio_spec(access=["insider"]))
    try:
        tier1, insider = _users(hub.specs.values())
        s = _saved_hunt(cfg, ["fake"], [("fake", "get_host")], insider)
        assert s["owner"] == "eve" and s["restricted"] == ["fake"]
        lib = service.library_for(cfg)
        assert access.run_as(tier1, lib.get, s["id"]) is None
        assert access.run_as(tier1, lib.list) == []
        assert access.run_as(insider, lib.get, s["id"])["id"] == s["id"]
    finally:
        hub.close()


def test_scheduled_replay_runs_as_owner(home, tmp_path):
    cfg = config.get_config(reload=True)
    hub = make_hub(tmp_path, stdio_spec(access=["insider"]))
    try:
        tier1, _ = _users(hub.specs.values())
        # saved by ann (tier1), whose recorded calls touch a connector she may not use
        s = _saved_hunt(cfg, [], [("fake", "get_host")], tier1)
        res = service.run_replay(cfg, s["id"], hub=hub)          # no caller: the scheduler
        steps = service.store_for(cfg).get(res["id"])["steps"]
        assert any(x["kind"] == "blocked" and x["connector"] == "fake" for x in steps)
        assert not [r for r in hub.audit.recent() if r["status"] == "ok"]   # nothing read from the source
    finally:
        hub.close()


def test_audit_names_the_identity(tmp_path):
    hub = make_hub(tmp_path, stdio_spec())
    try:
        ann = access.Access(user="ann", role="operator")
        access.run_as(ann, hub.call, "fake", "get_host", {}, actor="replay:3")
        assert hub.audit.recent()[0]["actor"] == "replay:3 (as ann)"
    finally:
        hub.close()


def test_scheduler_identity(home, monkeypatch):
    cfg = config.get_config(reload=True)
    assert access.scheduler_access(cfg) is None                    # default: no identity, every connector
    cfg.raw["scheduler"] = {"groups": ["soc"], "role": "operator"}
    cfg.raw["connectors"] = [{"name": "mail", "roles": ["email"], "transport": "stdio", "command": "true",
                              "access": ["insider"]}]
    cfg.connectors = cfg.raw["connectors"]
    a = access.scheduler_access(cfg)
    assert a.user == "scheduler" and "mail" not in (a.connectors or set())
    cfg.intel = {"sweep": {"interval_minutes": 1}}
    seen = []
    monkeypatch.setattr(service, "start_job", lambda jobs, kind, meta, fn, **kw: seen.append((kind, access.current())) or "j")
    from actaeon.hunt.scheduler import Scheduler
    Scheduler(cfg, None).tick()
    assert seen and seen[0][0] == "sweep" and seen[0][1].user == "scheduler"
    cfg.raw["scheduler"] = {"role": "boss"}
    with pytest.raises(ValueError):
        access.scheduler_access(cfg)


def test_restricted_notes(home, tmp_path):
    cfg = config.get_config(reload=True)
    specs = make_hub(tmp_path, stdio_spec(access=["insider"])).specs.values()
    tier1, insider = _users(specs)
    mem = service.memory_for(cfg)
    mem.add_note("fake connector: the CFO forwards to a personal address on purpose", author="eve",
                 restricted=["fake"])
    mem.add_note("backup01 uploads nightly to cloud storage", author="ann")
    texts = lambda: [n["text"][:6] for n in mem.notes()]   # noqa: E731
    assert len(access.run_as(insider, texts)) == 2
    assert access.run_as(tier1, texts) == ["backup"]
    assert "CFO" not in access.run_as(tier1, mem.context, "CFO forwards personal address")
    assert "CFO" in access.run_as(insider, mem.context, "CFO forwards personal address")


def test_feedback_note_inherits_restriction(home):
    cfg = config.get_config(reload=True)
    st = service.store_for(cfg)
    hid = st.create("x")
    st.update(hid, status="done", outcome="threat", verdict=json.dumps(
        {"outcome": "threat", "findings": [{"claim": "mail rule forwards out", "evidence": ["E2"]}]}))
    st.add_restricted(hid, "mail")
    r = service.add_feedback(cfg, hid, finding=0, kind="benign", author="eve")
    assert r["note"]["restricted"] == ["mail"]
