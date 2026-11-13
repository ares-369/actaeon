"""Login groups -> roles, per-connector access, and who can see restricted hunts."""
import json

import pytest

from actaeon import access, config
from actaeon.connectors.hub import ToolCallError
from actaeon.connectors.spec import parse_connectors
from actaeon.hunt import HuntStore, service

MAIL = {"name": "mail", "roles": ["email"], "transport": "stdio", "command": "true", "access": ["insider", "user:bob"]}
LOGS = {"name": "logs", "roles": ["log_search"], "transport": "stdio", "command": "true"}


def specs():
    return parse_connectors([MAIL, LOGS])


def test_build_and_matches():
    a = access.build(specs(), user="ann", role="operator", groups=["tier1"])
    assert a.connectors == {"logs"}
    assert access.build(specs(), user="ann", role="operator", groups=["insider"]).connectors == {"logs", "mail"}
    assert access.build(specs(), user="bob", role="viewer").connectors == {"logs", "mail"}
    assert access.build(specs(), user="x", role="admin").connectors is None
    assert access.build(parse_connectors([LOGS]), user="x", role="viewer").connectors is None
    assert access.matches("role:operator", "u", "admin", []) and not access.matches("role:admin", "u", "operator", [])


def test_spec_access_validation():
    with pytest.raises(ValueError):
        parse_connectors([{**MAIL, "access": "insider"}])
    with pytest.raises(ValueError):
        parse_connectors([{**MAIL, "access": ["role:boss"]}])


def test_group_roles(home):
    from actaeon.auth import group_role, parse_groups, resolve_user_role
    cfg = config.get_config(reload=True)
    cfg.auth.group_roles = {"soc-admins": "admin", "soc": "operator", "audit": "viewer"}
    cfg.auth.default_role = "viewer"
    assert group_role(cfg, ["audit", "soc"]) == "operator"
    assert resolve_user_role(cfg, "x", ["soc-admins", "audit"]) == "admin"
    assert resolve_user_role(cfg, "x", ["other"]) == "viewer"
    cfg.auth.require_group_role = True
    assert resolve_user_role(cfg, "x", ["other"]) == ""
    cfg.auth.roles = {"x": "operator"}
    assert resolve_user_role(cfg, "x", []) == "operator"     # an explicit user mapping wins
    assert parse_groups("a, b;c") == ["a", "b", "c"] and parse_groups(["a"]) == ["a"] and parse_groups(None) == []


def test_bad_group_role_rejected(home):
    p = home / "config.yaml"
    raw = p.read_text().replace("auth:\n", "auth:\n  group_roles: {soc: boss}\n", 1)
    p.write_text(raw)
    with pytest.raises(ValueError, match="group_roles"):
        config.get_config(reload=True)


def test_hub_hides_and_blocks(tmp_path):
    from tests.test_connectors import make_hub, stdio_spec
    hub = make_hub(tmp_path, stdio_spec(access=["insider"]))
    try:
        tier1 = access.build(hub.specs.values(), user="ann", role="operator", groups=["tier1"])
        assert access.run_as(tier1, hub.tools_for_role, "log_search") == []
        with pytest.raises(ToolCallError, match="not allowed"):
            access.run_as(tier1, hub.call, "fake", "get_host", {})
        assert hub.audit.recent()[0]["status"] == "blocked"
        store = HuntStore(tmp_path / "hunts.sqlite")
        hid = store.create("x")
        insider = access.build(hub.specs.values(), user="eve", role="operator", groups=["insider"])
        assert access.run_as(insider, hub.tools_for_role, "log_search")
        access.run_as(insider, hub.call, "fake", "get_host", {}, hunt_id=hid)
        assert store.restricted_of(hid) == ["fake"]
        assert access.run_as(tier1, store.get, hid) is None
        assert access.run_as(insider, store.get, hid)["restricted"] == ["fake"]
        assert store.get(hid)                 # no caller (scheduler, CLI): everything
        assert [h["id"] for h in access.run_as(tier1, store.list)] == []
    finally:
        hub.close()


def test_jobs_inherit_caller(tmp_path):
    from actaeon.jobs import JobManager
    jm = JobManager(tmp_path / "j.sqlite")
    a = access.Access(user="ann", role="operator", connectors=frozenset({"logs"}))
    seen = {}

    def work(ctl):
        seen["a"] = access.current()
        return {}
    jid = access.run_as(a, jm.submit, "t", {}, work)
    jm.pool.shutdown(wait=True)
    assert seen["a"] == a and jid


def _restricted_hunt(cfg):
    st = service.store_for(cfg)
    hid = st.create("mail from the CFO forwarded outside", actor="eve")
    st.update(hid, status="done", outcome="threat",
              verdict=json.dumps({"outcome": "threat", "confidence": 80, "summary": "forwarding rule",
                                  "findings": [{"claim": "rule forwards to x@evil.example", "evidence": ["E2"]}]}))
    st.add_restricted(hid, "mail")
    service.leads_for(cfg).open_for(st.get(hid))
    service.memory_for(cfg).remember(st.get(hid))
    return hid


def _client(home, monkeypatch, require=False):
    raw = (home / "config.yaml").read_text()
    raw = raw.replace("connectors: []", "connectors:\n  - {name: mail, roles: [email], transport: stdio, command: 'true', "
                                        "access: [insider]}\n", 1)
    (home / "config.yaml").write_text(raw)
    cfg = config.get_config(reload=True)
    cfg.auth.mode = "proxy"
    cfg.auth.proxy_trusted_ips = ["127.0.0.1"]
    cfg.auth.proxy_groups_header = "X-Forwarded-Groups"
    cfg.auth.group_roles = {"soc": "operator", "insider": "operator"}
    cfg.auth.default_role = "viewer"
    cfg.auth.require_group_role = require
    from actaeon.web import create_app
    return cfg, create_app(cfg).test_client()


def test_restricted_hunt_visibility_over_http(home, monkeypatch):
    cfg, c = _client(home, monkeypatch)
    assert "connectors: []" not in (home / "config.yaml").read_text()
    hid = _restricted_hunt(cfg)
    lead = service.leads_for(cfg).by_hunt(hid)
    eve = {"X-Forwarded-User": "eve", "X-Forwarded-Groups": "soc, insider"}
    ann = {"X-Forwarded-User": "ann", "X-Forwarded-Groups": "soc"}
    me = c.get("/api/me", headers=ann).json
    assert me["role"] == "operator" and me["groups"] == ["soc"] and "mail" not in me["connectors"]
    for path in (f"/api/hunts/{hid}", f"/api/hunts/{hid}/stix", f"/api/hunts/{hid}/report.md",
                 f"/api/hunts/{hid}/export.json", f"/api/leads/{lead['id']}"):
        assert c.get(path, headers=eve).status_code == 200, path
        assert c.get(path, headers=ann).status_code == 404, path
    assert hid in json.dumps(c.get("/api/hunts", headers=eve).json)
    assert hid not in json.dumps(c.get("/api/hunts", headers=ann).json)
    assert hid in json.dumps(c.get("/api/leads", headers=eve).json)
    assert hid not in json.dumps(c.get("/api/leads", headers=ann).json)
    assert c.post(f"/api/leads/{lead['id']}/comment", json={"text": "hi"}, headers=ann).status_code == 404
    assert "forwarding" not in json.dumps(c.get("/api/memory/related?q=CFO forwarded", headers=ann).json)
    assert "forwarding" in json.dumps(c.get("/api/memory/related?q=CFO forwarded", headers=eve).json)


def test_require_group_role_refuses(home, monkeypatch):
    _cfg, c = _client(home, monkeypatch, require=True)
    assert c.get("/api/me", headers={"X-Forwarded-User": "zed", "X-Forwarded-Groups": "marketing"}).status_code == 403
    assert c.get("/api/me", headers={"X-Forwarded-User": "ann", "X-Forwarded-Groups": "soc"}).status_code == 200


def test_outputs_skip_restricted(home):
    from actaeon.outputs import dispatch
    cfg = config.get_config(reload=True)
    cfg.raw["outputs"] = [{"name": "hook", "type": "webhook", "when": ["all"], "url": "https://h.example/a"},
                          {"name": "inner", "type": "webhook", "when": ["all"], "url": "https://h.example/b",
                           "include_restricted": True}]

    class S:
        posts = []

        def post(self, url, **kw):
            self.posts.append(url)
            return type("R", (), {"status_code": 200})()
    s = S()
    res = dispatch(cfg, {"id": "x", "outcome": "threat", "verdict": {}, "steps": [], "restricted": ["mail"]}, session=s)
    assert s.posts == ["https://h.example/b"] and "skipped" in res[0]["detail"]
