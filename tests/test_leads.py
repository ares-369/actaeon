import base64

import pytest

from actaeon import config
from actaeon.auth import hash_password
from actaeon.leads import LeadStore, severity_of
from actaeon.web import create_app
from tests.conftest import write_cfg

THREAT = {"id": "h1", "hypothesis": "Office started encoded PowerShell", "outcome": "threat", "origin": "manual",
          "status": "done", "verdict": {"outcome": "threat", "confidence": 90, "summary": "bad",
                                        "verification": {"result": "confirmed"}}}


def test_lead_lifecycle(tmp_path):
    st = LeadStore(tmp_path / "h.sqlite")
    c = st.open_for(THREAT)
    assert c["status"] == "new" and c["severity"] == "critical"
    assert st.open_for({"id": "h2", "outcome": "no_results", "verdict": {}}) is None
    assert st.open_for(dict(THREAT))["id"] == c["id"]               # refresh, not a duplicate
    c = st.acknowledge(c["id"], "alice")
    assert c["status"] == "acknowledged" and c["assignee"] == "alice" and c["acknowledged_at"]
    c = st.set_status(c["id"], "alice", "in_progress")
    c = st.comment(c["id"], "bob", "looks like the patch tool")
    with pytest.raises(ValueError):
        st.close(c["id"], "bob", "false_positive", "  ")
    with pytest.raises(ValueError):
        st.close(c["id"], "bob", "meh", "x")
    c = st.close(c["id"], "bob", "false_positive", "nightly patch job")
    assert c["status"] == "closed" and c["closed_by"] == "bob" and c["resolution"] == "false_positive"
    with pytest.raises(ValueError):
        st.acknowledge(c["id"], "carol")
    c = st.reopen(c["id"], "carol", "it happened again")
    assert c["status"] == "acknowledged" and c["resolution"] == ""
    actions = [e["action"] for e in c["events"]]
    assert actions == ["opened", "updated", "acknowledged", "status", "comment", "closed", "reopened"]
    s = st.stats()
    assert s["open"] == 1 and s["mean_minutes_to_acknowledge"] is not None


def test_severity():
    assert severity_of({"outcome": "threat", "verdict": {"confidence": 60}}) == "medium"
    assert severity_of({"outcome": "inconclusive", "verdict": {"needs_review": True}}) == "medium"


def auth_home(home, monkeypatch):
    write_cfg(home, lambda d: d["auth"].update(mode="basic", users={
        "alice": {"password_hash": hash_password("alice-password-1"), "role": "operator", "name": "Alice A"},
        "victor": {"password_hash": hash_password("victor-password-1"), "role": "viewer"}}))
    return create_app(config.load_config()).test_client()


def hdr(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


def test_leads_api_with_named_users(home, monkeypatch):
    c = auth_home(home, monkeypatch)
    from actaeon.hunt import service
    hstore = service.store_for(config.get_config())
    hid = hstore.create("Office started encoded PowerShell")
    hstore.update(hid, status="done", outcome="threat", verdict={"outcome": "threat", "confidence": 75,
                                                                    "summary": "s"})
    service.send_outputs(config.get_config(), hstore.get(hid))
    a, v = hdr("alice", "alice-password-1"), hdr("victor", "victor-password-1")
    assert c.get("/api/me", headers=a).json == {"user": "alice", "role": "operator", "auth_mode": "basic",
                                                 "name": "Alice A"}
    leads = c.get("/api/leads", headers=v).json                      # viewers see everything
    cid = leads[0]["id"]
    assert c.post(f"/api/leads/{cid}/acknowledge", headers=v).status_code == 403   # but cannot change it
    r = c.post(f"/api/leads/{cid}/acknowledge", headers=a).json
    assert r["assignee"] == "alice"
    assert c.get("/api/leads?assignee=me", headers=a).json[0]["id"] == cid
    assert c.post(f"/api/leads/{cid}/close", headers=a, json={"resolution": "benign_true_positive"}).status_code == 400
    r = c.post(f"/api/leads/{cid}/close", headers=a, json={"resolution": "benign_true_positive",
                                                          "comment": "admin testing"}).json
    assert r["status"] == "closed" and r["closed_by"] == "alice"
    notes = service.memory_for(config.get_config()).notes()
    assert notes and "Known benign (lead" in notes[0]["text"] and notes[0]["author"] == "alice"
    detail = c.get(f"/api/leads/{cid}", headers=v).json
    assert detail["hunt"]["id"] == hid and detail["events"][-1]["user"] == "alice"
    assert c.get("/api/leads/stats", headers=v).json["by_resolution"] == {"benign_true_positive": 1}
    assert c.post(f"/api/leads/{cid}/explode", headers=a).status_code == 400
    assert {u["user"] for u in c.get("/api/users", headers=v).json} >= {"alice", "victor"}


def test_login_page_and_local_users(home):
    write_cfg(home, lambda d: d["auth"].update(mode="local", users={
        "alice": {"password_hash": hash_password("alice-password-1"), "role": "admin"}}))
    from actaeon import config as cmod
    c = create_app(cmod.load_config()).test_client()
    assert b"Sign in" in c.get("/login").data
    assert c.post("/login", data={"username": "alice", "password": "wrong"}).status_code == 401
    r = c.post("/login", data={"username": "alice", "password": "alice-password-1"})
    assert r.status_code == 302
    assert c.get("/api/me").json["user"] == "alice"


def test_users_cli(home, monkeypatch, capsys):
    import io

    from actaeon import cli
    monkeypatch.setattr("sys.stdin", io.StringIO("a-long-password\n"))
    cli.cli_main(["users", "add", "bob", "--role", "viewer", "--password-stdin"])
    cfg = config.load_config()
    assert cfg.auth.users["bob"]["role"] == "viewer" and cfg.auth.users["bob"]["password_hash"].startswith("pbkdf2")
    with pytest.raises(ValueError):
        write_cfg(home, lambda d: d["auth"].update(users={"x": {"password": "plain"}}))
        config.load_config()
