import pytest

from actaeon import config
from actaeon.server import startup_security_check
from actaeon.web import create_app
from tests.conftest import write_cfg


@pytest.fixture
def client(home):
    return create_app(config.get_config(reload=True)).test_client()


def test_index_and_health(client):
    assert client.get("/healthz").json == {"ok": True}
    r = client.get("/")
    assert r.status_code == 200 and b"mdi-bow-arrow" in r.data


def test_status(client):
    j = client.get("/api/status").json
    assert j["auth_mode"] == "none" and "analyst" in j["roles"]


def test_settings_llm_flow(client):
    assert "ollama" in client.get("/api/settings/llm").json["providers"]
    body = {"roles": {"reporter": {"provider": "gemini", "model": ""}}}
    assert client.post("/api/settings/llm", json={**body, "preview": True}).json["changed"]
    assert client.post("/api/settings/llm", json=body).json["roles"]["reporter"]["provider"] == "gemini"
    assert client.post("/api/settings/llm", json={"roles": {"x": {}}}).status_code == 400


def test_jobs_api(client):
    assert client.get("/api/jobs").json == []
    assert client.get("/api/jobs/missing").status_code == 404
    assert client.post("/api/jobs/missing/explode").status_code == 400


def test_basic_auth_required(home, monkeypatch):
    write_cfg(home, lambda d: d["auth"].update(mode="basic"))
    monkeypatch.setenv("ACTAEON_AUTH_PASSWORD", "pw")
    c = create_app(config.load_config()).test_client()
    assert c.get("/api/status").status_code == 401
    import base64
    tok = base64.b64encode(b"actaeon:pw").decode()
    assert c.get("/api/status", headers={"Authorization": f"Basic {tok}"}).status_code == 200


def test_viewer_cannot_change_models(home, monkeypatch):
    write_cfg(home, lambda d: d["auth"].update(mode="basic", default_role="viewer"))
    monkeypatch.setenv("ACTAEON_AUTH_PASSWORD", "pw")
    c = create_app(config.load_config()).test_client()
    import base64
    h = {"Authorization": "Basic " + base64.b64encode(b"actaeon:pw").decode()}
    assert c.post("/api/settings/llm", json={"roles": {}}, headers=h).status_code == 403


def test_refuses_open_network_bind(home):
    write_cfg(home, lambda d: d["actaeon"].update(bind_host="0.0.0.0"))
    errors, _ = startup_security_check(config.load_config())
    assert errors


def test_proxy_needs_trusted_ips(home):
    write_cfg(home, lambda d: d["auth"].update(mode="proxy"))
    errors, _ = startup_security_check(config.load_config())
    assert errors
