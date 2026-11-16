"""Web API, roles, the alert webhook, MCP, the offline demo and the benchmark."""

import re
from pathlib import Path

import pytest

from tests.conftest import write_cfg

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def demo(tmp_path, monkeypatch):
    """An offline demo home (scripted provider, sample connectors, live demo response tools)."""
    for v in ("ACTAEON_CONFIG", "ACTAEON_BIND_HOST", "ACTAEON_BIND_PORT", "ACTAEON_AUTH_PASSWORD"):
        monkeypatch.delenv(v, raising=False)
    from actaeon.demo.setup import init_demo
    init_demo(tmp_path, offline=True)
    monkeypatch.setenv("ACTAEON_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    from actaeon import config
    from actaeon.connectors import hub
    from actaeon.providers import get_llm
    config._CONFIG, hub._HUB = None, None
    get_llm(reload=True)
    write_cfg(tmp_path, lambda d: d["soc"].update(auto=False))
    yield tmp_path
    if hub._HUB:
        hub._HUB.close()
    config._CONFIG, hub._HUB = None, None


def app_client(cfg_reload=True):
    from actaeon import config
    from actaeon.web import create_app
    app = create_app(config.get_config(reload=cfg_reload))
    app.config["TESTING"] = True
    return app.test_client()


def test_full_flow_through_the_api(demo):
    from actaeon.demo.data import alerts
    from actaeon.soc.service import store_for, triage_case
    c = app_client()
    r = c.post("/api/alerts?source=demo", json=alerts())
    assert r.status_code == 200 and r.json["new"] == 6 and len(r.json["cases_opened"]) == 5
    assert c.post("/api/alerts", json={"alerts": alerts()[:1]}).json["duplicates"] == 0   # other source: new id
    from actaeon import config
    cfg = config.get_config()
    for case in store_for(cfg).cases(status="new"):
        triage_case(cfg, case["id"], manual=True)
    cases = c.get("/api/cases").json
    chain = next(x for x in cases if "DEMO-WS07" in x["title"])
    d = c.get(f"/api/cases/{chain['id']}").json
    assert d["verdict"] == "true_positive" and d["graph"]["nodes"] and d["timeline"] and d["chain"]
    assert {a["name"] for a in d["actions"]} == {"isolate_host", "block_ip", "disable_user"}
    iso = next(a for a in d["actions"] if a["name"] == "isolate_host")
    r = c.post(f"/api/actions/{iso['id']}/approve", json={})
    assert r.json["status"] == "executed" and "isolated DEMO-WS07" in r.json["result"]
    assert c.post(f"/api/actions/{iso['id']}/approve", json={}).status_code == 409
    assert c.post(f"/api/actions/{iso['id']}/undo", json={}).json["status"] == "undone"
    md = c.get(f"/api/cases/{chain['id']}/report.md")
    assert md.status_code == 200 and b"True positive" in md.data
    assert c.post(f"/api/cases/{chain['id']}/close", json={"verdict": "true_positive"}).json["status"] == "closed"
    assert c.get("/api/soc/metrics").json["agreement"]["agree"] == 1
    audit = c.get("/api/audit").json
    assert any(r["status"] == "action" and r["tool"] == "isolate_host" for r in audit)
    assert c.get("/api/audit/verify").json["ok"] is True


def test_injection_case_waits_for_a_person(demo):
    from actaeon import config
    from actaeon.demo.data import alerts
    from actaeon.soc.service import store_for, triage_case
    c = app_client()
    c.post("/api/alerts", json=[a for a in alerts() if a["id"] == "demo-a6"])
    cfg = config.get_config()
    case = store_for(cfg).cases()[0]
    out = triage_case(cfg, case["id"], manual=True)
    assert out["status"] == "needs_analyst" and out["report"]["injection"]


def test_bad_alert_payloads(demo):
    c = app_client()
    assert c.post("/api/alerts", data="nope", content_type="application/json").status_code == 400
    assert c.post("/api/alerts", json=[1, "x"]).json["invalid"] == 2


def test_security_headers_and_index(demo):
    r = app_client().get("/")
    assert r.status_code == 200 and "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"


def _basic(home, users):
    from actaeon.auth import hash_password
    write_cfg(home, lambda d: d["auth"].update(mode="basic", users={
        u: {"password_hash": hash_password("pw-" + u, iters=1000), "role": r} for u, r in users.items()}))


def _auth(u):
    import base64
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:pw-{u}".encode()).decode()}


def test_roles(demo):
    _basic(demo, {"vic": "viewer", "op": "operator", "adm": "admin"})
    c = app_client()
    assert c.get("/api/cases").status_code == 401
    assert c.get("/api/cases", headers=_auth("vic")).status_code == 200
    assert c.post("/api/alerts", json={"id": "1"}, headers=_auth("vic")).status_code == 403
    assert c.post("/api/actions/1/approve", json={}, headers=_auth("vic")).status_code == 403
    assert c.post("/api/alerts", json={"id": "1"}, headers=_auth("op")).status_code == 200
    assert c.get("/api/audit", headers=_auth("op")).status_code == 403
    assert c.post("/api/settings/llm", json={"roles": {}}, headers=_auth("op")).status_code == 403
    assert c.get("/api/audit", headers=_auth("adm")).status_code == 200


def test_alert_webhook_token(demo, monkeypatch):
    _basic(demo, {"vic": "viewer"})
    write_cfg(demo, lambda d: d["soc"]["intake"].update(webhook_token_env="HD_TOKEN"))
    monkeypatch.setenv("HD_TOKEN", "s3cret-token")
    c = app_client()
    hdr = {"Authorization": "Bearer s3cret-token"}
    assert c.post("/api/alerts", json={"id": "w1"}, headers=hdr).status_code == 200
    assert c.post("/api/alerts", json={"id": "w1"}, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/api/cases", headers=hdr).status_code == 401       # the token only sends alerts


def test_mcp_server(demo):
    from actaeon import config
    from actaeon.jobs import JobManager
    from actaeon.mcp_server import build
    cfg = config.get_config(reload=True)
    jobs = JobManager.from_config(cfg)
    srv = build(cfg, jobs, role_of=lambda: "viewer")
    names = {t["name"] for t in srv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]}
    assert {"list_cases", "get_case", "submit_alerts", "triage_case"} <= names
    assert not any("approve" in n for n in names)        # approvals are for people only
    r = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "submit_alerts", "arguments": {"alerts": [{"id": "m1"}]}}})
    assert r["result"]["isError"] and "operator" in r["result"]["content"][0]["text"]
    op = build(cfg, jobs, role_of=lambda: "operator")
    r = op.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": "submit_alerts", "arguments": {"alerts": [{"id": "m1", "title": "t"}]}}})
    assert not r["result"].get("isError")
    r = op.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "list_cases", "arguments": {}}})
    assert "m1" not in r["result"]["content"][0]["text"] and '"title"' in r["result"]["content"][0]["text"]


def test_offline_bench_passes(tmp_path, monkeypatch):
    monkeypatch.delenv("ACTAEON_CONFIG", raising=False)
    from actaeon.soc.bench import run_bench
    res = run_bench(tmp_path / "b", offline=True)
    assert res["score"]["passed"] == res["score"]["total"] == 5
    assert res["score"]["tp_found"] == 2 and res["score"]["false_alarms"] == 0


def test_case_can_start_a_hunt(demo):
    from actaeon.demo.data import alerts
    c = app_client()
    c.post("/api/alerts", json=[a for a in alerts() if a["id"] == "demo-a4"])
    cid = c.get("/api/cases").json[0]["id"]
    r = c.post(f"/api/cases/{cid}/hunt", json={})
    assert r.status_code == 200 and r.json["hunt_id"]
    h = c.get(f"/api/hunts/{r.json['hunt_id']}").json
    assert h["origin"] == f"case:{cid}" and cid in h["hypothesis"]
    assert any("Started hunt" in n["text"] for n in c.get(f"/api/cases/{cid}").json["notes"])


def test_triage_ui_never_parses_html_or_sets_style_attributes():
    js = (ROOT / "actaeon/static/soc.js").read_text()
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(", js)
    assert "style:" not in js          # inline style attributes are blocked by the content security policy
    html = (ROOT / "actaeon/templates/index.html").read_text()
    assert html.index("/static/soc.js") < html.index("/static/app.js")     # pages exist before the router runs
