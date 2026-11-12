import base64
import time

from actaeon import config
from actaeon.connectors import ConnectorHub, parse_connectors
from actaeon.connectors.audit import AuditLog
from actaeon.mcp_server import build
from actaeon.web import create_app
from tests.conftest import write_cfg
from tests.test_hunt import LLM, PLAN, Hub, call


def rpc(c, method, params=None, headers=None, rid=1):
    return c.post("/mcp", json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}},
                  headers=headers or {})


def tool(c, name, args=None, headers=None):
    r = rpc(c, "tools/call", {"name": name, "arguments": args or {}}, headers)
    return r.status_code, r.json["result"]


def test_http_mcp_basic_flow(home):
    c = create_app(config.get_config(reload=True)).test_client()
    assert rpc(c, "initialize").json["result"]["serverInfo"]["name"] == "actaeon"
    names = {t["name"] for t in rpc(c, "tools/list").json["result"]["tools"]}
    assert {"start_hunt", "get_hunt", "list_hunts", "hunt_report", "lookup_intel", "coverage", "decode_command"} <= names
    _, r = tool(c, "decode_command", {"text": "i`e`x"})
    assert r["structuredContent"]["final"] == "iex"
    _, r = tool(c, "add_intel", {"values": ["1.2.3.4"]})
    assert r["isError"] and "allow_intel_writes" in r["content"][0]["text"]
    _, r = tool(c, "get_hunt", {"id": "nope"})
    assert r["isError"]
    assert c.get("/mcp").status_code == 405
    assert c.post("/mcp", data="x", content_type="text/plain").status_code == 400
    assert c.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}).status_code == 202


def test_mcp_start_and_get_hunt(home):
    cfg = config.get_config(reload=True)
    from actaeon.jobs import JobManager
    jobs = JobManager(home / "data" / "j.sqlite")
    srv = build(cfg, jobs, llm=LLM(PLAN, [call(index="e", time_from="now-1d"),
                                          {"action": "verdict", "outcome": "no_results", "summary": "ok"}]), hub=Hub())
    r = srv.handle({"id": 1, "method": "tools/call", "params": {"name": "start_hunt",
                                                                "arguments": {"hypothesis": "test via mcp"}}})
    hid = r["result"]["structuredContent"]["hunt_id"]
    for _ in range(100):
        h = srv.handle({"id": 2, "method": "tools/call", "params": {"name": "get_hunt",
                                                                    "arguments": {"id": hid, "include_results": True}}})
        st = h["result"]["structuredContent"]
        if st["status"] == "done":
            break
        time.sleep(0.05)
    assert st["outcome"] == "no_results" and st["origin"] == "mcp"
    assert any("result" in s for s in st["steps"])
    rep = srv.handle({"id": 3, "method": "tools/call", "params": {"name": "hunt_report", "arguments": {"id": hid}}})
    assert "# Hunt report" in rep["result"]["content"][0]["text"]


def test_mcp_token_and_roles(home, monkeypatch):
    monkeypatch.setenv("MCP_TOK", "s3cret-token")
    monkeypatch.setenv("ACTAEON_AUTH_PASSWORD", "pw")
    write_cfg(home, lambda d: (d["auth"].update(mode="basic", default_role="viewer"),
                               d.update(mcp={"token_env": "MCP_TOK", "token_role": "viewer", "allow_intel_writes": True})))
    c = create_app(config.load_config()).test_client()
    assert rpc(c, "tools/list").status_code == 401                                      # no credentials
    assert rpc(c, "tools/list", headers={"Authorization": "Bearer wrong"}).status_code == 401
    ok = {"Authorization": "Bearer s3cret-token"}
    assert rpc(c, "tools/list", headers=ok).status_code == 200
    _, r = tool(c, "start_hunt", {"hypothesis": "x"}, ok)
    assert r["isError"] and "operator" in r["content"][0]["text"]                       # viewer token
    _, r = tool(c, "lookup_intel", {"value": "1.2.3.4"}, ok)
    assert not r.get("isError")
    basic = {"Authorization": "Basic " + base64.b64encode(b"actaeon:pw").decode()}       # viewer via login
    _, r = tool(c, "add_intel", {"values": ["1.2.3.4"]}, basic)
    assert r["isError"] and "operator" in r["content"][0]["text"]
    # the token does not open the rest of the API
    assert c.get("/api/hunts", headers=ok).status_code == 401


def test_mcp_operator_can_add_intel(home, monkeypatch):
    monkeypatch.setenv("MCP_TOK", "t")
    write_cfg(home, lambda d: d.update(mcp={"token_env": "MCP_TOK", "allow_intel_writes": True}))
    c = create_app(config.load_config()).test_client()
    _, r = tool(c, "add_intel", {"text": "C2 hxxp://bad[.]example", "tags": ["mcp"]},
                {"Authorization": "Bearer t"})
    assert r["structuredContent"]["new"] >= 1


def test_expose_filter(home):
    write_cfg(home, lambda d: d.update(mcp={"expose": ["list_hunts", "get_hunt"]}))
    c = create_app(config.load_config()).test_client()
    assert {t["name"] for t in rpc(c, "tools/list").json["result"]["tools"]} == {"list_hunts", "get_hunt"}


def test_stdio_mcp_server_through_hub(home, tmp_path, monkeypatch):
    """Actaeon's own connector hub talks to `actaeon mcp` over stdio."""
    spec = parse_connectors([{"name": "actaeon-self", "roles": ["analysis"], "transport": "stdio",
                              "command": "actaeon", "args": ["mcp"], "timeout_sec": 20,
                              "env": {"ACTAEON_HOME": str(home)}, "rate_per_min": 6000}])[0]
    hub = ConnectorHub([spec], AuditLog(tmp_path / "a.sqlite"), sleep=lambda s: None)
    try:
        r = hub.test("actaeon-self")
        assert r["ok"] and r["tools"] >= 10, r
        allowed = {t["name"] for t in hub.tools("actaeon-self") if t["allowed"]}
        assert "list_hunts" in allowed and "start_hunt" not in allowed   # hub policy sees it as state-changing
        out = hub.call("actaeon-self", "decode_command", {"text": "i`e`x"})
        assert '"final": "iex"' in out["content"]
    finally:
        hub.close()
