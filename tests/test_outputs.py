import pytest

from actaeon import config
from actaeon.outputs import append_excel, dispatch, events_of, facts, send_email, validate
from tests.conftest import write_cfg

HUNT = {"id": "abc123", "hypothesis": "Office started encoded PowerShell", "origin": "manual", "status": "done",
        "outcome": "threat",
        "verdict": {"outcome": "threat", "confidence": 85, "needs_review": False, "summary": "Found it on WS07",
                    "findings": [{"claim": "WS07 contacted 203.0.113.66", "evidence": ["E3"]}], "attack": ["T1059.001"]},
        "steps": [{"n": 3, "kind": "call", "connector": "logs", "tool": "search", "ok": True,
                   "arguments": {"query": "=cmd"}, "note": "hits=2"}]}


class FakeSMTP:
    sent = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def starttls(self, context=None):
        self.tls = True

    def login(self, u, p):
        self.user = (u, p)

    def send_message(self, msg):
        FakeSMTP.sent.append(msg)


def test_validate():
    validate([{"name": "a", "type": "excel", "path": "x.xlsx"}])
    for bad in ([{"name": "A", "type": "excel", "path": "x"}], [{"name": "a", "type": "sms"}],
                [{"name": "a", "type": "email", "smtp_host": "h"}], [{"name": "a", "type": "excel", "path": "x", "when": ["meh"]}],
                [{"name": "a", "type": "webhook", "url": "u", "token": "plain"}]):
        with pytest.raises(ValueError):
            validate(bad)


def test_events_and_facts():
    assert events_of(HUNT) == {"all", "threat"}
    f = facts(HUNT, "https://actaeon.example")
    assert f["link"] == "https://actaeon.example/#hunt/abc123" and "203.0.113.66" in f["indicators"]
    assert f["severity"] == "high" and f["queries"][0].startswith("E3 logs.search")


def test_email_critical_recipients(monkeypatch):
    FakeSMTP.sent.clear()
    o = {"name": "m", "type": "email", "smtp_host": "mail", "from": "a@x.example", "to": ["soc@x.example"],
         "to_critical": ["lead@x.example"], "username_env": "U", "password_env": "P"}
    send_email(o, facts(HUNT), env={"U": "user", "P": "pw"}, smtp_cls=FakeSMTP)
    msg = FakeSMTP.sent[-1]
    assert "lead@x.example" in msg["To"] and msg["Subject"].startswith("[Actaeon] threat")
    body = msg.get_content()
    assert "WS07 contacted 203.0.113.66 (E3)" in body and "leads for an analyst" in body
    low = dict(HUNT, verdict=dict(HUNT["verdict"], confidence=50))
    send_email(o, facts(low), env={}, smtp_cls=FakeSMTP)
    assert "lead@x.example" not in FakeSMTP.sent[-1]["To"]


def test_excel_appends_rows(tmp_path):
    from openpyxl import load_workbook
    o = {"name": "x", "type": "excel", "path": str(tmp_path / "audit.xlsx")}
    append_excel(o, facts(HUNT))
    append_excel(o, facts(dict(HUNT, id="def456")))
    ws = load_workbook(tmp_path / "audit.xlsx")["Hunts"]
    rows = list(ws.values)
    assert rows[0][0] == "Time (UTC)" and len(rows) == 3 and rows[2][1] == "def456"
    assert "'E3" not in str(rows[1][10]) and str(rows[1][10]).startswith("E3")


def test_dispatch_filters_and_never_raises(home, monkeypatch):
    write_cfg(home, lambda d: d.update(outputs=[
        {"name": "sheet", "type": "excel", "when": ["all"], "path": str(home / "data" / "a.xlsx")},
        {"name": "hook", "type": "webhook", "when": ["needs_review"], "url": "https://hook.example"},
        {"name": "broken", "type": "webhook", "when": ["threat"], "url": "https://down.example"}]))
    cfg = config.load_config()

    class S:
        def post(self, url, **kw):
            raise ConnectionError("down")
    r = dispatch(cfg, HUNT, session=S())
    assert [(x["name"], x["ok"]) for x in r] == [("sheet", True), ("broken", False)]


def test_mcp_tool_output_respects_write_policy(home):
    from actaeon.connectors import ConnectorHub, ToolCallError, parse_connectors
    from actaeon.connectors.audit import AuditLog
    write_cfg(home, lambda d: d.update(outputs=[{"name": "case", "type": "mcp_tool", "when": ["threat"],
                                                 "connector": "cases", "tool": "create_case",
                                                 "arguments": {"title": "{title}", "severity": "{severity}"}}]))
    cfg = config.load_config()

    class FakeHub(ConnectorHub):
        def __init__(self, allow_write):
            spec = parse_connectors([{"name": "cases", "roles": ["asset"], "transport": "stdio", "command": "x",
                                      "allow_write": allow_write, "tools": {"allow": ["create_case"]}}])[0]
            super().__init__([spec], AuditLog(home / "data" / "a.sqlite"))
            self._tools = {"cases": [{"name": "create_case", "allowed": True, "reason": "",
                                      "inputSchema": {}, "annotations": {}}]}
            self.made = []

        def _client(self, name):
            hub = self

            class C:
                def call_tool(self, tool, args):
                    hub.made.append(args)
                    return {"content": [{"type": "text", "text": "case 42"}]}

                def close(self):
                    pass
            return C()
    ok = FakeHub(True)
    r = dispatch(cfg, HUNT, hub=ok)
    assert r[0]["ok"] and ok.made[0] == {"title": "[Actaeon] threat: Office started encoded PowerShell", "severity": "high"}
    blocked = FakeHub(False)
    r = dispatch(cfg, HUNT, hub=blocked)
    assert not r[0]["ok"] and blocked.made == []
    assert ToolCallError


def test_hunt_runs_outputs_and_records_them(home):
    from actaeon.hunt import service
    from tests.test_hunt import LLM, PLAN, Hub, call
    write_cfg(home, lambda d: d.update(outputs=[{"name": "sheet", "type": "excel", "when": ["all"],
                                                 "path": str(home / "data" / "a.xlsx")}]))
    cfg = config.load_config()
    h = service.run_hunt(cfg, "x", llm=LLM(PLAN, [call(index="e", time_from="now-1d"),
                                                  {"action": "verdict", "outcome": "no_results", "summary": "s"}]),
                         hub=Hub())
    out = [s for s in h["steps"] if s["kind"] == "output"]
    assert out and out[0]["tool"] == "sheet" and out[0]["ok"]
    assert (home / "data" / "a.xlsx").exists()


def test_outputs_test_cli(home, capsys):
    from actaeon import cli
    write_cfg(home, lambda d: d.update(outputs=[{"name": "sheet", "type": "excel", "path": str(home / "t.xlsx")}]))
    config.get_config(reload=True)
    cli.cli_main(["outputs", "test", "sheet"])
    assert "OK   sheet" in capsys.readouterr().out
