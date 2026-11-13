"""Sigma -> connector query language through pySigma (the built-in test backend stands in for a real one)."""
import json

import pytest

pytest.importorskip("sigma")

from actaeon import config
from actaeon.hunt import sigma_convert as sc

RULE = """
title: Office spawns encoded PowerShell
logsource: {category: process_creation, product: windows}
detection:
  sel:
    ParentImage|endswith: '\\\\winword.exe'
    CommandLine|contains: ' -enc '
  condition: sel
"""
PIPE = """
name: lab fields
priority: 20
transformations:
  - type: field_name_mapping
    mapping:
      ParentImage: process.parent.executable
      CommandLine: process.command_line
"""


@pytest.fixture
def plugins(monkeypatch):
    from sigma.backends.test import TextQueryTestBackend
    from sigma.plugins import InstalledSigmaPlugins
    p = InstalledSigmaPlugins()
    p.register_backend("text", TextQueryTestBackend)
    monkeypatch.setattr(sc, "_plugins", lambda: p)
    return p


def test_convert_and_pipeline_file(plugins, tmp_path):
    assert sc.available()["backends"] == ["text"]
    q = sc.convert(RULE, backend="text")
    assert q[0].startswith("ParentImage endswith") and 'CommandLine contains " -enc "' in q[0]
    f = tmp_path / "pipe.yml"
    f.write_text(PIPE)
    q = sc.convert(RULE, backend="text", pipelines=[str(f)])
    assert "process.parent.executable" in q[0] and "process.command_line" in q[0]


def test_convert_errors(plugins):
    with pytest.raises(sc.SigmaConvertError, match="no pySigma backend"):
        sc.convert(RULE, backend="nope")
    with pytest.raises(sc.SigmaConvertError):
        sc.convert("title: x\n", backend="text")
    with pytest.raises(sc.SigmaConvertError):
        sc.convert(RULE, backend="text", pipelines=["/does/not/exist.yml"])


def test_not_installed(monkeypatch):
    monkeypatch.setattr(sc, "_plugins", lambda: None)
    assert sc.available()["installed"] is False
    with pytest.raises(sc.SigmaConvertError, match="not installed"):
        sc.convert(RULE, backend="text")


def test_spec_validation():
    from actaeon.connectors.spec import parse_connectors
    base = {"name": "logs", "roles": ["log_search"], "transport": "stdio", "command": "true"}
    assert parse_connectors([{**base, "sigma": {"backend": "text"}}])
    for bad in ({"pipelines": []}, {"backend": "text", "pipelines": "x"}, "text"):
        with pytest.raises(ValueError):
            parse_connectors([{**base, "sigma": bad}])


class CountHub:
    def __init__(self):
        self.calls = []

    def tools(self, name):
        return [{"name": "count", "allowed": True, "inputSchema": {"properties": {
            "index": {}, "query": {}, "time_from": {}, "time_to": {}}}}]

    def call(self, conn, tool, args, **kw):
        self.calls.append((conn, tool, args))
        return {"content": '<<UNTRUSTED-DATA a>>\n{"count": 3}\n<<END-UNTRUSTED-DATA a>>', "is_error": False}


def test_draft_converts_and_backtests(plugins):
    from actaeon.hunt.detection import draft
    from tests.test_chat import Scripted
    h = {"id": "h1", "hypothesis": "office spawns encoded powershell", "outcome": "threat",
         "verdict": {"attack": ["T1059.001"], "findings": [{"claim": "x", "evidence": ["E2"]}]},
         "steps": [{"n": 2, "kind": "call", "ok": True, "connector": "logs", "tool": "search",
                    "arguments": {"index": "events-*", "query": "process.name:powershell.exe"},
                    "result": '{"total": 4}'}]}
    llm = Scripted([{"sigma": RULE, "notes": "n"}])
    hub = CountHub()
    d = draft(llm, h, sigma_targets=[{"connector": "logs", "backend": "text", "pipelines": [], "format": "default",
                                      "backtest": True}], hub=hub)
    assert d["valid"], d
    assert d["converted"][0]["queries"][0].startswith("ParentImage endswith")
    assert d["converted"][0]["backtest"] == {"days": 14, "matches": 3, "index": "events-*"}
    assert hub.calls[0][2]["index"] == "events-*" and "time_from" in hub.calls[0][2]
    bad = draft(Scripted([{"sigma": RULE}]), h, sigma_targets=[{"connector": "logs", "backend": "nope", "pipelines": [],
                                        "format": "default", "backtest": False}])
    assert "no pySigma backend" in bad["converted"][0]["error"]


def test_api(plugins, home):
    raw = (home / "config.yaml").read_text().replace(
        "connectors: []", "connectors:\n  - {name: logs, roles: [log_search], transport: stdio, command: 'true', "
                          "sigma: {backend: text}}\n", 1)
    (home / "config.yaml").write_text(raw)
    from actaeon.web import create_app
    c = create_app(config.get_config(reload=True)).test_client()
    assert c.get("/api/sigma/backends").json["backends"] == ["text"]
    r = c.post("/api/sigma/convert", json={"sigma": RULE})
    assert r.status_code == 200 and r.json["converted"][0]["connector"] == "logs"
    assert "status: experimental" in r.json["sigma"]
    assert c.post("/api/sigma/convert", json={"sigma": "a: [b"}).status_code == 400
    assert json.dumps(r.json).count("ParentImage") >= 1
