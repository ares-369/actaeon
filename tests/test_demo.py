import json

from actaeon.bridges.demo import DemoBridge
from actaeon.demo.data import C2_IP, LABEL, events


def test_every_event_is_labelled_and_uses_doc_ranges():
    ev = events()
    assert ev and all(e["sample"] == LABEL for e in ev)
    blob = json.dumps(ev)
    assert "10.0." not in blob and "192.168." not in blob
    for e in ev:
        ip = (e.get("destination") or {}).get("ip")
        if ip:
            assert ip.startswith(("203.0.113.", "198.51.100.")), ip


def test_demo_queries():
    b = DemoBridge()
    base = {"index": "demo-events", "time_from": "now-7d"}
    assert b.count({**base, "query": "process.name:powershell.exe AND process.parent.name:winword.exe"})["count"] == 1
    assert b.count({**base, "query": f"destination.ip:{C2_IP}"})["count"] >= 40
    assert b.count({**base, "query": "process.command_line:*-enc* AND NOT host.name:DEMO-ADM01"})["count"] == 1
    assert b.count({**base, "query": "(host.name:DEMO-WS07 OR host.name:DEMO-ADM01) AND process.name:powershell.exe"})["count"] == 57
    assert b.count({**base, "query": '"update-check.example"'})["count"] >= 40
    r = b.top_values({**base, "field": "process.parent.name", "query": "process.name:powershell.exe", "rare": True})
    assert r["buckets"][0]["value"] == "winword.exe"
    assert b.search({**base, "size": 5})["returned"] == 5


def test_demo_guards():
    import pytest

    from actaeon.bridges.server import ToolInputError
    b = DemoBridge()
    with pytest.raises(ToolInputError):
        b.search({"index": "other", "time_from": "now-1d"})
    with pytest.raises(ToolInputError):
        b.search({"index": "demo-events", "time_from": "now-90d"})
    with pytest.raises(ToolInputError):
        b.search({"index": "demo-events", "time_from": "now-1d", "query": "(a OR b"})


def test_offline_demo_end_to_end(tmp_path, monkeypatch, capsys):
    from actaeon import cli
    from actaeon import config as c
    from actaeon.connectors import hub as h
    monkeypatch.delenv("ACTAEON_CONFIG", raising=False)
    try:
        cli.cmd_demo(type("A", (), {"dir": str(tmp_path / "demo"), "offline": True, "run": True, "port": 8611})())
    finally:
        c._CONFIG, h._HUB = None, None
    out = capsys.readouterr().out
    assert "NOT an AI model" in out and "verdict: threat" in out and "[E3]" in out
    assert "were used in this environment (executed)" in out
    from actaeon.hunt import HuntStore
    hunts = HuntStore(tmp_path / "demo" / "data" / "hunts.sqlite").list()
    demo_hunt = next(x for x in hunts if x["origin"] == "demo")
    assert demo_hunt["models"]["analyst"]["provider"] == "demo"
    assert all(f.get("evidence") != [] for f in demo_hunt["verdict"]["findings"])


def test_demo_banner(tmp_path, monkeypatch):
    from actaeon import config as c
    from actaeon.demo.setup import init_demo
    from actaeon.web import create_app
    init_demo(tmp_path / "d", offline=True)
    monkeypatch.setenv("ACTAEON_HOME", str(tmp_path / "d"))
    monkeypatch.setenv("ACTAEON_CONFIG", str(tmp_path / "d" / "config.yaml"))
    try:
        r = create_app(c.load_config()).test_client().get("/")
        assert b"synthetic sample data" in r.data
    finally:
        c._CONFIG = None


def test_demo_query_ranges():
    from actaeon.bridges.demo import _Q, DemoBridge
    flat = DemoBridge().flat

    def n(q):
        m = _Q(q).parse()
        return sum(1 for e in flat if m(e))

    total = n("event.category:network")
    assert total and n("event.category:network AND @timestamp:[now-30d TO now]") == total
    assert n("event.category:network AND @timestamp:{now TO *}") == 0
    assert 0 < n("destination.port:[443 TO 443]") <= total
    assert n("destination.port:{443 TO 443}") == 0
    assert n("NOT destination.port:[443 TO 443] AND event.category:network") == total - n("destination.port:[443 TO 443]")
