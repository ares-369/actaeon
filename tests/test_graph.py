"""Investigation graph built from stored results."""
import json

from actaeon import config
from actaeon.hunt import service
from actaeon.hunt.graph import build


def _wrap(o):
    return "<<UNTRUSTED-DATA a>>\n" + json.dumps(o) + "\n<<END-UNTRUSTED-DATA a>>"


def test_build_links_and_cited(home):
    st = service.store_for(config.get_config(reload=True))
    hid = st.create("office spawned powershell")
    ev = {"hits": [{"@timestamp": "2026-11-14T10:00:00Z", "host": {"name": "WS07"}, "user": {"name": "jdoe"},
                    "process": {"name": "powershell.exe", "parent": {"name": "winword.exe"}},
                    "destination": {"domain": "update-check.example"}}]}
    st.add_step(hid, 2, "call", connector="logs", tool="search", ok=True, result=_wrap(ev))
    st.add_step(hid, 3, "call", connector="local-intel", tool="lookup", ok=True,
                arguments={"value": "update-check.example"}, result=_wrap({"value": "update-check.example", "found": True}))
    st.add_step(hid, 4, "call", connector="local-intel", tool="lookup", ok=True,
                arguments={"value": "clean.example"}, result=_wrap({"value": "clean.example", "found": False}))
    st.update(hid, status="done", outcome="threat", verdict=json.dumps(
        {"outcome": "threat", "findings": [{"claim": "x", "evidence": ["E2"]}]}))
    g = build(st.get(hid))
    ids = {n["id"] for n in g["nodes"]}
    assert {"user:jdoe", "host:WS07", "parent:winword.exe", "process:powershell.exe",
            "destination:update-check.example", "intel:intel match: update-check.example"} <= ids
    assert not any("clean.example" in i for i in ids)                 # a lookup that found nothing adds nothing
    pairs = {(e["from"], e["to"]) for e in g["edges"]}
    assert ("user:jdoe", "host:WS07") in pairs and ("parent:winword.exe", "process:powershell.exe") in pairs
    assert ("process:powershell.exe", "destination:update-check.example") in pairs
    assert all(n["cited"] for n in g["nodes"] if n["kind"] != "intel")
    assert any(e["cited"] for e in g["edges"])


def test_graph_api_on_demo(tmp_path, monkeypatch):
    from actaeon import cli
    from actaeon import config as c
    from actaeon.connectors import hub as h
    monkeypatch.delenv("ACTAEON_CONFIG", raising=False)
    try:
        cli.cmd_demo(type("A", (), {"dir": str(tmp_path / "demo"), "offline": True, "run": True, "port": 8611})())
        monkeypatch.setenv("ACTAEON_HOME", str(tmp_path / "demo"))
        monkeypatch.setenv("ACTAEON_CONFIG", str(tmp_path / "demo" / "config.yaml"))
        c._CONFIG, h._HUB = None, None
        from actaeon.web import create_app
        client = create_app(c.load_config()).test_client()
        hunts = client.get("/api/hunts").json
        hid = next(x["id"] for x in (hunts["hunts"] if isinstance(hunts, dict) else hunts) if x["origin"] == "demo")
        g = client.get(f"/api/hunts/{hid}/graph").json
        labels = {n["label"] for n in g["nodes"]}
        assert "DEMO-WS07" in labels and any("powershell" in x.lower() for x in labels)
        assert client.get("/api/hunts/nope/graph").status_code == 404
    finally:
        c._CONFIG, h._HUB = None, None


def test_first_and_last_seen(home):
    st = service.store_for(config.get_config(reload=True))
    hid = st.create("beacon")
    hits = [{"@timestamp": t, "host": {"name": "WS07"}, "destination": {"ip": "203.0.113.66"}}
            for t in ("2026-11-14T10:00:00Z", "2026-11-12T08:30:00Z", "2026-11-13T09:00:00Z")]
    st.add_step(hid, 2, "call", connector="logs", tool="search", ok=True, result=_wrap({"hits": hits}))
    st.add_step(hid, 3, "call", connector="local-intel", tool="lookup", ok=True,
                arguments={"value": "203.0.113.66"}, result=_wrap({"value": "203.0.113.66", "found": True}))
    st.update(hid, status="done", outcome="threat", verdict=json.dumps({"outcome": "threat"}))
    g = build(st.get(hid))
    host = next(n for n in g["nodes"] if n["id"] == "host:WS07")
    assert (host["first"], host["last"]) == ("2026-11-12T08:30:00Z", "2026-11-14T10:00:00Z")
    link = next(e for e in g["edges"] if e["from"] == "host:WS07" and e["to"] == "destination:203.0.113.66")
    assert (link["first"], link["last"]) == ("2026-11-12T08:30:00Z", "2026-11-14T10:00:00Z")
    intel = next(n for n in g["nodes"] if n["kind"] == "intel")
    assert intel["first"] is None                       # an intel lookup is not an event with a time
