"""Entities across hunts: extraction from cited evidence, recurrence, visibility, context."""
import json

from actaeon import access, config
from actaeon.hunt import service
from actaeon.hunt.entities import EntityStore, extract


def _hunt(st, outcome, host, *, cited=True, needs_review=False, restricted=None, claim_extra=""):
    hid = st.create(f"hunt on {host}")
    events = {"hits": [{"@timestamp": "2026-11-14T10:00:00Z", "host": {"name": host}, "user": {"name": "jdoe"},
                        "process": {"name": "powershell.exe"}, "destination": {"ip": "203.0.113.66"}}]}
    st.add_step(hid, 2, "call", connector="logs", tool="search", ok=True,
                result="<<UNTRUSTED-DATA a>>\n" + json.dumps(events) + "\n<<END-UNTRUSTED-DATA a>>")
    st.add_step(hid, 3, "call", connector="logs", tool="search", ok=True,
                result="<<UNTRUSTED-DATA b>>\n" + json.dumps({"hits": [{"@timestamp": "2026-11-14T10:00:00Z",
                                                                         "host": {"name": "uncited-host"}}]})
                + "\n<<END-UNTRUSTED-DATA b>>")
    v = {"outcome": outcome, "findings": [{"claim": f"{host} ran encoded PowerShell {claim_extra}",
                                           "evidence": ["E2"] if cited else []}]}
    if needs_review:
        v["needs_review"] = True
    st.update(hid, status="done", outcome=outcome, verdict=json.dumps(v))
    for r in restricted or []:
        st.add_restricted(hid, r)
    return st.get(hid)


def test_extract_only_cited(home):
    st = service.store_for(config.get_config(reload=True))
    e = extract(_hunt(st, "threat", "WS07", claim_extra="contacting evil.example"))
    assert set(e["host"]) == {"WS07"} and "uncited-host" not in e["host"]
    assert set(e["user"]) == {"jdoe"} and "203.0.113.66" in e["ip"] and "evil.example" in e["domain"]
    assert e["host"]["WS07"] == {"E2"}


def test_recurring_and_history(home):
    cfg = config.get_config(reload=True)
    st, es = service.store_for(cfg), service.entities_for(cfg)
    for outcome, review in (("telemetry_found_benign", False), ("inconclusive", False), ("no_results", True)):
        es.index_hunt(_hunt(st, outcome, "WS07", needs_review=review))
    es.index_hunt(_hunt(st, "threat", "WS99"))
    rows = {(r["type"], r["value"]): r for r in es.summary(cfg)}
    assert rows[("host", "WS07")]["hunts"] == 3 and rows[("host", "WS07")]["recurring"]
    assert not rows[("host", "WS99")]["recurring"]
    assert [r["value"] for r in es.summary(cfg, recurring_only=True, type_="host")] == ["WS07"]
    assert len(es.history("host", "ws07")) == 3                     # case-insensitive
    assert "recurring" in es.context_for(cfg, "Did WS07 beacon out again?")
    assert es.context_for(cfg, "nothing known here") == ""


def test_restricted_sightings_hidden(home):
    cfg = config.get_config(reload=True)
    st, es = service.store_for(cfg), service.entities_for(cfg)
    es.index_hunt(_hunt(st, "threat", "CFO-LAPTOP", restricted=["mail"]))
    tier1 = access.Access(user="ann", role="operator", connectors=frozenset({"logs"}))
    assert access.run_as(tier1, es.history, "host", "CFO-LAPTOP") == []
    assert es.history("host", "CFO-LAPTOP")


def test_api_and_cli(home, capsys):
    cfg = config.get_config(reload=True)
    st = service.store_for(cfg)
    service.send_outputs(cfg, _hunt(st, "threat", "WS07"))         # indexing happens where leads open
    from actaeon.web import create_app
    c = create_app(cfg).test_client()
    assert any(r["value"] == "WS07" for r in c.get("/api/entities?type=host").json)
    assert c.get("/api/entities/host/WS07").json[0]["outcome"] == "threat"
    assert c.get("/api/entities/host/nope").status_code == 404
    import pytest

    from actaeon import cli
    with pytest.raises(SystemExit):
        cli.cli_main(["entities", "--type", "host"])
    assert "WS07" in capsys.readouterr().out


def test_offline_demo_records_entities(tmp_path, monkeypatch):
    from actaeon import cli
    from actaeon import config as c
    from actaeon.connectors import hub as h
    monkeypatch.delenv("ACTAEON_CONFIG", raising=False)
    try:
        cli.cmd_demo(type("A", (), {"dir": str(tmp_path / "demo"), "offline": True, "run": True, "port": 8611})())
    finally:
        c._CONFIG, h._HUB = None, None
    es = EntityStore(tmp_path / "demo" / "data" / "hunts.sqlite")
    hosts = {r["value"] for r in es.summary(None, type_="host")}
    assert "DEMO-WS07" in hosts and "DEMO-ADM01" not in hosts       # the benign look-alike is not in a finding
