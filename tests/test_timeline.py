import json

from actaeon.hunt.timeline import build, describe


def step(n, hits):
    return {"n": n, "kind": "call", "ok": True, "connector": "logs", "tool": "search", "ms": 5, "note": "",
            "why": "", "arguments": {}, "ts": "t",
            "result": f"<<UNTRUSTED-DATA a>>\n{json.dumps({'hits': hits})}\n<<END-UNTRUSTED-DATA a>>"}


def test_timeline_orders_and_labels():
    h = {"steps": [
        step(3, [{"@timestamp": "2026-11-10T10:05:00Z", "host": {"name": "WS07"}, "event": {"category": "network",
                  "action": "connection"}, "destination": {"ip": "203.0.113.66"}, "process": {"name": "powershell.exe"}}]),
        step(2, [{"@timestamp": "2026-11-10T10:00:00Z", "host": {"name": "WS07"}, "user": {"name": "c.okafor"},
                  "event": {"category": "process", "action": "start"},
                  "process": {"name": "powershell.exe", "parent": {"name": "winword.exe"}, "command_line": "-enc AAA"}},
                 {"message": "no time here"}]),
        step(4, [{"timestamp": "1762768800", "hostname": "DC01", "event_type": "logon failure", "src_ip": "198.51.100.200"}]),
        {"n": 5, "kind": "call", "ok": False, "connector": "logs", "tool": "search", "result": "call failed"}]}
    t = build(h)
    assert [e["evidence"] for e in t["events"]] == ["E4", "E2", "E3"]      # E4's epoch time is a year earlier
    by_ev = {e["evidence"]: e for e in t["events"]}
    assert by_ev["E2"]["parent"] == "winword.exe" and by_ev["E2"]["user"] == "c.okafor" and by_ev["E2"]["state"] == "executed"
    assert by_ev["E3"]["destination"] == "203.0.113.66"
    assert by_ev["E4"]["host"] == "DC01" and by_ev["E4"]["source"] == "198.51.100.200"
    assert t["no_time"] == 1 and t["entities"]["host"][0] == {"value": "WS07", "count": 2}
    assert "winword.exe -> powershell.exe" in describe(by_ev["E2"])
    times = [e["time"] for e in t["events"]]
    assert times == sorted(times)


def test_timeline_in_report():
    from actaeon.hunt.report import markdown
    h = {"id": "x", "hypothesis": "h", "created": "c", "status": "done", "origin": "manual",
         "verdict": {"outcome": "threat", "confidence": 50, "summary": "s"},
         "steps": [step(2, [{"@timestamp": "2026-11-10T10:00:00Z", "host": {"name": "WS07"},
                             "event": {"action": "start"}, "process": {"name": "a.exe"}}])]}
    md = markdown(h)
    assert "## Timeline (1 events" in md and "| WS07 |" in md
