import json

from actaeon.hunt.sweep import Sweep
from actaeon.hunt.triage import classify, classify_event, events_from
from actaeon.intel import IntelStore
from actaeon.providers.base import LLMResult


def wrap(obj):
    return f"<<UNTRUSTED-DATA a>>\n{json.dumps(obj)}\n<<END-UNTRUSTED-DATA a>>"


def test_classify_events():
    assert classify_event({"event.category": "network", "event.action": "connection", "destination.ip": "x"}) == "executed"
    assert classify_event({"event.category": "network", "event.action": "deny", "destination.ip": "x"}) == "blocked"
    assert classify_event({"event.action": "file_quarantined", "file.hash": "x"}) == "blocked"
    assert classify_event({"event.category": "authentication", "event.outcome": "failure", "source.ip": "x"}) == "blocked"
    assert classify_event({"email.subject": "hi", "email.body": "see hxxp://x"}) == "passive"
    assert classify_event({"event.category": "process", "process.name": "a.exe"}) == "executed"
    assert classify_event({"message": "something"}) == "unknown"


def test_classify_overall():
    ev = [{"email.subject": "s"}, {"event.action": "blocked"}, {"process.name": "p", "event.action": "process_start"}]
    assert classify(ev)["state"] == "executed"
    assert classify(ev[:2])["state"] == "blocked"
    assert classify([])["state"] == "unknown"


def test_events_from():
    assert events_from(wrap({"hits": [{"a": {"b": 1}}]})) == [{"a.b": "1"}]
    assert events_from("not json") == []


class StateHub:
    """Each indicator returns its own kind of events."""
    EVENTS = {"203.0.113.1": [{"event": {"category": "network", "action": "connection"}, "destination": {"ip": "x"}}],
              "203.0.113.2": [{"event": {"category": "network", "action": "deny"}, "destination": {"ip": "y"}}],
              "evil.example": [{"email": {"subject": "invoice", "body": "evil.example"}}],
              "odd.example": [{"message": "odd.example"}]}

    def __init__(self):
        self.calls = []

    def tools_for_role(self, role):
        if role != "log_search":
            return []
        return [{"connector": "logs", "name": "search", "inputSchema": {"type": "object", "properties": {
            "index": {"type": "string"}, "query": {"type": "string"}, "time_from": {"type": "string"}}}}]

    def call(self, connector, tool, args, actor="", hunt_id="", **kw):
        self.calls.append(args["query"])
        hits = [e for v, evs in self.EVENTS.items() if f'"{v}"' in args["query"] for e in evs]
        return {"content": wrap({"total": len(hits), "hits": hits}), "is_error": False}


def sweep(tmp_path, values, **settings):
    intel = IntelStore(tmp_path / "i.sqlite")
    for v in values:
        intel.add(v, confidence=80)
    from actaeon.hunt import HuntStore
    t = {"connector": "logs", "tool": "search", "arguments": {"index": "e", "query": "{values}", "time_from": "now-7d"}}
    return Sweep(StateHub(), intel, HuntStore(tmp_path / "h.sqlite"), {"targets": [t], **settings}, **settings.pop("kw", {}))


def test_sweep_threat_only_when_executed(tmp_path):
    r = sweep(tmp_path, ["203.0.113.1", "203.0.113.2", "evil.example"]).run()
    v = r["verdict"]
    assert v["outcome"] == "threat"
    assert v["sweep"]["triage"] == {"203.0.113.1": "executed", "203.0.113.2": "blocked", "evil.example": "passive"}
    assert any("was USED" in f["claim"] for f in v["findings"])


def test_sweep_all_blocked_or_passive_is_benign(tmp_path):
    r = sweep(tmp_path, ["203.0.113.2", "evil.example"]).run()
    assert r["verdict"]["outcome"] == "telemetry_found_benign" and not r["verdict"]["needs_review"]


def test_sweep_model_second_look(tmp_path):
    class LLM:
        def for_role(self, role):
            class B:
                provider = type("P", (), {"name": "fake"})()
                model = "m"

                def chat(self, messages, **kw):
                    assert "UNTRUSTED-DATA" in messages[1]["content"]
                    return LLMResult(text='{"state": "passive", "reason": "only a log message"}')
            return B()
    intel = IntelStore(tmp_path / "i.sqlite")
    intel.add("odd.example", confidence=80)
    from actaeon.hunt import HuntStore
    t = {"connector": "logs", "tool": "search", "arguments": {"index": "e", "query": "{values}", "time_from": "now-7d"}}
    r = Sweep(StateHub(), intel, HuntStore(tmp_path / "h.sqlite"), {"targets": [t], "triage": "model"}, llm=LLM()).run()
    v = r["verdict"]
    assert v["sweep"]["triage"] == {"odd.example": "passive"} and "only a log message" in v["findings"][0]["claim"]
    assert v["outcome"] == "telemetry_found_benign"


def test_demo_spray_ip_is_blocked(tmp_path):
    from actaeon.bridges.demo import DemoBridge
    from actaeon.demo.data import SPRAY_IP
    out = DemoBridge().search({"index": "demo-events", "query": f'"{SPRAY_IP}"', "time_from": "now-7d"})
    assert classify(events_from(wrap(out)))["state"] == "blocked"
