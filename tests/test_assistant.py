import json

import pytest

from actaeon import config
from actaeon.assistant import Conversations, ask
from actaeon.hunt import service
from actaeon.providers.base import LLMResult
from tests.test_hunt import PLAN, Hub, call


class Script:
    def __init__(self, assistant, analyst):
        self.assistant, self.analyst = list(assistant), list(analyst)

    def for_role(self, role):
        outer = self

        class B:
            provider = type("P", (), {"name": "fake"})()
            model = "m"

            def chat(self, messages, **kw):
                sysm = messages[0]["content"]
                if "assistant for a security team" in sysm:
                    r = outer.assistant.pop(0)
                    if callable(r):
                        r = r(messages)
                elif "You plan threat hunts" in sysm:
                    r = PLAN
                elif "sceptical" in sysm:
                    r = {"action": "verify", "result": "unconfirmed", "reason": "n/a"}
                else:
                    r = outer.analyst.pop(0)
                return LLMResult(text=json.dumps(r))
        return B()


def test_assistant_runs_and_stores_a_hunt(home):
    cfg = config.get_config(reload=True)

    def answer(messages):
        last = messages[-1]["content"]
        hid = json.loads(last.split("\n", 2)[2].rsplit("\n", 1)[0])["id"]
        return {"action": "answer", "text": f"Found activity, see hunt {hid}.", "hunts": [hid, "nope"], "cases": [999]}
    llm = Script([{"action": "search_records", "query": "203.0.113.66"},
                  {"action": "start_hunt", "hypothesis": "A host contacted 203.0.113.66 in the last 7 days."},
                  answer],
                 [call(index="e", time_from="now-7d", query="a"), call(index="e", time_from="now-6d", query="b"),
                  call("lookup", value="203.0.113.66"),
                  {"action": "verdict", "outcome": "threat", "confidence": 70, "summary": "contacted",
                   "findings": [{"claim": "WS07 contacted it", "evidence": ["E2", "E3"]}]}])
    r = ask(cfg, "did anything talk to 203.0.113.66?", user="alice", llm=llm, hub=Hub(results={"search": '{"total": 3}'}))
    assert len(r["hunts"]) == 1 and r["cases"]                     # made-up ids dropped, real case linked
    h = service.store_for(cfg).get(r["hunts"][0])
    assert h["origin"] == "ask:alice" and h["actor"] == "alice" and h["status"] == "done"
    assert service.cases_for(cfg).get(r["cases"][0])["hunt_id"] == h["id"]
    conv = Conversations(service.store_for(cfg).path).get(r["conversation_id"])
    assert [m["role"] for m in conv["messages"]] == ["user", "assistant"]
    assert conv["messages"][1]["links"]["hunts"] == r["hunts"]


def test_assistant_hunt_limit_and_errors(home):
    cfg = config.get_config(reload=True)
    many = [{"action": "start_hunt", "hypothesis": f"h{i}"} for i in range(3)] + [{"action": "answer", "text": "ok"}]
    analyst = []
    for _ in range(2):
        analyst += [{"action": "verdict", "outcome": "inconclusive", "summary": "x"}]
    r = ask(cfg, "run lots", user="bob", llm=Script(many, analyst), hub=Hub())
    assert len(r["hunts"]) == 2
    with pytest.raises(ValueError):
        ask(cfg, " ", user="bob", llm=Script([], []), hub=Hub())


def test_assistant_api(home):
    from actaeon.web import create_app
    c = create_app(config.get_config(reload=True)).test_client()
    assert c.post("/api/assistant", json={"message": ""}).status_code == 400
    assert c.get("/api/assistant").json == []
    assert c.get("/api/assistant/99").status_code == 404


def test_demo_assistant(tmp_path, monkeypatch):
    from actaeon import config as cmod
    from actaeon.connectors import hub as hubmod
    from actaeon.demo.setup import init_demo
    from actaeon.providers import get_llm
    init_demo(tmp_path / "d", offline=True)
    monkeypatch.setenv("ACTAEON_HOME", str(tmp_path / "d"))
    monkeypatch.setenv("ACTAEON_CONFIG", str(tmp_path / "d" / "config.yaml"))
    try:
        cfg = cmod.get_config(reload=True)
        hubmod._HUB = None
        get_llm(reload=True)
        r = ask(cfg, "Has anything contacted update-check.example?", user="demo")
        assert r["hunts"] and "DEMO-WS07" in r["answer"]
        assert service.store_for(cfg).get(r["hunts"][0])["origin"] == "ask:demo"
    finally:
        if hubmod._HUB:
            hubmod._HUB.close()
        cmod._CONFIG, hubmod._HUB = None, None
        get_llm(reload=True)
