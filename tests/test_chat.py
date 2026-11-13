import json

import pytest

from actaeon import config
from actaeon.hunt import HuntEngine, service
from actaeon.hunt.chat import ChatLog, ask
from tests.test_hunt import LLM, PLAN, Hub, call


class Scripted:
    def __init__(self, replies):
        self.replies, self.seen = list(replies), []

    def for_role(self, role):
        outer = self

        class B:
            provider = type("P", (), {"name": "fake"})()
            model = "m"

            def chat(self, messages, **kw):
                outer.seen.append(messages)
                from actaeon.providers.base import LLMResult
                r = outer.replies.pop(0) if outer.replies else {"action": "answer", "text": "done"}
                return LLMResult(text=json.dumps(r))
        return B()


def finished(cfg, hub):
    eng = HuntEngine(LLM(PLAN, [call(index="e", time_from="now-1d", query="host:A"),
                                {"action": "verdict", "outcome": "no_results", "summary": "nothing on A"}]),
                     hub, service.store_for(cfg))
    return eng.run("hunt on host A")


def test_chat_answers_and_follows_up(home):
    cfg = config.get_config(reload=True)
    hub = Hub(results={"search": '{"total": 1}'})
    h = finished(cfg, hub)
    llm = Scripted([
        {"action": "call", "connector": "logs", "tool": "search", "arguments": {"index": "e", "time_from": "now-1d",
                                                                                 "query": "host:B"}, "thought": "other host"},
        {"action": "answer", "text": "Host B also shows activity (E4), unlike A (E2). E77 too.",
         "evidence": ["E2", "E4", "E77"]}])
    r = ask(cfg, h["id"], "check host B as well", author="ana", llm=llm, hub=hub)
    assert r["calls"] == 1 and r["evidence"] == ["E2", "E4"] and "E77 removed" in r["answer"]
    after = service.store_for(cfg).get(h["id"])
    new = [s for s in after["steps"] if s["note"] == "from chat"]
    assert new and new[0]["arguments"]["query"] == "host:B" and new[0]["why"].startswith("chat:")
    msgs = ChatLog(service.store_for(cfg).path).list(h["id"])
    assert [m["role"] for m in msgs] == ["analyst", "actaeon"] and msgs[0]["author"] == "ana"
    first_prompt = llm.seen[0][1]["content"]
    assert "Hunt record" in first_prompt and "UNTRUSTED-DATA" in first_prompt and "check host B" in first_prompt


def test_chat_refuses_writes_and_limits_calls(home):
    cfg = config.get_config(reload=True)
    hub = Hub()
    h = finished(cfg, hub)
    hub.calls.clear()
    bad = {"action": "call", "connector": "logs", "tool": "search",
           "arguments": {"index": "e", "time_from": "now-1d", "query": "* | delete"}}
    r = ask(cfg, h["id"], "delete it", llm=Scripted([bad] * 10), hub=hub)
    assert hub.calls == [] and r["calls"] == 5


def test_chat_guards(home):
    cfg = config.get_config(reload=True)
    with pytest.raises(LookupError):
        ask(cfg, "nope", "hi", llm=Scripted([]), hub=Hub())
    h = finished(cfg, Hub())
    with pytest.raises(ValueError):
        ask(cfg, h["id"], "  ", llm=Scripted([]), hub=Hub())


def test_chat_api(home):
    from actaeon.web import create_app
    cfg = config.get_config(reload=True)
    h = finished(cfg, Hub())
    c = create_app(cfg).test_client()
    assert c.get(f"/api/hunts/{h['id']}/chat").json == []
    assert c.post(f"/api/hunts/{h['id']}/chat", json={"message": ""}).status_code == 400
    assert c.post("/api/hunts/zzz/chat", json={"message": "x"}).status_code == 404


def test_tool_loop_last_turn_gets_one_more_chance(home):
    from actaeon.hunt.toolloop import run_loop
    cfg = config.get_config(reload=True)
    hub = Hub(results={"search": '{"total": 1}'})
    h = finished(cfg, hub)
    c = {"action": "call", "connector": "logs", "tool": "search",
         "arguments": {"index": "e", "time_from": "now-1d", "query": "host:B"}}
    llm = Scripted([c, dict(c, arguments={**c["arguments"], "query": "host:C"}),
                    {"action": "answer", "text": "final"}])
    final, _made, calls = run_loop(llm=llm, hub=hub, store=service.store_for(cfg), hid=h["id"], system="s", user="u",
                                   final_action="answer", max_calls=1, max_results=50, actor="t", why_prefix="")
    assert calls == 1 and final == {"action": "answer", "text": "final"}


def test_tool_loop_asks_again_after_invalid_json(home):
    from actaeon.hunt.toolloop import run_loop
    from actaeon.providers.base import LLMResult
    cfg = config.get_config(reload=True)
    hub = Hub(results={"search": '{"total": 1}'})
    h = finished(cfg, hub)
    replies = ['{"action": "call", "tool": "search", "arguments": {"q": 1, "thought": "x"} oops}',
               json.dumps({"action": "answer", "text": "fine"})]

    class L:
        def for_role(self, role):
            class B:
                def chat(self, messages, **kw):
                    return LLMResult(text=replies.pop(0))
            return B()
    final, _m, calls = run_loop(llm=L(), hub=hub, store=service.store_for(cfg), hid=h["id"], system="s", user="u",
                                final_action="answer", max_calls=5, max_results=50, actor="t", why_prefix="")
    assert final == {"action": "answer", "text": "fine"} and calls == 0
