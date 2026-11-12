import json
import time

import pytest

from actaeon.connectors.hub import ToolCallError
from actaeon.hunt import HuntEngine, HuntLimits, HuntStore
from actaeon.hunt.jsonparse import first_object
from actaeon.hunt.validator import ValidationError, validate_call
from actaeon.providers.base import LLMResult

SEARCH = {"connector": "logs", "name": "search", "description": "search events",
          "inputSchema": {"type": "object", "properties": {"index": {"type": "string"}, "query": {"type": "string"},
                                                           "time_from": {"type": "string"}, "size": {"type": "integer"}},
                          "required": ["index"]}}
LOOKUP = {"connector": "local-intel", "name": "lookup", "description": "intel lookup",
          "inputSchema": {"type": "object", "properties": {"value": {"type": "string"}}, "required": ["value"]}}


class Bound:
    def __init__(self, script, name):
        self.script, self.name = script, name
        self.provider = type("P", (), {"name": "fake"})()
        self.model = "scripted"
        self.seen = []

    def chat(self, messages, **kw):
        self.seen.append(messages)
        item = self.script.pop(0) if self.script else {"action": "verdict", "outcome": "inconclusive"}
        if isinstance(item, Exception):
            return LLMResult(text="", error=str(item))
        return LLMResult(text=item if isinstance(item, str) else json.dumps(item))


class LLM:
    def __init__(self, plan, actions):
        self.roles = {"planner": Bound([plan], "planner"), "analyst": Bound(list(actions), "analyst")}

    def for_role(self, role):
        return self.roles[role]


class Hub:
    def __init__(self, tools=None, results=None, fail=()):
        self.tools = tools or {"log_search": [SEARCH], "intel": [LOOKUP]}
        self.results = results or {}
        self.fail = set(fail)
        self.calls = []

    def tools_for_role(self, role):
        return [dict(t) for t in self.tools.get(role, [])]

    def call(self, connector, tool, args, actor="", hunt_id=""):
        self.calls.append((connector, tool, args))
        if tool in self.fail:
            raise ToolCallError("connection refused")
        return {"content": f"<<UNTRUSTED-DATA x>>{self.results.get(tool, '{}')}<<END-UNTRUSTED-DATA x>>",
                "is_error": False}


PLAN = {"summary": "look for encoded powershell", "attack": ["T1059.001", "bogus"],
        "steps": [{"role": "log_search", "goal": "find -enc"}, {"role": "identity", "goal": "who ran it"}],
        "data_needed": ["log_search"]}


def call(tool="search", **args):
    conn = "local-intel" if tool == "lookup" else "logs"
    return {"action": "call", "thought": "t", "connector": conn, "tool": tool, "arguments": args}


def run(tmp_path, actions, hub=None, limits=None, **kw):
    llm = LLM(PLAN, actions)
    eng = HuntEngine(llm, hub or Hub(), HuntStore(tmp_path / "h.sqlite"), limits or HuntLimits(max_steps=5), **kw)
    return eng.run("encoded powershell launched from office"), llm


# ---- validator ----
def test_validator_caps_and_requires_time():
    args, notes = validate_call(SEARCH, {"index": "e", "time_from": "now-1d", "size": 99999}, max_results=200)
    assert args["size"] == 200 and notes
    with pytest.raises(ValidationError, match="time range"):
        validate_call(SEARCH, {"index": "e"})
    with pytest.raises(ValidationError, match="required"):
        validate_call(SEARCH, {"time_from": "now-1d"})
    with pytest.raises(ValidationError, match="type"):
        validate_call(SEARCH, {"index": 5, "time_from": "now-1d"})
    assert validate_call(SEARCH, {"index": "e", "time_from": "x", "size": "10"})[0]["size"] == 10


@pytest.mark.parametrize("q", [
    "* | delete", "DELETE FROM events", "drop table x", "_delete_by_query", "x | outputlookup bad.csv",
    "foo\x00bar", "eval(os.system('x'))", "INSERT INTO t VALUES (1)", "a" * 5000,
])
def test_validator_refuses_writes(q):
    with pytest.raises(ValidationError):
        validate_call(SEARCH, {"index": "e", "time_from": "now-1d", "query": q})


def test_validator_allows_normal_queries():
    for q in ("process.name:powershell.exe AND cmdline:*-enc*", "event.action:deleted",
              "user.name:admin AND NOT host:dc01", "message:\"update available\""):
        validate_call(SEARCH, {"index": "e", "time_from": "now-1d", "query": q})


def test_first_object():
    assert first_object('sure!\n```json\n{"a": {"b": "}"}}\n```') == {"a": {"b": "}"}}
    assert first_object('x {"a":1} y') == {"a": 1}
    assert first_object("no json") is None


# ---- engine ----
def test_threat_with_cited_evidence(tmp_path):
    h, llm = run(tmp_path, [
        call(index="e", query="cmdline:*-enc*", time_from="now-24h"),
        call("lookup", value="203.0.113.9"),
        call(index="e", query="host:A", time_from="now-24h"),
        {"action": "verdict", "outcome": "threat", "confidence": 85, "summary": "found it",
         "findings": [{"claim": "encoded powershell on host A", "evidence": ["E2", "E3", "E4"]},
                      {"claim": "made-up claim", "evidence": ["E99"]}],
         "attack": ["T1059.001"], "next_steps": ["isolate"]},
    ], hub=Hub(results={"search": '{"total": 1}'}))
    v = h["verdict"]
    assert h["status"] == "done" and v["outcome"] == "threat"
    assert v["findings"] == [{"claim": "encoded powershell on host A", "evidence": ["E2", "E3", "E4"]}]
    assert v["confidence"] == 85
    assert v["unsupported_claims"][0]["claim"] == "made-up claim"
    assert any("E99" in c for c in v["checks"])
    assert h["plan"]["attack"] == ["T1059.001"] and h["plan"]["missing_roles"] == ["identity"]
    kinds = [s["kind"] for s in h["steps"]]
    assert kinds == ["plan", "call", "call", "call", "verdict"]
    # the result was fed back to the model as untrusted data with its evidence id
    last_prompt = llm.roles["analyst"].seen[-1][-1]["content"]
    assert last_prompt.startswith("E4 result of logs.search") and "UNTRUSTED-DATA" in last_prompt


def test_threat_without_evidence_is_downgraded(tmp_path):
    h, _ = run(tmp_path, [{"action": "verdict", "outcome": "threat", "confidence": 99, "summary": "trust me",
                           "findings": [{"claim": "bad", "evidence": []}]}])
    assert h["verdict"]["outcome"] == "inconclusive" and h["verdict"]["confidence"] <= 40


def test_no_results_needs_a_successful_search(tmp_path):
    h, _ = run(tmp_path, [call(index="e", time_from="now-1d"),
                          {"action": "verdict", "outcome": "no_results", "confidence": 70, "summary": "clean"}],
               hub=Hub(fail={"search"}))
    assert h["verdict"]["outcome"] == "logs_missing"
    assert h["steps"][1]["ok"] is False and "connection refused" in h["steps"][1]["result"]


def test_intel_only_is_not_a_data_search(tmp_path):
    h, _ = run(tmp_path, [call("lookup", value="1.2.3.4"),
                          {"action": "verdict", "outcome": "no_results", "summary": "nothing"}])
    assert h["verdict"]["outcome"] == "logs_missing"


def test_no_results_ok_after_search(tmp_path):
    h, _ = run(tmp_path, [call(index="e", time_from="now-1d"),
                          {"action": "verdict", "outcome": "no_results", "confidence": 70, "summary": "clean"}])
    assert h["verdict"]["outcome"] == "no_results" and h["verdict"]["confidence"] == 70


def test_validator_and_unknown_tool_are_blocked_not_run(tmp_path):
    hub = Hub()
    h, llm = run(tmp_path, [
        call(index="e"),                                   # no time range
        call(index="e", time_from="now-1d", query="* | delete"),
        {"action": "call", "connector": "edr", "tool": "isolate_host", "arguments": {}},
        {"action": "verdict", "outcome": "inconclusive", "summary": "x"},
    ], hub=hub)
    assert hub.calls == []
    assert [s["kind"] for s in h["steps"]].count("blocked") == 3
    msgs = [m["content"] for m in llm.roles["analyst"].seen[-1] if m["role"] == "user"]
    assert any("refused by the validator" in m for m in msgs) and any("not an available tool" in m for m in msgs)


def test_repeat_calls_not_rerun(tmp_path):
    hub = Hub()
    c = call(index="e", time_from="now-1d")
    _h, _ = run(tmp_path, [c, c, {"action": "verdict", "outcome": "no_results", "summary": "x"}], hub=hub)
    assert len(hub.calls) == 1


def test_step_limit(tmp_path):
    hub = Hub()
    acts = [call(index="e", time_from=f"now-{i}h") for i in range(1, 10)]
    h, _ = run(tmp_path, acts, hub=hub, limits=HuntLimits(max_steps=3))
    assert len(hub.calls) == 3 and h["verdict"]["outcome"] == "inconclusive"
    assert "limit" in h["verdict"]["summary"].lower()


def test_parse_failures_end_hunt(tmp_path):
    h, _ = run(tmp_path, ["hello", "still not json", "nope"])
    assert h["verdict"]["outcome"] == "inconclusive" and "valid actions" in h["verdict"]["summary"]


def test_stop_and_time_limit(tmp_path):
    h, _ = run(tmp_path, [call(index="e", time_from="now-1d")], checkpoint=lambda: False)
    assert h["status"] == "stopped"
    t = [0.0]

    def clock():
        t[0] += 1000
        return t[0]
    h, _ = run(tmp_path, [call(index="e", time_from="now-1d")], clock=clock)
    assert h["status"] == "stopped" and "time limit" in h["error"]


def test_planner_failure_is_not_fatal(tmp_path):
    llm = LLM(RuntimeError("model down"), [{"action": "verdict", "outcome": "inconclusive", "summary": "x"}])
    llm.roles["planner"].script = [RuntimeError("model down")]
    h = HuntEngine(llm, Hub(), HuntStore(tmp_path / "h.sqlite")).run("x")
    assert h["status"] == "done" and h["plan"] is None
    assert h["steps"][0]["kind"] == "plan" and h["steps"][0]["ok"] is False


def test_unknown_outcome(tmp_path):
    h, _ = run(tmp_path, [{"action": "verdict", "outcome": "pwned", "summary": "x"}])
    assert h["verdict"]["outcome"] == "inconclusive"


def test_old_results_trimmed(tmp_path):
    big = "x" * 5000
    hub = Hub(results={"search": big})
    acts = [call(index="e", time_from=f"now-{i}h") for i in range(1, 7)]
    acts.append({"action": "verdict", "outcome": "no_results", "summary": "x"})
    _, llm = run(tmp_path, acts, hub=hub, limits=HuntLimits(max_steps=10))
    prompt = llm.roles["analyst"].seen[-1]
    trimmed = [m for m in prompt if "older result trimmed" in m["content"]]
    assert len(trimmed) == 2


# ---- service / API ----
def test_api_hunt_lifecycle(home):
    from actaeon import config
    from actaeon.hunt import service
    from actaeon.web import create_app
    cfg = config.get_config(reload=True)
    app = create_app(cfg)
    jobs = app.extensions["actaeon_jobs"]
    hid = service.start_hunt(jobs, cfg, "test hypothesis", llm=LLM(PLAN, [
        call(index="e", time_from="now-1d"), {"action": "verdict", "outcome": "no_results", "summary": "ok"}]),
        hub=Hub())
    c = app.test_client()
    for _ in range(100):
        h = c.get(f"/api/hunts/{hid}").json
        if h["status"] in ("done", "error", "stopped"):
            break
        time.sleep(0.05)
    assert h["status"] == "done" and h["outcome"] == "no_results"
    assert c.get("/api/hunts").json[0]["id"] == hid
    assert c.post("/api/hunts", json={"hypothesis": ""}).status_code == 400
    assert c.post(f"/api/hunts/{hid}/explode").status_code == 400
    assert c.get("/api/hunts/nope").status_code == 404


def test_viewer_cannot_start_hunt(home, monkeypatch):
    import base64

    from actaeon import config
    from actaeon.web import create_app
    from tests.conftest import write_cfg
    write_cfg(home, lambda d: d["auth"].update(mode="basic", default_role="viewer"))
    monkeypatch.setenv("ACTAEON_AUTH_PASSWORD", "pw")
    h = {"Authorization": "Basic " + base64.b64encode(b"actaeon:pw").decode()}
    c = create_app(config.load_config()).test_client()
    assert c.post("/api/hunts", json={"hypothesis": "x"}, headers=h).status_code == 403


def test_orphans_marked(tmp_path):
    s = HuntStore(tmp_path / "h.sqlite")
    hid = s.create("x")
    s.update(hid, status="running")
    s.mark_orphans()
    assert s.get(hid)["status"] == "stopped"


def test_resolve_tool_slips():
    from actaeon.hunt.engine import resolve_tool
    idx = {("logs", "search"): {"role": "log_search"}, ("local-intel", "lookup"): {"role": "intel"},
           ("other", "search"): {"role": "network"}}
    assert resolve_tool(idx, {"connector": "log_search", "tool": "logs.search"}) == ("logs", "search")
    assert resolve_tool(idx, {"connector": "x", "tool": "lookup"}) == ("local-intel", "lookup")
    assert resolve_tool(idx, {"connector": "log_search", "tool": "search"}) == ("logs", "search")
    assert resolve_tool(idx, {"connector": "zzz", "tool": "search"}) == ("zzz", "search")


def test_blocked_calls_use_budget(tmp_path):
    hub = Hub()
    bad = {"action": "call", "connector": "nope", "tool": "nothing", "arguments": {}}
    h, _ = run(tmp_path, [bad] * 50, hub=hub, limits=HuntLimits(max_steps=4))
    assert h["status"] == "done" and h["verdict"]["outcome"] == "inconclusive"
    assert [s["kind"] for s in h["steps"]].count("blocked") == 4


def test_star_in_argument_names(tmp_path):
    hub = Hub()
    _h, _ = run(tmp_path, [{"action": "call", "connector": "logs", "tool": "search",
                           "arguments": {"index*": "e", "time_from*": "now-1d"}},
                          {"action": "verdict", "outcome": "no_results", "summary": "x"}], hub=hub)
    assert hub.calls and hub.calls[0][2]["index"] == "e"


GET_FIELDS = {"connector": "logs", "name": "get_fields", "description": "fields",
              "inputSchema": {"type": "object", "properties": {"index": {"type": "string"}}, "required": ["index"]}}


def test_unknown_fields_refused_after_automatic_get_fields(tmp_path):
    hub = Hub(tools={"log_search": [SEARCH, GET_FIELDS]},
              results={"get_fields": '{"fields": {"process.name": "keyword", "process.parent.name": "keyword"}}'})
    h, llm = run(tmp_path, [
        call(index="e", time_from="now-7d", query="app_name:Office AND process_name:powershell.exe"),
        call(index="e", time_from="now-7d", query="process.parent.name:winword.exe AND process.name:powershell.exe"),
        {"action": "verdict", "outcome": "no_results", "summary": "x"},
    ], hub=hub)
    tools_called = [c[1] for c in hub.calls]
    assert tools_called == ["get_fields", "search"]          # fields fetched once, bad query never sent
    blocked = [s for s in h["steps"] if s["kind"] == "blocked"]
    assert "app_name" in blocked[0]["note"] and "process.name" in blocked[0]["note"]
    msgs = [m["content"] for m in llm.roles["analyst"].seen[-1] if m["role"] == "user"]
    assert any("fetched automatically" in m for m in msgs)


def test_truncated_field_list_does_not_block(tmp_path):
    hub = Hub(tools={"log_search": [SEARCH, GET_FIELDS]},
              results={"get_fields": '{"fields": {"a": "keyword"}, "truncated": true}'})
    run(tmp_path, [call(index="e", time_from="now-7d", query="zzz:1"),
                   {"action": "verdict", "outcome": "no_results", "summary": "x"}], hub=hub)
    assert [c[1] for c in hub.calls] == ["get_fields", "search"]


def test_model_get_fields_is_reused(tmp_path):
    hub = Hub(tools={"log_search": [SEARCH, GET_FIELDS]},
              results={"get_fields": '{"fields": {"process.name": "keyword"}}'})
    run(tmp_path, [{"action": "call", "connector": "logs", "tool": "get_fields", "arguments": {"index": "e"}},
                   call(index="e", time_from="now-7d", query="process.name:x"),
                   {"action": "verdict", "outcome": "no_results", "summary": "x"}], hub=hub)
    assert [c[1] for c in hub.calls] == ["get_fields", "search"]


def test_threat_nudged_to_corroborate_once(tmp_path):
    threat = {"action": "verdict", "outcome": "threat", "confidence": 95, "summary": "bad",
              "findings": [{"claim": "encoded powershell", "evidence": ["E2"]}]}
    h, llm = run(tmp_path, [call(index="e", time_from="now-1d", query="x"), threat, threat])
    notes = [s["note"] for s in h["steps"] if s["kind"] == "note"]
    assert any("asked to corroborate" in n and "intel" in n and "pivot" in n for n in notes)
    asked = [m["content"] for m in llm.roles["analyst"].seen[-1] if m["role"] == "user"]
    assert any("Before a threat verdict" in m for m in asked)
    v = h["verdict"]
    assert v["outcome"] == "threat" and v["confidence"] == 60      # second verdict accepted, capped
    assert any("only one piece of evidence" in c for c in v["checks"])


def test_threat_cap_one_kind_of_query(tmp_path):
    h, _ = run(tmp_path, [call(index="e", time_from="now-1d", query="a"), call(index="e", time_from="now-2d", query="b"),
                          call("lookup", value="1.2.3.4"),
                          {"action": "verdict", "outcome": "threat", "confidence": 99, "summary": "x",
                           "findings": [{"claim": "c", "evidence": ["E2", "E3"]}]}])
    assert h["verdict"]["confidence"] == 75
