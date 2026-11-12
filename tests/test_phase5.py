import json
from datetime import datetime, timedelta, timezone

import pytest

from actaeon import config
from actaeon.hunt import HuntStore, service
from actaeon.hunt.library import Library, replay, starters
from actaeon.hunt.memory import HuntMemory
from actaeon.hunt.signals import hits
from actaeon.hunt.sweep import Sweep, auto_targets
from actaeon.intel import IntelStore
from tests.test_hunt import LLM, PLAN, Hub, call


def wrap(obj):
    return f"<<UNTRUSTED-DATA a source=x>>\n{json.dumps(obj)}\n<<END-UNTRUSTED-DATA a>>"


class CountHub(Hub):
    """Returns hits for queries that mention any value in ``bad``."""

    def __init__(self, bad=(), **kw):
        super().__init__(**kw)
        self.bad = set(bad)

    def call(self, connector, tool, args, actor="", hunt_id=""):
        self.calls.append((connector, tool, args))
        if tool in self.fail:
            from actaeon.connectors.hub import ToolCallError
            raise ToolCallError("down")
        q = str(args.get("query", ""))
        n = sum(1 for b in self.bad if b in q)
        return {"content": wrap({"total": n, "hits": [{"x": 1}] * n}), "is_error": False}


# ---- signals ----
@pytest.mark.parametrize("obj,n", [({"total": 3}, 3), ({"total": {"value": 7}}, 7), ({"count": 0}, 0),
                                   ({"found": True}, 1), ({"matches": [1, 2]}, 2), ([1, 2, 3], 3),
                                   ({"buckets": []}, 0), ({"other": 1}, None)])
def test_hits(obj, n):
    assert hits(wrap(obj)) == n


def test_hits_not_json():
    assert hits(wrap("plain")) is None and hits("call failed") is None


# ---- library + replay ----
def finished_hunt(tmp_path, hub=None, db="h.sqlite"):
    from actaeon.hunt import HuntEngine
    eng = HuntEngine(LLM(PLAN, [call(index="e", time_from="now-1d", query="cmd"),
                                {"action": "verdict", "outcome": "no_results", "summary": "clean",
                                 "attack": ["T1059.001"]}]),
                     hub or CountHub(), HuntStore(tmp_path / db))
    return eng.run("encoded powershell")


def test_save_and_replay(tmp_path):
    h = finished_hunt(tmp_path)
    lib = Library(tmp_path / "h.sqlite")
    s = lib.save_from_hunt(h, name="enc ps", interval_minutes=60)
    assert s["calls"][0]["arguments"]["time_from"] == "now-1d" and not s["warnings"]
    assert s["attack"] == ["T1059.001"]
    store = HuntStore(tmp_path / "h.sqlite")
    r = replay(lib.get(s["id"]), CountHub(), store, lib)
    assert r["outcome"] == "no_results" and r["origin"] == f"replay:{s['id']}"
    assert "automatic replay" in r["verdict"]["checks"][0]
    r = replay(lib.get(s["id"]), CountHub(bad={"cmd"}), store, lib)
    assert r["outcome"] == "inconclusive" and r["verdict"]["needs_review"] and r["verdict"]["replay"]["hits"] == 1
    assert r["verdict"]["findings"][0]["evidence"] == ["E1"]
    assert lib.get(s["id"])["last_hits"] == 1
    r = replay(lib.get(s["id"]), CountHub(fail={"search"}), store, lib)
    assert r["outcome"] == "logs_missing"


def test_replay_revalidates(tmp_path):
    h = finished_hunt(tmp_path)
    lib = Library(tmp_path / "h.sqlite")
    s = lib.save_from_hunt(h)
    s["calls"][0]["arguments"]["query"] = "* | delete"
    hub = CountHub()
    r = replay(s, hub, HuntStore(tmp_path / "h.sqlite"), lib)
    assert hub.calls == [] and r["steps"][0]["kind"] == "blocked" and r["outcome"] == "logs_missing"


def test_save_warns_on_fixed_time(tmp_path):
    h = finished_hunt(tmp_path)
    h["steps"][1]["arguments"]["time_from"] = "2026-01-01T00:00:00Z"
    assert Library(tmp_path / "h.sqlite").save_from_hunt(h)["warnings"]


def test_save_needs_calls(tmp_path):
    with pytest.raises(ValueError):
        Library(tmp_path / "h.sqlite").save_from_hunt({"id": "x", "hypothesis": "h", "steps": []})


def test_due(tmp_path):
    h = finished_hunt(tmp_path)
    lib = Library(tmp_path / "h.sqlite")
    s = lib.save_from_hunt(h, interval_minutes=30)
    lib.save_from_hunt(h, interval_minutes=0)
    now = datetime.now(timezone.utc)
    assert [x["id"] for x in lib.due(now)] == [s["id"]]
    lib.mark_run(s["id"], 0, [], "x")
    assert lib.due(now) == [] and lib.due(now + timedelta(minutes=31))
    lib.set(s["id"], enabled=False)
    assert lib.due(now + timedelta(days=1)) == []


def test_starters_are_generic():
    items = starters()
    assert len(items) >= 12
    import re
    for s in items:
        assert s["name"] and s["hypothesis"] and s["attack"]
        assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in s["attack"])


# ---- memory ----
def test_memory(tmp_path):
    m = HuntMemory(tmp_path / "h.sqlite")
    m.remember({"id": "a", "created": "2026-11-01", "status": "done", "hypothesis": "encoded powershell from word",
                "verdict": {"outcome": "telemetry_found_benign", "summary": "deploy tool", "findings": [],
                            "attack": ["T1059.001"]}})
    m.remember({"id": "b", "created": "2026-11-02", "status": "done", "hypothesis": "dns tunnelling",
                "verdict": {"outcome": "no_results", "summary": "none", "findings": []}})
    n = m.add_note("The patch tool runs encoded powershell nightly on build servers", tags=["benign"])
    ctx = m.context("encoded powershell launched by office")
    assert "patch tool" in ctx and "deploy tool" in ctx and "dns tunnelling" not in ctx
    assert m.retire_note(n["id"]) and "patch tool" not in m.context("encoded powershell")
    assert m.context("") == "" and m.related("the and for") == {"hunts": [], "notes": []}
    with pytest.raises(ValueError):
        m.add_note("  ")


def test_memory_feeds_next_hunt(home):
    cfg = config.get_config(reload=True)
    service.memory_for(cfg).add_note("Encoded powershell on build servers is the patch tool", tags=["benign"])
    llm = LLM(PLAN, [{"action": "verdict", "outcome": "inconclusive", "summary": "x"}])
    service.run_hunt(cfg, "encoded powershell from office", llm=llm, hub=Hub())
    first_user = llm.roles["analyst"].seen[0][1]["content"]
    assert "patch tool" in first_user
    assert service.memory_for(cfg).related("encoded powershell")["hunts"]


# ---- sweeps ----
def test_sweep_ledger_and_attribution(tmp_path):
    intel = IntelStore(tmp_path / "i.sqlite")
    for v in ("203.0.113.1", "203.0.113.2", "evil.example", "CVE-2024-1234", "T1059"):
        intel.add(v, confidence=80)
    target = {"connector": "logs", "tool": "search",
              "arguments": {"index": "e", "query": "{values}", "time_from": "{lookback}"}}
    hub = CountHub(bad={"evil.example"})
    sw = Sweep(hub, intel, HuntStore(tmp_path / "h.sqlite"), {"targets": [target], "batch": 2})
    r = sw.run()
    v = r["verdict"]
    assert v["outcome"] == "threat" and v["needs_review"] and v["sweep"]["indicators"] == 3
    assert len(v["findings"]) == 1 and "evil.example" in v["findings"][0]["claim"]
    assert hub.calls[0][2]["query"].count(" OR ") == 1
    assert hub.calls[0][2]["time_from"] == "now-7d"
    assert not any("CVE" in c[2]["query"] for c in hub.calls)
    # second run: nothing changed -> nothing searched
    hub.calls.clear()
    r2 = sw.run()
    assert hub.calls == [] and r2["outcome"] == "inconclusive"
    intel.add("198.51.100.9")
    sw.run()
    assert [c[2]["query"] for c in hub.calls] == ['"198.51.100.9"']


def test_sweep_failures_keep_ledger_position(tmp_path):
    intel = IntelStore(tmp_path / "i.sqlite")
    intel.add("203.0.113.1", confidence=80)
    target = {"connector": "logs", "tool": "search",
              "arguments": {"index": "e", "query": "{values}", "time_from": "{lookback}"}}
    sw = Sweep(CountHub(fail={"search"}), intel, HuntStore(tmp_path / "h.sqlite"), {"targets": [target]})
    assert sw.run()["outcome"] == "logs_missing"
    hub = CountHub()
    Sweep(hub, intel, HuntStore(tmp_path / "h.sqlite"), {"targets": [target]}).run()
    assert hub.calls  # retried because the failed sweep did not advance the ledger


def test_sweep_quotes_values(tmp_path):
    intel = IntelStore(tmp_path / "i.sqlite")
    intel.add("https://x.example/a\\b", confidence=80)
    hub = CountHub()
    t = {"connector": "logs", "tool": "search", "arguments": {"index": "e", "query": "{values}", "time_from": "now-1d"}}
    Sweep(hub, intel, HuntStore(tmp_path / "h.sqlite"), {"targets": [t], "batch": 1}).run()
    assert any("a\\\\b" in c[2]["query"] for c in hub.calls)


def test_auto_targets():
    from actaeon.connectors import parse_connectors
    specs = {s.name: s for s in parse_connectors([
        {"name": "logs", "roles": ["log_search"], "transport": "stdio", "command": "actaeon",
         "args": ["bridge", "search-index", "--url", "x", "--index", "a-*", "--index", "b-*"]},
        {"name": "other", "roles": ["intel"], "transport": "stdio", "command": "x"}])}
    t = auto_targets(specs)
    assert len(t) == 1 and t[0]["arguments"]["index"] == "a-*,b-*"


# ---- API + scheduler ----
def test_phase5_api(home):
    from actaeon.web import create_app
    cfg = config.get_config(reload=True)
    app = create_app(cfg)
    c = app.test_client()
    h = finished_hunt(home / "data", db="hunts.sqlite")
    lib = c.get("/api/library").json
    assert lib["saved"] == [] and len(lib["starters"]) >= 12
    r = c.post("/api/library", json={"hunt_id": h["id"], "name": "x", "interval_minutes": 15}).json
    assert r["interval_minutes"] == 15
    assert c.post(f"/api/library/{r['id']}", json={"enabled": False}).json["enabled"] is False
    assert c.post("/api/library", json={"hunt_id": "nope"}).status_code == 404
    assert c.post(f"/api/library/{r['id']}/delete").json["ok"]
    assert c.post("/api/memory/notes", json={"text": "known admin tool", "tags": ["benign"]}).json["id"]
    assert c.get("/api/memory/notes").json[0]["text"] == "known admin tool"
    assert c.post("/api/memory/notes", json={"text": ""}).status_code == 400
    assert c.post("/api/hunts/advisory/999").status_code == 404


def test_advisory_hunt_text(home):
    cfg = config.get_config(reload=True)
    aid = service.intel_for(cfg).add_advisory("Campaign X", "uses hxxp://bad[.]example T1105 CVE-2024-1")["advisory_id"]
    hyp, ctx = service.advisory_hunt(cfg, aid)
    assert "Campaign X" in hyp and "T1105" in hyp
    assert "bad.example" in ctx and "UNTRUSTED-DATA" in ctx


def test_scheduler_tick(home):
    from actaeon.hunt.scheduler import Scheduler
    from actaeon.jobs import JobManager
    cfg = config.get_config(reload=True)
    h = finished_hunt(home / "data", db="hunts.sqlite")
    service.library_for(cfg).save_from_hunt(h, interval_minutes=10)
    jobs = JobManager(home / "data" / "j.sqlite")
    sch = Scheduler(cfg, jobs)
    assert len(sch.tick()) == 1
    assert sch.tick() == []   # marked as run, not due again yet
