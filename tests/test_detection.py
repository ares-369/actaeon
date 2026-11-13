import json

from actaeon.hunt.detection import DetectionStore, check_sigma, draft, native_queries
from actaeon.providers.base import LLMResult

HUNT = {"id": "h1", "hypothesis": "Office started encoded PowerShell", "outcome": "threat",
        "plan": {"attack": ["T1204.002"]},
        "verdict": {"outcome": "threat", "summary": "s", "attack": ["T1059.001"],
                    "findings": [{"claim": "word -> powershell -enc", "evidence": ["E3"]}]},
        "feedback": [{"kind": "benign", "claim": "admin script", "comment": "svc.maint nightly"}],
        "steps": [{"n": 2, "kind": "call", "ok": True, "connector": "logs", "tool": "search",
                   "arguments": {"query": "nothing:here"}, "result": '<<UNTRUSTED-DATA a>>\n{"total": 0}\n<<END-UNTRUSTED-DATA a>>'},
                  {"n": 3, "kind": "call", "ok": True, "connector": "logs", "tool": "search",
                   "arguments": {"query": "process.parent.name:winword.exe AND process.name:powershell.exe"},
                   "result": '<<UNTRUSTED-DATA a>>\n{"total": 1}\n<<END-UNTRUSTED-DATA a>>'}]}

SIGMA = """title: t
logsource: {category: process_creation, product: windows}
detection:
  sel: {Image|endswith: powershell.exe}
  condition: sel
status: stable
level: high
"""


class R:
    def __init__(self, text):
        self.text = text

    def for_role(self, role):
        t = self.text

        class B:
            provider = type("P", (), {"name": "fake"})()
            model = "m"

            def chat(self, messages, **kw):
                assert "svc.maint nightly" in messages[1]["content"]
                return LLMResult(text=t)
        return B()


def test_native_queries_only_those_with_data():
    q = native_queries(HUNT)
    assert [x["evidence"] for x in q] == ["E3"] and q[0]["hits"] == 1


def test_check_sigma_normalises():
    text, problems = check_sigma(SIGMA, ["T1059.001"])
    assert problems == []
    assert "status: experimental" in text and "attack.t1059.001" in text
    assert check_sigma("title: x\n", [])[1] == ["missing logsource", "missing detection"]
    assert "not valid YAML" in check_sigma("a: [", [])[1][0]
    assert "no condition" in check_sigma("title: x\nlogsource: {}\ndetection: {sel: {a: b}}\n", [])[1][0]


def test_draft_with_model():
    d = draft(R(json.dumps({"sigma": SIGMA, "notes": "tune"})), HUNT)
    assert d["valid"] and d["status"] == "draft" and d["attack"] == ["T1059.001", "T1204.002"]
    assert "experimental" in d["sigma"] and d["native"][0]["evidence"] == "E3"


def test_draft_without_working_query_is_flagged():
    h = dict(HUNT, steps=HUNT["steps"][:1], verdict=dict(HUNT["verdict"], findings=[]))
    d = draft(R("not json"), h)
    assert not d["valid"] and any("did not return a rule" in p for p in d["problems"])
    assert any("not grounded" in p for p in d["problems"])


def test_store(tmp_path):
    ds = DetectionStore(tmp_path / "h.sqlite")
    saved = ds.save(draft(None, HUNT))
    assert ds.list("h1")[0]["id"] == saved["id"]


def test_demo_detection_end_to_end(tmp_path, monkeypatch):
    from actaeon import config as c
    from actaeon.demo.setup import DEMO_HYPOTHESIS, init_demo
    from actaeon.web import create_app
    init_demo(tmp_path / "d", offline=True)
    monkeypatch.setenv("ACTAEON_HOME", str(tmp_path / "d"))
    monkeypatch.setenv("ACTAEON_CONFIG", str(tmp_path / "d" / "config.yaml"))
    from actaeon.connectors import hub as hubmod
    from actaeon.providers import get_llm
    try:
        cfg = c.get_config(reload=True)
        hubmod._HUB = None
        get_llm(reload=True)
        from actaeon.hunt import service
        h = service.run_hunt(cfg, DEMO_HYPOTHESIS)
        r = create_app(cfg).test_client().post(f"/api/hunts/{h['id']}/detection").json
        assert r["valid"] and "winword.exe" in r["sigma"] and r["native"]
    finally:
        if hubmod._HUB:
            hubmod._HUB.close()
        c._CONFIG, hubmod._HUB = None, None
        get_llm(reload=True)


def test_backtest_counts_per_day():
    import json as _json

    from actaeon.hunt.detection import backtest

    class Hub:
        def __init__(self):
            self.calls = []

        def tools(self, name):
            return [{"name": "search", "allowed": True}, {"name": "count", "allowed": True}]

        def call(self, conn, tool, args, **kw):
            self.calls.append(args)
            return {"content": _json.dumps({"count": 3 if len(self.calls) == 2 else 0})}
    h = {"id": "h1", "verdict": {"findings": [{"claim": "x", "evidence": ["E2"]}]},
         "steps": [{"kind": "call", "ok": True, "n": 2, "connector": "logs", "tool": "search",
                    "arguments": {"index": "ev", "query": "process.name:x.exe", "time_from": "now-1d"},
                    "result": _json.dumps({"total": 1, "hits": [{}]})}]}
    hub = Hub()
    r = backtest(hub, h, days=7)
    q = r["queries"][0]
    assert len(hub.calls) == 7 and "time_from" in hub.calls[0] and hub.calls[0]["query"] == "process.name:x.exe"
    assert q["total"] == 3 and q["days_with_hits"] == 1 and q["verdict"] == "rare"
