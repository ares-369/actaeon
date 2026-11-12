import json

from actaeon import config
from actaeon.hunt import service
from actaeon.hunt.verify import apply
from actaeon.providers.base import LLMResult
from tests.test_hunt import PLAN, Hub, call


class Script:
    """Analyst replies for the hunt, then verifier replies."""

    def __init__(self, hunt, verify):
        self.hunt, self.verify = list(hunt), list(verify)
        self.seen = []

    def for_role(self, role):
        outer = self

        class B:
            provider = type("P", (), {"name": "fake"})()
            model = "m"

            def chat(self, messages, **kw):
                outer.seen.append(messages)
                if "sceptical analyst" in messages[0]["content"]:
                    r = outer.verify.pop(0)
                elif "You plan threat hunts" in messages[0]["content"]:
                    r = PLAN
                else:
                    r = outer.hunt.pop(0)
                return LLMResult(text=json.dumps(r))
        return B()


THREAT = [call(index="e", time_from="now-1d", query="a"), call(index="e", time_from="now-2d", query="b"),
          call("lookup", value="1.2.3.4"),
          {"action": "verdict", "outcome": "threat", "confidence": 70, "summary": "bad",
           "findings": [{"claim": "c", "evidence": ["E2", "E3", "E4"]}]}]


def run(home, verify_replies):
    cfg = config.get_config(reload=True)
    llm = Script(THREAT, verify_replies)
    return service.run_hunt(cfg, "test", llm=llm, hub=Hub(results={"search": '{"total": 2}'})), llm


def test_verify_confirmed_raises_confidence(home):
    h, llm = run(home, [call(index="e", time_from="now-7d", query="wider"),
                        {"action": "verify", "result": "confirmed", "reason": "still active", "evidence": ["E6"]}])
    v = h["verdict"]
    assert v["outcome"] == "threat" and v["verification"]["result"] == "confirmed" and v["confidence"] >= 80
    assert any(s["note"] == "from verify" for s in h["steps"])
    assert any("sceptical" in m[0]["content"] for m in llm.seen)


def test_confirmed_without_own_evidence_is_unconfirmed(home):
    h, _ = run(home, [{"action": "verify", "result": "confirmed", "reason": "trust me", "evidence": ["E2"]}])
    v = h["verdict"]
    assert v["verification"]["result"] == "unconfirmed" and v["confidence"] <= 60 and v["needs_review"]


def test_refuted_never_silently_dismisses(home):
    h, _ = run(home, [call(index="e", time_from="now-7d", query="admin"),
                      {"action": "verify", "result": "refuted", "reason": "patch tool", "evidence": ["E7"]}])
    assert h["outcome"] == "inconclusive" and h["verdict"]["needs_review"]


def test_verify_can_be_turned_off(home):
    from tests.conftest import write_cfg
    write_cfg(home, lambda d: d["hunt"].update(verify=False))
    cfg = config.load_config()
    h = service.run_hunt(cfg, "x", llm=Script(THREAT, []), hub=Hub())
    assert "verification" not in h["verdict"]


def test_apply_direct():
    v = apply({"verdict": {"outcome": "threat", "confidence": 90}}, {"result": "unconfirmed", "reason": "r"})
    assert v["confidence"] == 60 and v["needs_review"]


def test_demo_verification(tmp_path, monkeypatch, capsys):
    from actaeon import cli
    from actaeon import config as c
    from actaeon.connectors import hub as hubmod
    try:
        cli.cmd_demo(type("A", (), {"dir": str(tmp_path / "d"), "offline": True, "run": True, "port": 8611})())
    finally:
        c._CONFIG, hubmod._HUB = None, None
    from actaeon.hunt import HuntStore
    h = next(x for x in HuntStore(tmp_path / "d" / "data" / "hunts.sqlite").list() if x["origin"] == "demo")
    assert h["verdict"]["verification"]["result"] == "confirmed"
