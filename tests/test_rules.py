import io
import json
import zipfile

import pytest
from conftest import write_cfg

SIGMA = """title: Office starts encoded PowerShell
description: Word or Excel starting PowerShell with an encoded command
logsource: {category: process_creation, product: windows}
detection:
  sel:
    ParentImage|endswith: ['\\\\winword.exe', '\\\\excel.exe']
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: ' -enc'
  condition: sel
level: high
tags: [attack.t1059.001]
falsepositives: [Office add-ins that script PowerShell]
"""
BAD_EVT = {"data": {"win": {"eventdata": {"parentImage": "C:\\Office\\WINWORD.EXE",
                                          "image": "C:\\Windows\\powershell.exe",
                                          "commandLine": "powershell -nop -enc SQBFAFgA"}}}}
GOOD_EVT = {"data": {"win": {"eventdata": {"parentImage": "C:\\Windows\\explorer.exe",
                                           "image": "C:\\Windows\\powershell.exe",
                                           "commandLine": "powershell -file backup.ps1"}}}}


@pytest.fixture
def on(home):
    write_cfg(home, lambda d: d.update(rules={"enabled": True}))
    from actaeon.config import get_config
    return get_config()


def test_off_by_default(home):
    from actaeon.config import get_config
    from actaeon.web import create_app
    assert get_config().rules.enabled is False
    cl = create_app(get_config()).test_client()
    assert cl.get("/api/rules/status").get_json() == {"enabled": False}
    assert cl.get("/api/rules").status_code == 404


def test_config_validation(home):
    from actaeon.rules.config import parse
    with pytest.raises(ValueError, match="unknown"):
        parse({"nope": 1})
    with pytest.raises(ValueError, match="priorities"):
        parse({"priorities": ["X123"]})
    assert parse({"field_map": {"Image": "proc.exe"}}).field_map == {"Image": ["proc.exe"]}


def test_lifecycle_and_ready_gate(on):
    from actaeon.rules import service as S
    r = S.create(on, SIGMA, actor="alice")
    assert r["status"] == "draft" and r["attack"] == ["T1059.001"] and r["version"] == 1
    with pytest.raises(ValueError, match="cannot approve"):
        S.change_status(on, r["id"], "approve", actor="bob")
    S.change_status(on, r["id"], "submit", actor="alice")
    with pytest.raises(ValueError, match="real event"):
        S.change_status(on, r["id"], "approve", actor="bob")
    S.add_test(on, r["id"], name="model", expect="match", event=BAD_EVT, origin="synthetic", actor="alice")
    d = S.detail(on, r["id"], actor="bob")
    assert any("real event" in p for p in d["ready_problems"])     # synthetic does not count
    S.add_test(on, r["id"], name="real", expect="match", event=BAD_EVT, origin="real", actor="alice")
    S.add_test(on, r["id"], name="admin", expect="no_match", event=GOOD_EVT, origin="real", actor="alice")
    d = S.detail(on, r["id"], actor="bob")
    assert d["ready_problems"] == ["the tests have not been run"]
    res = S.run_tests(on, r["id"], actor="bob")
    assert res["ok"] and res["passed"] == 3
    assert res["results"][0]["fields"]["Image"] == "data.win.eventdata.image"
    # the last editor may not approve their own rule
    with pytest.raises(ValueError, match="last editor"):
        S.change_status(on, r["id"], "approve", actor="alice")
    ok = S.change_status(on, r["id"], "approve", actor="bob")
    assert ok["status"] == "ready" and ok["approved_by"] == "bob"
    # editing a ready rule sends it back to testing with a new version, and the old run no longer counts
    e = S.edit(on, r["id"], SIGMA.replace("level: high", "level: critical"), actor="carol")
    assert e["status"] == "testing" and e["version"] == 2 and e["approved_by"] is None
    d = S.detail(on, r["id"], actor="bob")
    assert any("older version" in p for p in d["ready_problems"])
    assert [v["version"] for v in d["versions"]] == [2, 1]


def test_failing_test_blocks(on):
    from actaeon.rules import service as S
    r = S.create(on, SIGMA, actor="a")
    S.change_status(on, r["id"], "submit", actor="a")
    S.add_test(on, r["id"], name="real", expect="match", event=GOOD_EVT, origin="real", actor="a")
    S.add_test(on, r["id"], name="neg", expect="no_match", event=GOOD_EVT, origin="real", actor="a")
    assert not S.run_tests(on, r["id"], actor="b")["ok"]
    with pytest.raises(ValueError, match="1 test"):
        S.change_status(on, r["id"], "approve", actor="b")


def test_lint(on):
    from actaeon.rules.lint import lint
    msgs = lint("title: x\nlogsource: {product: windows}\ndetection:\n  sel: {Image: '*'}\n  condition: sel\n")
    errs = [m["text"] for m in msgs if m["level"] == "error"]
    assert any("matches anything" in e for e in errs)
    assert any("ATT&CK" in m["text"] for m in msgs)
    msgs = lint(SIGMA, known_fields={"image", "commandline"})
    assert [m["text"] for m in msgs] == ["field 'ParentImage' was not seen in your data (add it to rules.field_map "
                                         "if it has another name)"]
    only_not = "title: x\nlogsource: {product: w}\ndetection:\n  f: {A: b}\n  condition: not f\n"
    assert any("only excludes" in m["text"] for m in lint(only_not))


def test_duplicate_logic_warns(on):
    from actaeon.rules import service as S
    a = S.create(on, SIGMA, actor="a")
    b = S.create(on, SIGMA.replace("title: Office", "title: Copy of Office"), actor="a")
    assert a["id"] != b["id"]
    assert any(a["id"] in m["text"] for m in S.detail(on, b["id"], actor="a")["lint"])


def test_from_hunt_adds_real_evidence(on):
    from actaeon.hunt.service import store_for as hs
    from actaeon.rules import service as S
    st = hs(on)
    hid = st.create("Office spawning encoded PowerShell")
    res = json.dumps({"total": 1, "hits": [BAD_EVT]})
    st.add_step(hid, 3, "call", connector="logs", tool="search", arguments={"query": "q"}, ok=True,
                result=f"<<UNTRUSTED-DATA a>>\n{res}\n<<END-UNTRUSTED-DATA a>>")
    st.update(hid, status="done", outcome="threat",
              verdict={"outcome": "threat", "attack": ["T1059.001"],
                       "findings": [{"claim": "encoded powershell from word", "evidence": ["E3"]}]})
    r = S.from_hunt(on, st.get(hid), actor="a", sigma=SIGMA)
    d = S.detail(on, r["id"], actor="b")
    assert r["source"] == {"kind": "hunt", "ref": hid}
    assert [(t["origin"], t["expect"]) for t in d["tests"]] == [("real", "match")]
    assert d["last_run"]["ok"] is True


def test_coverage_gaps(on, home):
    from actaeon.hunt.service import store_for as hs
    from actaeon.rules import service as S
    write_cfg(home, lambda d: d.update(rules={"enabled": True, "priorities": ["T1003.001"]}))
    from actaeon import config
    config._CONFIG = None
    cfg = config.get_config()
    st = hs(cfg)
    hid = st.create("x")
    st.update(hid, status="done", outcome="threat", verdict={"outcome": "threat", "attack": ["T1059.001"]})
    S.create(cfg, SIGMA, actor="a")
    cov = {x["technique"]: x for x in S.coverage(cfg)["techniques"]}
    assert cov["T1059.001"]["gap"] and cov["T1059.001"]["draft"] == 1
    assert cov["T1003.001"]["reasons"] == ["on your priority list"] and cov["T1003.001"]["name"]


def test_import_and_export(on):
    from actaeon.rules import service as S
    two = SIGMA + "---\n" + SIGMA.replace("title: Office", "title: Other").replace("level: high", "level: low")
    out = S.import_text(on, two, actor="a")
    assert len(out["created"]) == 2 and not out["errors"]
    rid = out["created"][0]
    again = S.import_text(on, S.store_for(on).get(rid)["sigma"], actor="a")
    assert again["unchanged"] == [rid]
    assert S.import_text(on, "title: c\ncorrelation: {}\n", actor="a")["errors"]
    S.add_test(on, rid, name="n", expect="match", event=BAD_EVT, origin="real", actor="a")
    z = zipfile.ZipFile(io.BytesIO(S.export_zip(on, ("draft",))))
    names = z.namelist()
    assert "INDEX.txt" in names and sum(n.endswith(".yml") for n in names) == 2
    tests = json.loads(next(z.read(n) for n in names if n.endswith(".tests.json") and rid[:8] in n))
    assert tests[0]["expect"] == "match"


class FakeLLM:
    def __init__(self, obj):
        self.obj = obj

    def for_role(self, role):
        obj = self.obj

        class B:
            def chat(self, messages, **kw):
                from actaeon.providers.base import LLMResult
                facts = json.loads(messages[1]["content"])
                assert facts["technique"] == "T1059.001" and facts["name"]
                return LLMResult(text=json.dumps(obj))
        return B()


def test_draft_for_technique_marks_samples_synthetic(on):
    from actaeon.rules import service as S
    llm = FakeLLM({"sigma": SIGMA, "notes": "tune parents", "match_samples": [BAD_EVT], "no_match_samples": [GOOD_EVT]})
    r = S.draft_for_technique(on, llm, "t1059.001", actor="a", context="advisory text")
    d = S.detail(on, r["id"], actor="b")
    assert {t["origin"] for t in d["tests"]} == {"synthetic"} and d["last_run"]["ok"]
    assert d["source"]["kind"] == "gap" and d["notes"].startswith("Model draft.")
    with pytest.raises(ValueError, match="not a known"):
        S.draft_for_technique(on, llm, "T9999", actor="a")


def test_web_api(on):
    from actaeon.web import create_app
    cl = create_app(on).test_client()
    r = cl.post("/api/rules", json={"sigma": SIGMA})
    assert r.status_code == 201, r.get_json()
    rid = r.get_json()["id"]
    assert cl.post("/api/rules", json={"sigma": "title: x"}).status_code == 400
    assert cl.post(f"/api/rules/{rid}/tests", json={"expect": "match", "event": BAD_EVT, "origin": "real"}).status_code == 201
    assert cl.post(f"/api/rules/{rid}/tests", json={"expect": "match", "event": "nope"}).status_code == 400
    assert cl.post(f"/api/rules/{rid}/run").get_json()["ok"]
    assert cl.post(f"/api/rules/{rid}/status", json={"action": "submit"}).get_json()["status"] == "testing"
    assert cl.post(f"/api/rules/{rid}/status", json={"action": "approve"}).status_code == 409
    one = cl.get(f"/api/rules/{rid}").get_json()
    assert one["tests"] and one["lint"] is not None and one["ready_problems"]
    assert cl.get("/api/rules?status=testing").get_json()[0]["id"] == rid
    assert cl.get("/api/rules/coverage").get_json()["techniques"][0]["technique"] == "T1059.001"
    assert cl.post(f"/api/rules/{rid}/delete").status_code == 409
    z = cl.get("/api/rules/export.zip?status=testing")
    assert z.status_code == 200 and z.data[:2] == b"PK"
    assert cl.post("/api/rules/import", json={"text": SIGMA.replace("title: Office", "title: New")}).get_json()["created"]


def test_cli(on, capsys):
    from actaeon.cli import cli_main
    from actaeon.rules import service as S
    r = S.create(on, SIGMA, actor="a")
    S.add_test(on, r["id"], name="n", expect="match", event=BAD_EVT, origin="real", actor="a")
    for argv, code in ((["rules", "test", r["id"]], 0), (["rules", "list"], 0), (["rules", "coverage"], 0),
                       (["rules", "test", "--all"], 0), (["rules", "lint", r["id"]], 0)):
        with pytest.raises(SystemExit) as e:
            cli_main(argv)
        assert e.value.code == code, argv
    assert "1/1 passed" in capsys.readouterr().out


def test_mcp_tools(on):
    from actaeon.rules import service as S
    from actaeon.rules.mcp import add_tools
    tools = {}
    add_tools(lambda name, desc, props, fn, required=(): tools.__setitem__(name, fn), on)
    r = S.create(on, SIGMA, actor="a")
    assert tools["list_rules"]({})["rules"][0]["id"] == r["id"]
    assert tools["get_rule"]({"id": r["id"]})["sigma"].startswith("title")
    assert tools["rule_coverage"]({"gaps_only": True})["techniques"] == []
