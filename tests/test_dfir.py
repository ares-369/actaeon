import gzip
import io
import json
import time
import zipfile

import pytest
from conftest import write_cfg

SYSMON1 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f}"/><EventID>1</EventID><Level>4</Level>
<TimeCreated SystemTime="2026-11-20 10:00:01.250000+00:00"/><EventRecordID>77</EventRecordID>
<Execution ProcessID="1" ThreadID="2"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>WS01.corp</Computer><Security UserID="S-1-5-18"/></System><EventData>
<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="CommandLine">powershell.exe -nop -enc SQBFAFgA</Data>
<Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\WINWORD.EXE</Data>
<Data Name="User">CORP\\bob</Data></EventData></Event>"""


def win(eid, channel, ts, **data):
    return {"System": {"EventID": eid, "Channel": channel, "Computer": "WS01",
                       "TimeCreated": {"#attributes": {"SystemTime": ts}}, "Provider": {"#attributes": {"Name": "x"}}},
            "EventData": data}


@pytest.fixture
def on(home):
    write_cfg(home, lambda d: d.update(dfir={"enabled": True}, rules={"enabled": True}))
    from actaeon.config import get_config
    return get_config()


def jl(rows):
    return "\n".join(json.dumps(r) for r in rows) + "\n"


def test_parse_time():
    from actaeon.dfir.parsers import parse_time
    assert parse_time("2026-11-20T10:00:01Z") == "2026-11-20T10:00:01.000Z"
    assert parse_time("2026-11-20 15:30:01.123456 +05:30") == "2026-11-20T10:00:01.123Z"
    assert parse_time(1763632801) == "2025-11-20T10:00:01.000Z"
    assert parse_time(1763632801123) == "2025-11-20T10:00:01.123Z"
    assert parse_time("11/20/2026 10:00:01") == "2026-11-20T10:00:01.000Z"
    assert parse_time("Nov 20 10:00:01", year=2026) == "2026-11-20T10:00:01.000Z"
    assert parse_time("not a time") == ""


def test_event_xml():
    from actaeon.dfir.parsers import from_event_xml
    e = from_event_xml(SYSMON1)
    assert e["ts"] == "2026-11-20T10:00:01.250Z" and e["host"] == "WS01.corp" and e["event_id"] == "1"
    assert e["data"]["Image"].endswith("powershell.exe") and e["data"]["Provider_Name"] == "Microsoft-Windows-Sysmon"
    assert e["summary"].startswith("C:\\Program Files\\Microsoft Office\\WINWORD.EXE -> ")


def test_formats(tmp_path):
    from actaeon.dfir.parsers import parse_file
    (tmp_path / "v.jsonl").write_text(jl([win("4688", "Security", "2026-11-20T10:00:00Z", NewProcessName="C:\\x\\cmd.exe",
                                                ParentProcessName="C:\\x\\w3wp.exe", CommandLine="cmd /c whoami")]))
    evs = [e for e in parse_file(tmp_path / "v.jsonl") if "_kind" not in e]
    assert evs[0]["data"]["Image"] == "C:\\x\\cmd.exe" and "w3wp.exe -> " in evs[0]["summary"]   # 4688 aliases
    (tmp_path / "plaso.csv").write_text("date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc\n"
                                        "11/20/2026,10:00:00,UTC,M...,FILE,NTFS,mtime,-,WS01,x,File C:\\evil.exe\n")
    e = next(e for e in parse_file(tmp_path / "plaso.csv") if "_kind" not in e)
    assert e["ts"] == "2026-11-20T10:00:00.000Z" and e["host"] == "WS01" and "evil.exe" in e["summary"]
    (tmp_path / "auth.log").write_text("Nov 20 10:00:01 web1 sshd[11]: Failed password for root from 203.0.113.9 port 2 ssh2\n"
                                       "garbage line\n")
    out = list(parse_file(tmp_path / "auth.log", year=2026))
    assert out[1]["data"]["action"] == "ssh_failed" and out[1]["data"]["src_ip"] == "203.0.113.9"
    assert out[2] == {"_error": "line 2: not a syslog line"}
    with gzip.open(tmp_path / "a.jsonl.gz", "wt") as g:
        g.write(jl([{"timestamp": "2026-11-20T10:00:00Z", "hostname": "h", "message": "hello"}]))
    assert [e["summary"] for e in parse_file(tmp_path / "a.jsonl.gz") if "_kind" not in e] == ["hello"]
    with zipfile.ZipFile(tmp_path / "c.zip", "w") as z:
        z.writestr("Windows/Security.jsonl", jl([win("4624", "Security", "2026-11-20T10:00:00Z", TargetUserName="bob",
                                                     LogonType="10", IpAddress="198.51.100.7")]))
        z.writestr("README.bin", b"\x00\x01")
    out = list(parse_file(tmp_path / "c.zip"))
    assert out[1] == {"_member": "Windows/Security.jsonl", "_kind": "json"}
    assert out[2]["summary"] == "Logon type 10 bob from 198.51.100.7"


def make_evidence(tmp_path):
    rows = [win("1", "Microsoft-Windows-Sysmon/Operational", "2026-11-20T10:00:05Z", Image="C:\\w\\powershell.exe",
                ParentImage="C:\\o\\winword.exe", CommandLine="powershell -nop -enc SQBFAFgA"),
            win("4624", "Security", "2026-11-20T10:00:01Z", TargetUserName="bob", LogonType="10", IpAddress="198.51.100.7",
                Image="C:\\w\\powershell.exe", CommandLine="powershell -enc x"),        # not process_creation
            win("1102", "Security", "2026-11-20T11:00:00Z", SubjectUserName="bob"),
            {"Timestamp": "2026-11-20T10:30:00Z", "Computer": "WS02", "Channel": "Sec", "EventID": 4625,
             "RuleTitle": "Hayabusa test rule", "Level": "med", "Details": {"Tgt": "admin"}}]
    rows += [win("4625", "Security", f"2026-11-20T09:{i:02d}:00Z", TargetUserName="admin", IpAddress="203.0.113.5")
             for i in range(12)]
    rows.append(win("4624", "Security", "2026-11-20T09:20:00Z", TargetUserName="admin", LogonType="3",
                    IpAddress="203.0.113.5"))
    p = tmp_path / "evidence.jsonl"
    p.write_text(jl(rows))
    return p


def test_import_analyze_and_marks(on, tmp_path):
    from actaeon.dfir import service as S
    st = S.store_for(on)
    c = st.create_case("Case", "", actor="a")
    p = make_evidence(tmp_path)
    r = S.import_file(on, c["id"], p, "evidence.jsonl", actor="a")
    assert r["events"] == 17 and r["status"] == "done" and len(r["sha256"]) == 64
    assert S.import_file(on, c["id"], p, "copy.jsonl", actor="a")["duplicate"]
    res = S.analyze(on, c["id"])
    titles = {d["title"]: d for d in st.detection_summary(c["id"])}
    assert titles["Encoded PowerShell command line"]["n"] == 1          # only the Sysmon 1 event, not the 4624
    assert "Event log cleared" in titles and titles["Hayabusa test rule"]["origin"] == "imported"
    assert titles["Hayabusa test rule"]["level"] == "medium"
    assert res["bruteforce_hits"] == 1 and any("after 12 failed" in t for t in titles)
    rows, total = st.search(c["id"], detected=True)
    assert total == 5 and rows[0]["ts"] <= rows[-1]["ts"]
    assert st.search(c["id"], q="CommandLine:-enc")[1] == 2
    assert st.search(c["id"], host="WS02")[1] == 1
    seq = rows[0]["seq"]
    st.mark(c["id"], seq, star=True, tags=["initial access", " "], comment="first sign")
    e = st.event(c["id"], seq)
    assert e["star"] == 1 and e["tags"] == ["initial access"] and e["comment"] == "first sign"
    an = st.analysis(c["id"])
    assert an["logons"][0]["failed"] == 12 and an["stacking"]["parent_child"][0]["value"] == "winword.exe -> powershell.exe"
    csv_text = S.export_csv(on, c["id"], detected=True)
    assert csv_text.splitlines()[0].startswith("Timestamp,Host,Log") and len(csv_text.splitlines()) == 6
    md = S.report_markdown(on, c["id"])
    assert r["sha256"] in md and "first sign" in md


def test_library_rules_run_on_evidence(on, tmp_path):
    from actaeon.dfir import service as S
    from actaeon.rules import service as R
    rule = """title: Winword child
logsource: {category: process_creation, product: windows}
detection:
  sel: {ParentImage|endswith: '\\\\winword.exe'}
  condition: sel
level: high
tags: [attack.t1204.002]
"""
    r = R.create(on, rule, actor="a")
    c = S.store_for(on).create_case("Case", "", actor="a")
    S.import_file(on, c["id"], make_evidence(tmp_path), "e.jsonl", actor="a")
    S.analyze(on, c["id"])
    assert "Winword child" not in {d["title"] for d in S.store_for(on).detection_summary(c["id"])}   # draft: not run
    R.change_status(on, r["id"], "submit", actor="a")
    S.analyze(on, c["id"])
    d = {d["title"]: d for d in S.store_for(on).detection_summary(c["id"])}["Winword child"]
    assert d["origin"] == "library" and d["attack"] == ["T1204.002"]


def test_max_events_and_bad_file(on, tmp_path, home):
    write_cfg(home, lambda d: d.update(dfir={"enabled": True, "max_events_per_case": 1000}))
    from actaeon import config
    from actaeon.dfir import service as S
    config._CONFIG = None
    cfg = config.get_config()
    c = S.store_for(cfg).create_case("Case", "", actor="a")
    p = tmp_path / "big.jsonl"
    p.write_text(jl([{"timestamp": "2026-11-20T10:00:00Z", "n": i} for i in range(1500)]))
    r = S.import_file(cfg, c["id"], p, "big.jsonl", actor="a")
    assert r["events"] == 1000 and "max_events_per_case" in r["note"]
    q = tmp_path / "x.bin"
    q.write_bytes(b"\x00\x01\x02")
    with pytest.raises(Exception, match="unknown format"):
        list(__import__("actaeon.dfir.parsers", fromlist=["parse_file"]).parse_file(q))


class FakeLLM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.seen = []

    def for_role(self, role):
        outer = self

        class B:
            provider = type("P", (), {"name": "fake"})()
            model = "m"

            def chat(self, messages, **kw):
                from actaeon.providers.base import LLMResult
                outer.seen.append(messages)
                return LLMResult(text=json.dumps(outer.replies.pop(0)))
        return B()


def test_story_checks_citations(on, tmp_path):
    from actaeon.dfir import ai
    from actaeon.dfir import service as S
    c = S.store_for(on).create_case("Case", "", actor="a")
    S.import_file(on, c["id"], make_evidence(tmp_path), "e.jsonl", actor="a")
    S.analyze(on, c["id"])
    shown = S.store_for(on).search(c["id"], detected=True)[0][0]["seq"]
    llm = FakeLLM([{"summary": "s", "confidence": "medium", "phases": [
        {"phase": "Execution", "when": "10:00", "what": "encoded powershell", "events": [f"E{shown}", "E99999"]},
        {"phase": "made up", "what": "exfiltration of data", "events": []}], "open_questions": ["q"]}])
    b = ai.story(on, llm, c["id"], actor="a")
    assert b["phases"][0]["events"] == [shown] and b["citations_removed"] == 1
    assert b["phases"][1]["uncited"] and b["phases"][1]["phase"] == "other" and b["unsupported_parts"] == 1
    assert "E99999" not in llm.seen[0][1]["content"] and f"E{shown} " in llm.seen[0][1]["content"]
    assert S.store_for(on).stories(c["id"])[0]["body"]["summary"] == "s"


def test_ask_can_search(on, tmp_path):
    from actaeon.dfir import ai
    from actaeon.dfir import service as S
    c = S.store_for(on).create_case("Case", "", actor="a")
    S.import_file(on, c["id"], make_evidence(tmp_path), "e.jsonl", actor="a")
    llm = FakeLLM([{"search": "198.51.100.7"}, {"answer": "bob logged on over RDP", "events": ["E2"]}])
    r = ai.ask(on, llm, c["id"], "who used RDP?", actor="a")
    assert r["events"] == [2] and r["searches"][0]["found"] >= 1
    with pytest.raises(ValueError):
        ai.ask(on, None, c["id"], "x", actor="a")


def wait_idle(cl, cid):
    for _ in range(100):
        o = cl.get(f"/api/dfir/cases/{cid}").get_json()
        if not (o.get("work") or {}).get("running"):
            return o
        time.sleep(0.1)
    raise AssertionError("still running")


def test_web(on, tmp_path, home):
    from actaeon.web import create_app
    cl = create_app(on).test_client()
    assert cl.post("/api/dfir/cases", json={}).status_code == 400
    cid = cl.post("/api/dfir/cases", json={"title": "Web case"}).get_json()["id"]
    data = make_evidence(tmp_path).read_bytes()
    r = cl.post(f"/api/dfir/cases/{cid}/upload", data={"files": (io.BytesIO(data), "../../e.jsonl")},
                content_type="multipart/form-data")
    assert r.status_code == 202 and r.get_json()["files"] == ["e.jsonl"]
    o = wait_idle(cl, cid)
    assert o["events"] == 17 and o["sources"][0]["name"] == "e.jsonl", o["work"]
    assert not [p for p in home.glob("data/dfir-uploads/**/*") if p.is_file()]   # kept only until imported
    assert o["activity"][0]["action"] == "import" and o["interrupted"] == []
    assert cl.post(f"/api/dfir/cases/{cid}/analyze").status_code == 202
    o = wait_idle(cl, cid)
    assert o["detections"] and o["analyzed"]
    ev = cl.get(f"/api/dfir/cases/{cid}/events?detected=1&limit=2").get_json()
    assert ev["total"] == 5 and len(ev["events"]) == 2
    seq = ev["events"][0]["seq"]
    assert cl.post(f"/api/dfir/cases/{cid}/events/{seq}", json={"star": True}).get_json()["star"] == 1
    assert cl.post(f"/api/dfir/cases/{cid}/notes", json={"kind": "hypothesis", "text": "RDP in", "events": [seq]}).status_code == 201
    assert cl.post(f"/api/dfir/cases/{cid}/notes", json={"kind": "bad", "text": "x"}).status_code == 400
    assert cl.get(f"/api/dfir/cases/{cid}/export.csv").data.startswith(b"Timestamp")
    assert b"RDP in" in cl.get(f"/api/dfir/cases/{cid}/report.md").data
    assert cl.post(f"/api/dfir/cases/{cid}/delete").get_json()["deleted"] == cid
    assert cl.get(f"/api/dfir/cases/{cid}").status_code == 404


def test_off_by_default(home):
    from actaeon.config import get_config
    from actaeon.web import create_app
    cl = create_app(get_config()).test_client()
    assert cl.get("/api/dfir/status").get_json() == {"enabled": False}
    assert cl.get("/api/dfir/cases").status_code == 404


def test_cli_and_mcp(on, tmp_path, capsys):
    from actaeon.cli import cli_main
    from actaeon.dfir.mcp import add_tools
    with pytest.raises(SystemExit):
        cli_main(["dfir", "new", "CLI", "case"])
    cid = capsys.readouterr().out.strip()
    for argv in (["dfir", "import", cid, str(make_evidence(tmp_path))], ["dfir", "analyze", cid],
                 ["dfir", "timeline", cid, "--detected"], ["dfir", "show", cid]):
        with pytest.raises(SystemExit) as e:
            cli_main(argv)
        assert e.value.code == 0, argv
    assert "Encoded PowerShell" in capsys.readouterr().out
    tools = {}
    add_tools(lambda name, desc, props, fn, required=(): tools.__setitem__(name, fn), on)
    assert tools["list_investigations"]({})["investigations"][0]["id"] == cid
    assert tools["search_investigation"]({"id": cid, "detected": True})["total"] == 5
    assert tools["get_investigation"]({"id": cid})["sources"][0]["sha256"]


def test_evtx_dump_json_shape(tmp_path):
    """The JSON lines evtx_dump writes (attributes under #attributes, EventID with Qualifiers as #text)."""
    from actaeon.dfir.parsers import from_event_json
    rec = {"Event": {"#attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
                     "System": {"Provider": {"#attributes": {"Name": "Service Control Manager"}},
                                "EventID": {"#attributes": {"Qualifiers": 16384}, "#text": 7045},
                                "TimeCreated": {"#attributes": {"SystemTime": "2026-11-20T10:00:00.123456Z"}},
                                "Channel": "System", "Computer": "DC1"},
                     "EventData": {"ServiceName": "evil", "ImagePath": "C:\\Users\\Public\\x.exe",
                                   "AccountName": "LocalSystem"}}}
    e = from_event_json(rec)
    assert e["event_id"] == "7045" and e["ts"] == "2026-11-20T10:00:00.123Z" and e["host"] == "DC1"
    assert e["data"]["Provider_Name"] == "Service Control Manager" and e["data"]["ImagePath"].endswith("x.exe")
    assert e["summary"].startswith("Service installed evil")


def test_evtx_dump_missing_tool(tmp_path):
    from actaeon.dfir.parsers import ParseError, parse_file
    p = tmp_path / "a.evtx"
    p.write_bytes(b"ElfFile\x00" + b"\x00" * 100)
    with pytest.raises(ParseError, match="does not exist"):
        list(parse_file(p, evtx_dump=str(tmp_path / "nope")))


def test_prompt_fits_small_local_model(on, tmp_path, home):
    write_cfg(home, lambda d: d.update(dfir={"enabled": True}, llm={
        "providers": {"ollama": {"base_url": "http://x", "num_ctx": 6000}},
        "roles": {r: {"provider": "ollama", "model": "m"} for r in ("planner", "analyst", "reporter")}}))
    from actaeon import config
    from actaeon.dfir import ai
    from actaeon.dfir import service as S
    config._CONFIG = None
    cfg = config.get_config()
    assert ai.prompt_budget(cfg, "reporter", 3000) == 4500
    c = S.store_for(cfg).create_case("Case", "", actor="a")
    rows = [win("1102", "Security", f"2026-11-20T10:{i % 60:02d}:00Z", SubjectUserName="u" * 50) for i in range(300)]
    p = tmp_path / "many.jsonl"
    p.write_text(jl(rows))
    S.import_file(cfg, c["id"], p, "many.jsonl", actor="a")
    S.analyze(cfg, c["id"])
    for seq in range(1, 201):
        S.store_for(cfg).mark(c["id"], seq, star=True)
    llm = FakeLLM([{"summary": "s", "phases": []}])
    b = ai.story(cfg, llm, c["id"], actor="a")
    sent = llm.seen[0][0]["content"] + llm.seen[0][1]["content"]
    assert len(sent) <= 4500 + 200 and b["events_left_out"] > 0 and b["events_given"] > 0


def test_facts_never_crowd_out_events():
    from actaeon.dfir.ai import facts_text
    big = {"case": "c", "detections": [{"title": "x" * 100}] * 500, "hosts": ["h" * 30] * 300}
    t = facts_text(big, 2000)
    assert len(t) <= 2000 and t.startswith("{") and t.endswith("}")


def test_word_search_uses_the_index(on, tmp_path):
    from actaeon.dfir import service as S
    st = S.store_for(on)
    c = st.create_case("Case", "", actor="a")
    S.import_file(on, c["id"], make_evidence(tmp_path), "e.jsonl", actor="a")
    assert st.search(c["id"], q="winword")[1] == 1            # a word inside a path
    assert st.search(c["id"], q="powersh")[1] == 2            # the last word is a prefix
    assert st.search(c["id"], q="powershell winword")[1] == 1  # every word must appear
    assert st.search(c["id"], q="nothing-like-this")[1] == 0


def test_process_tree(on, tmp_path):
    from actaeon.dfir import service as S
    from actaeon.dfir.views import process_tree
    sy = "Microsoft-Windows-Sysmon/Operational"
    rows = [win("1", sy, "2026-11-20T10:00:00Z", ProcessGuid="{A}", ParentProcessGuid="{X}", ProcessId="100",
                Image="C:\\o\\winword.exe", ParentImage="C:\\w\\explorer.exe"),
            win("1", sy, "2026-11-20T10:00:05Z", ProcessGuid="{B}", ParentProcessGuid="{A}", ProcessId="200",
                ParentProcessId="100", Image="C:\\w\\powershell.exe", CommandLine="powershell -enc x"),
            win("1", sy, "2026-11-20T10:00:09Z", ProcessGuid="{C}", ParentProcessGuid="{B}", ProcessId="300",
                Image="C:\\w\\whoami.exe"),
            win("3", sy, "2026-11-20T10:00:07Z", ProcessGuid="{B}", Image="C:\\w\\powershell.exe",
                DestinationIp="203.0.113.9", DestinationPort="443"),
            # Security 4688 links by hex process ids and time
            win("4688", "Security", "2026-11-20T11:00:00Z", NewProcessId="0x1f4", ProcessId="0x4",
                NewProcessName="C:\\w\\cmd.exe"),
            win("4688", "Security", "2026-11-20T11:00:02Z", NewProcessId="0x258", ProcessId="0x1f4",
                NewProcessName="C:\\w\\net.exe", CommandLine="net user x /add")]
    p = tmp_path / "t.jsonl"
    p.write_text(jl(rows))
    st = S.store_for(on)
    c = st.create_case("Case", "", actor="a")
    S.import_file(on, c["id"], p, "t.jsonl", actor="a")
    t = process_tree(st, c["id"], 2)                               # the powershell event
    assert [a["image"].rsplit("\\", 1)[-1] for a in t["ancestors"]] == ["winword.exe"]
    assert t["focus"]["children"][0]["image"].endswith("whoami.exe")
    t = process_tree(st, c["id"], 4)                               # the network event maps to its process
    assert t["focus"]["seq"] == 2
    t = process_tree(st, c["id"], 6)                               # net.exe under cmd.exe by pid
    assert t["ancestors"][0]["image"].endswith("cmd.exe")


def test_accounts_flag_new_late_sources(on, tmp_path):
    from actaeon.dfir import service as S
    rows = [win("4624", "Security", "2026-11-01T09:00:00Z", TargetUserName="bob", LogonType="3", IpAddress="10.0.0.5"),
            win("4624", "Security", "2026-11-01T10:00:00Z", TargetUserName="bob", LogonType="3", IpAddress="10.0.0.5"),
            win("4624", "Security", "2026-11-05T02:00:00Z", TargetUserName="bob", LogonType="10", IpAddress="198.51.100.7")]
    p = tmp_path / "l.jsonl"
    p.write_text(jl(rows))
    st = S.store_for(on)
    c = st.create_case("Case", "", actor="a")
    S.import_file(on, c["id"], p, "l.jsonl", actor="a")
    S.analyze(on, c["id"])
    a = st.analysis(c["id"])["accounts"][0]
    assert a["account"] == "bob" and a["ok"] == 3 and a["types"] == {"3": 2, "10": 1}
    assert a["new_later"] == [{"kind": "source", "value": "198.51.100.7", "first": "2026-11-05T02:00:00.000Z"}]


def test_support_check():
    from actaeon.dfir.ai import support
    lsass = {"seq": 1, "summary": "rundll32 comsvcs MiniDump lsass", "data": {},
             "detections": [{"title": "LSASS memory dumped", "attack": ["T1003.001"]}]}
    sticky = {"seq": 2, "summary": "reg.exe SetValue Image File Execution Options sethc.exe", "data": {},
              "detections": [{"title": "Sticky key backdoor", "attack": ["T1546.008"]}]}
    res = support("credential access", "Credential theft from LSASS using Dumpert and Mimikatz", [lsass, sticky])
    assert res[0]["fits"] and res[0]["why"] == "ATT&CK tactic"
    assert not res[1]["fits"]
    assert support("other", "sethc.exe replaced", [sticky])[0]["why"] == "shared words: sethc.exe"


def test_interrupted_import_can_run_again(on, tmp_path, home):
    from actaeon.dfir import service as S
    from actaeon.web import create_app
    cl = create_app(on).test_client()
    st = S.store_for(on)
    c = st.create_case("Case", "", actor="a")
    kept = S.uploads_dir(on, c["id"]) / "k-e.jsonl"
    kept.write_bytes(make_evidence(tmp_path).read_bytes())
    sid = st.add_source(c["id"], name="e.jsonl", sha256="x" * 64, size=1, actor="a")
    st.set_source(sid, upload_path=str(kept))
    st.add_events(c["id"], sid, [(1, {"ts": "", "host": "h", "channel": "", "event_id": "", "user": "", "process": "",
                                      "summary": "half", "data": {}})])
    o = cl.get(f"/api/dfir/cases/{c['id']}").get_json()
    assert o["interrupted"] == [sid]
    assert cl.post(f"/api/dfir/cases/{c['id']}/sources/{sid}/retry").status_code == 202
    o = wait_idle(cl, c["id"])
    assert o["events"] == 17 and [s["status"] for s in o["sources"]] == ["done"] and not kept.exists()
    assert cl.post(f"/api/dfir/cases/{c['id']}/sources/{sid}/retry").status_code == 409
