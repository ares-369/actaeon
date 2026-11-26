import base64

import pytest

from actaeon.rules.sigma_eval import Unsupported, compile_rule

EVT = {"data": {"win": {"eventdata": {"image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                      "commandLine": "powershell.exe -nop -enc SQBFAFgA",
                                      "parentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"}}},
       "agent": {"name": "ws01", "ip": "10.0.0.31"}, "rule": {"level": 12, "id": "92052"}}


def rule(det: str) -> str:
    return "title: t\nlogsource: {product: windows}\ndetection:\n" + det


def m(det: str, ev=EVT, fmap=None):
    return compile_rule(rule(det)).match(ev, fmap)


def test_leaf_field_lookup_and_endswith_case_insensitive():
    ok, used = m("  sel:\n    Image|endswith: '\\powershell.EXE'\n    ParentImage|endswith: '\\winword.exe'\n"
                 "  condition: sel\n")
    assert ok and used["Image"] == "data.win.eventdata.image"


def test_contains_all_and_lists():
    assert m("  sel:\n    CommandLine|contains|all: ['-nop', '-enc']\n  condition: sel\n")[0]
    assert not m("  sel:\n    CommandLine|contains|all: ['-nop', '-hidden']\n  condition: sel\n")[0]
    assert m("  sel:\n    CommandLine|contains: ['-hidden', '-enc']\n  condition: sel\n")[0]


def test_wildcards_and_escapes():
    assert m("  sel:\n    Image: '*\\\\powershell.exe'\n  condition: sel\n")[0]
    assert m("  sel:\n    agent.name: 'ws?1'\n  condition: sel\n")[0]
    assert not m("  sel:\n    agent.name: 'ws\\?1'\n  condition: sel\n")[0]
    assert m("  sel:\n    agent.name: 'ws\\?1'\n  condition: sel\n", ev={"agent": {"name": "ws?1"}})[0]


def test_conditions():
    base = "  sel:\n    Image|endswith: powershell.exe\n  filter:\n    agent.name: ws01\n"
    assert not m(base + "  condition: sel and not filter\n")[0]
    assert m(base + "  condition: sel and filter\n")[0]
    assert m(base + "  condition: 1 of them\n")[0]
    assert m(base + "  condition: all of them\n")[0]
    assert not m(base + "  condition: (sel or filter) and not (sel and filter)\n")[0]
    with pytest.raises(Unsupported):
        m(base + "  condition: 1 of nothere*\n")


def test_unknown_identifier_and_aggregation_are_unsupported():
    with pytest.raises(Unsupported):
        m("  sel: {a: b}\n  condition: sel and other\n")
    with pytest.raises(Unsupported):
        m("  sel: {a: b}\n  condition: sel | count() > 5\n")
    with pytest.raises(Unsupported):
        compile_rule("title: c\ncorrelation: {type: event_count}\n")
    with pytest.raises(Unsupported):
        m("  sel:\n    a|expand: b\n  condition: sel\n")


def test_fieldref_and_fieldless_items():
    ev = {"SubjectUserName": "bob", "TargetUserName": "BOB", "Other": "x"}
    assert m("  sel:\n    SubjectUserName|fieldref: TargetUserName\n  condition: sel\n", ev=ev)[0]
    assert not m("  sel:\n    SubjectUserName|fieldref: Other\n  condition: sel\n", ev=ev)[0]
    assert m("  sel:\n    '|contains': 'bo'\n  condition: sel\n", ev=ev)[0]
    assert not m("  sel:\n    '|contains': 'zzz'\n  condition: sel\n", ev=ev)[0]


def test_null_exists_numbers_cidr_re():
    assert m("  sel:\n    Missing: null\n  condition: sel\n")[0]
    assert m("  sel:\n    Missing|exists: false\n    Image|exists: true\n  condition: sel\n")[0]
    assert m("  sel:\n    rule.level|gte: 10\n  condition: sel\n")[0]
    assert not m("  sel:\n    rule.level|lt: 10\n  condition: sel\n")[0]
    assert m("  sel:\n    rule.id: 92052\n  condition: sel\n")[0]
    assert m("  sel:\n    agent.ip|cidr: 10.0.0.0/24\n  condition: sel\n")[0]
    assert not m("  sel:\n    agent.ip|cidr: 192.168.0.0/16\n  condition: sel\n")[0]
    assert m("  sel:\n    CommandLine|re: '-[eE][nN][cC]\\s'\n  condition: sel\n")[0]
    assert not m("  sel:\n    CommandLine|re: '-ENC'\n  condition: sel\n")[0]
    assert m("  sel:\n    CommandLine|re|i: '-ENC'\n  condition: sel\n")[0]


def test_keywords_and_list_of_maps():
    assert m("  kw:\n    - 'SQBFAFgA'\n  condition: kw\n")[0]
    assert m("  sel:\n    - agent.name: nope\n    - agent.name: WS01\n  condition: sel\n")[0]


def test_base64_and_offset_and_wide():
    cmd = "IEX (New-Object Net.WebClient)"
    wide = base64.b64encode(cmd.encode("utf-16-le")).decode()
    ev = {"CommandLine": "powershell -enc " + wide}
    assert m("  sel:\n    CommandLine|wide|base64offset|contains: 'New-Object'\n  condition: sel\n", ev=ev)[0]
    assert not m("  sel:\n    CommandLine|base64offset|contains: 'New-Object'\n  condition: sel\n", ev=ev)[0]
    ev2 = {"CommandLine": "x " + base64.b64encode(b"hello world").decode()}
    assert m("  sel:\n    CommandLine|base64|contains: 'hello world'\n  condition: sel\n", ev=ev2)[0]


def test_windash_and_field_map():
    ev = {"proc": {"cmd": "net user /add bob"}}
    det = "  sel:\n    CommandLine|windash|contains: ' -add '\n  condition: sel\n"
    assert not m(det, ev=ev)[0]
    ok, used = m(det, ev=ev, fmap={"CommandLine": ["proc.cmd"]})
    assert ok and used == {"CommandLine": "proc.cmd"}


def test_condition_list_and_fields():
    r = compile_rule(rule("  a: {X: 1}\n  b: {Y: 2}\n  condition: [a, b]\n"))
    assert r.match({"Y": 2})[0] and not r.match({"Z": 3})[0]
    assert r.fields() == ["X", "Y"]
