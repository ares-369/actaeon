"""benchmarks/excytin/analyze.py: misses sorted by cause from stored traces."""
import json
import sys
from pathlib import Path

from actaeon.hunt.store import HuntStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks" / "excytin"))
import analyze


def trace(tmp_path, name, question, results):
    d = tmp_path / name
    st = HuntStore(d / "hunts.sqlite")
    hid = st.create(question[:200], origin="excytin")
    for n, (ok, text) in enumerate(results, 1):
        st.add_step(hid, n, "call", connector="incident_logs", tool="query", ok=ok, result=text)
    return str(d)


def test_causes(tmp_path):
    qdir = tmp_path / "q"
    qdir.mkdir()
    qs = [{"question": f"question {i}?", "answer": a} for i, a in enumerate(
        ["10.1.2.3", "evil.example", "MB-DC1", "x", "y", "SYSTEM"])]
    (qdir / "incident_7_qa_incident_x.json").write_text(json.dumps(qs))
    t = [trace(tmp_path, "t0", qs[0]["question"], [(True, "seen 10.1.2.3 here")]),
         trace(tmp_path, "t1", qs[1]["question"], [(True, "nothing"), (False, "evil.example error")]),
         trace(tmp_path, "t2", qs[2]["question"], [(True, "host MB-DC10 only")]),
         trace(tmp_path, "t5", qs[5]["question"], [(True, "user SYSTEM")])]
    res = [{"incident": "incident_7", "index": 0, "reward": 0.0, "calls": 3, "trace": t[0]},
           {"incident": "incident_7", "index": 1, "reward": 0.0, "calls": 2, "trace": t[1]},
           {"incident": "incident_7", "index": 2, "reward": 0.0, "calls": 25, "trace": t[2]},
           {"incident": "incident_7", "index": 3, "reward": 0.0, "calls": 2, "error": "429 RESOURCE_EXHAUSTED"},
           {"incident": "incident_7", "index": 4, "reward": 0.0, "calls": 2, "error": "MALFORMED_FUNCTION_CALL"},
           {"incident": "incident_7", "index": 5, "reward": 0.0, "calls": 25, "trace": t[3]}]
    q = analyze.load_questions(str(qdir))
    got = [analyze.classify(r, q[(r["incident"], r["index"])], r.get("trace"), 25) for r in res]
    assert [g["cause"] for g in got] == ["retrieved, missed", "never retrieved", "out of calls (never retrieved)",
                                         "service error", "malformed call", "out of calls (retrieved)"]
    assert got[5]["weak_match"] and not got[0]["weak_match"]
    assert got[1]["failed_calls"] == 1     # a failed call's text never counts as retrieved
