import json

import pytest

from actaeon import config
from actaeon.soc import floor
from actaeon.soc.intake import ingest
from actaeon.soc.service import triage_case
from tests.conftest import write_cfg
from tests.soc_fakes import FakeHub, FakeLLM
from tests.test_soc import ALERT, call, cfg_store, run_case, verdict

WIN = {"name": "weekly", "source": "10.20.30.4", "target": "203.0.113.5", "started": "2026-11-01T09:55:00+00:00",
       "finished": "2026-11-01T10:20:00+00:00"}


def limits(verdict_="true_positive"):
    return lambda d: d["soc"].update(never_dismiss=[{"rule": "R1", "verdict": verdict_, "reason": "decoy"}],
                                     authorised_tests="tests.jsonl")


def put(home, *wins):
    (home / "data").mkdir(exist_ok=True)
    (home / "data" / "tests.jsonl").write_text("not json\n" + "\n".join(json.dumps(w) for w in wins) + "\n")


def llm(v="benign"):
    return FakeLLM([call(), verdict(v)])


@pytest.mark.parametrize("to", ["true_positive", "needs_analyst"])
def test_the_model_cannot_dismiss_a_listed_rule(home, to):
    c, _ = run_case(home, llm(), FakeHub(), limits(to))
    assert c["verdict"] == to and c["report"]["floor"] == "R1" and "decoy" in c["summary"]
    assert any("the analysis said benign" in x for x in c["report"]["checks"])


def test_other_rules_and_real_verdicts_are_untouched(home):
    c, _ = run_case(home, llm(), FakeHub(), lambda d: d["soc"].update(never_dismiss=[{"rule": "OTHER"}]))
    assert c["verdict"] == "benign" and "floor" not in c["report"]


def test_a_real_verdict_is_not_changed(home):
    c, _ = run_case(home, llm("true_positive"), FakeHub(), limits())
    assert "floor" not in c["report"]


def test_a_recorded_test_is_labelled_and_left_open(home):
    put(home, WIN)
    c, _ = run_case(home, llm("true_positive"), FakeHub(),
                    lambda d: (limits()(d), d["soc"].update(auto_close_confidence=50)), manual=False)
    assert c["report"]["authorised_test"] == "weekly" and c["verdict"] == "benign" and c["status"] == "triaged"


@pytest.mark.parametrize("change", [{"source": "10.20.30.99"}, {"target": "203.0.113.6"},
                                    {"finished": "2026-11-01T09:59:00+00:00"}, {"finished": "2026-11-02T10:00:00+00:00"},
                                    {"target": ""}])
def test_an_address_alone_is_never_enough(home, change):
    put(home, {**WIN, **change})
    c, _ = run_case(home, llm(), FakeHub(), limits())
    assert "authorised_test" not in c["report"] and c["verdict"] == "true_positive"


def test_one_foreign_alert_spoils_the_label(home):
    put(home, WIN)
    cfg, store = cfg_store(home, lambda d: (limits()(d), d["soc"].update(verify=False)))
    foreign = {**ALERT, "id": "a2", "source": {"ip": "10.20.30.66"}}
    cid = ingest(cfg, store, [ALERT, foreign])["cases_opened"][0]               # same host: one case
    c = triage_case(cfg, cid, llm=llm(), hub=FakeHub(), store=store, manual=True)
    assert "authorised_test" not in c["report"] and c["verdict"] == "true_positive"


def test_an_alert_after_the_label_opens_its_own_case(home):
    put(home, WIN)
    cfg, store = cfg_store(home, lambda d: (limits()(d), d["soc"].update(verify=False)))
    cid = ingest(cfg, store, [ALERT])["cases_opened"][0]
    assert triage_case(cfg, cid, llm=llm(), hub=FakeHub(), store=store, manual=True)["report"]["authorised_test"]
    out = ingest(cfg, store, [{**ALERT, "id": "a2", "source": {"ip": "10.20.30.66"}}])
    assert len(out["cases_opened"]) == 1 and out["cases_opened"] != [cid]


def test_an_alert_that_joins_a_labelled_case_removes_the_label(home):
    # Addresses only in free text: the fingerprint is rule + host, so another attacker's alert joins the test's case.
    def decoy(n, ip, ts):
        return {"id": n, "@timestamp": ts, "rule": {"id": "R1", "name": "Decoy hit", "level": 12}, "host": {"name": "decoy"},
                "full_log": f"decoy 203.0.113.5 probed by {ip}"}
    put(home, WIN)
    cfg, store = cfg_store(home, lambda d: (limits()(d), d["soc"].update(verify=False)))
    cid = ingest(cfg, store, [decoy("t1", "10.20.30.4", "2026-11-01T10:00:00Z")])["cases_opened"][0]

    def triage():
        return triage_case(cfg, cid, llm=llm(), hub=FakeHub(), store=store, manual=True)
    assert triage()["report"]["authorised_test"] == "weekly"
    ingest(cfg, store, [decoy("t2", "10.20.30.4", "2026-11-01T10:05:00Z")])          # more of the same test
    assert store.get_case(cid)["status"] == "triaged"
    ingest(cfg, store, [decoy("x1", "10.20.30.66", "2026-11-01T10:06:00Z")])         # someone else
    c = store.get_case(cid)
    assert c["status"] == "new" and not c["verdict"] and not c["report"].get("authorised_test")
    c = triage()
    assert c["verdict"] == "true_positive" and "authorised_test" not in c["report"]


def test_bad_settings_are_refused(home):
    for bad in ({"never_dismiss": [{"verdict": "x"}]}, {"never_dismiss": [{"rule": "a", "verdict": "benign"}]},
                {"authorised_tests": "../etc/x"}):
        write_cfg(home, lambda d, bad=bad: d["soc"].update(never_dismiss=[], authorised_tests="") or d["soc"].update(bad))
        with pytest.raises(ValueError):
            config.load_config()
    assert floor.windows(type("C", (), {"soc": type("S", (), {"authorised_tests": ""})()})()) == []
