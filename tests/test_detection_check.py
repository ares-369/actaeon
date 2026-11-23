import json
from datetime import datetime, timezone

import pytest

from actaeon import config
from actaeon.soc import detection_check as dc
from actaeon.soc.alerts import normalize
from actaeon.soc.store import SocStore

T = {"name": "scan", "target": "10.9.0.2", "source": "10.9.0.5", "started": "2026-01-05T10:00:00+00:00",
     "finished": "2026-01-05T10:05:00+00:00"}


def raw(n, ts, ip="10.9.0.5", rule="100"):
    return {"id": f"a{n}", "timestamp": ts, "rule": {"id": rule, "level": 10, "description": f"rule {rule}"},
            "data": {"srcip": ip}}


class Hub:
    def __init__(self, items=(), error=False):
        self.items, self.error, self.args = list(items), error, []

    def call(self, name, tool, args, **kw):
        self.args.append(args)
        if self.error:
            raise RuntimeError("down")
        return {"content": json.dumps({"hits": self.items}), "is_error": False, "truncated": False}


@pytest.fixture
def env(home):
    cfg = config.get_config(reload=True)
    cfg.soc.intake.sources = [{"connector": "logs", "tool": "search", "name": "logs", "arguments": {"query": "x"}}]
    return cfg, SocStore(home / "s.sqlite", scratch=True)


def run(env, hub, t=T, **kw):
    return dc.check(env[0], env[1], hub, dc.load_run(json.dumps(t)), **kw)["tests"][0]


def test_layers(env):
    _cfg, store = env
    hit = raw(1, "2026-01-05T10:02:00+00:00")
    assert run(env, Hub())["layer"] == "missed"
    r = run(env, Hub([hit]))
    assert r["layer"] == "source" and r["first_min"] == 2.0
    a = normalize(hit, source="logs")
    store.add_alert(a, status="suppressed")
    r = run(env, Hub([hit]))
    assert r["layer"] == "alert" and "suppressed" in r["note"]
    cid = store.new_case("c", 60, "medium", a["ts"])
    store.attach(cid, a)
    store.set_case(cid, verdict="true_positive")
    r = run(env, Hub([hit]))
    assert r["layer"] == "case" and r["verdict"] == "true_positive"


def test_background_other_addresses_and_late_alerts_do_not_count(env):
    before, during = raw(1, "2026-01-05T09:55:00+00:00"), raw(2, "2026-01-05T10:02:00+00:00")
    r = run(env, Hub([before, during]))
    assert r["layer"] == "missed" and r["background"]
    assert run(env, Hub([raw(3, "2026-01-05T10:02:00+00:00", ip="10.9.0.77")]))["layer"] == "missed"
    assert run(env, Hub([raw(4, "2026-01-05T10:40:00+00:00")]))["layer"] == "missed"


def test_a_failed_lookup_or_test_is_unknown_not_missed(env):
    assert run(env, Hub(error=True))["layer"] == "unknown"
    assert run(env, Hub([raw(i, "2026-01-05T10:02:00+00:00") for i in range(dc.PAGE)]))["layer"] == "unknown"
    assert run(env, Hub(), {**T, "status": "error: no route"})["layer"] == "unknown"
    t = datetime.now(timezone.utc).isoformat()
    r = run(env, Hub(), {**T, "started": t, "finished": t})
    assert r["layer"] == "unknown" and "too early" in r["note"]


def test_query_override_and_report(env):
    hub = Hub([raw(1, "2026-01-05T10:02:00+00:00")])
    res = dc.check(env[0], env[1], hub, dc.load_run(json.dumps([T])), query="level:>=3")
    assert hub.args[0]["query"] == "level:>=3" and hub.args[0]["time_to"].startswith("2026-01-05T10:15")
    md = dc.markdown(res)
    assert "1 of 1 scored" in md and "0 in an Actaeon case" in md
    with pytest.raises(ValueError):
        dc.load_run(json.dumps({"target": "x"}))
