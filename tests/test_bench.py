from actaeon.bench import DEMO_CASES, load_cases, score


def test_score():
    rs = [{"outcome": "threat", "expect": ["threat"], "correct": True},
          {"outcome": "threat", "expect": ["no_results"], "correct": False},
          {"outcome": "no_results", "expect": ["threat"], "correct": False},
          {"outcome": "no_results", "expect": ["no_results"], "correct": True}]
    s = score(rs)
    assert s["accuracy"] == 0.5 and s["threat_precision"] == 0.5 and s["threat_recall"] == 0.5


def test_cases(tmp_path):
    assert len(DEMO_CASES) == 8 and load_cases(None) is DEMO_CASES
    f = tmp_path / "c.yaml"
    f.write_text("- id: a\n  hypothesis: h\n  expect: [threat]\n")
    assert load_cases(str(f))[0]["id"] == "a"
    f.write_text("- id: a\n")
    import pytest
    with pytest.raises(ValueError):
        load_cases(str(f))


def test_demo_has_spray():
    from actaeon.bridges.demo import DemoBridge
    b = DemoBridge()
    r = b.top_values({"index": "demo-events", "time_from": "now-7d", "field": "source.ip", "query": "event.outcome:failure"})
    assert r["buckets"][0]["value"] == "198.51.100.200" and r["buckets"][0]["count"] == 14
