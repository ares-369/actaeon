"""Hunt packs, connector contract check, STIX export, taxii output, bench model overrides."""
import json
import re

import pytest
import yaml

from actaeon import config
from actaeon.hunt.packs import PackError, builtin_dir, load_all, load_dir, validate

GOOD = {"id": "my-hunt", "name": "My hunt", "attack": ["T1059.001"], "roles": ["endpoint"],
        "hypothesis": "A script host started an encoded command on a server in the last 7 days."}


# ---- hunt packs ----
def test_builtin_pack_is_valid():
    hunts = load_dir(builtin_dir())
    assert len(hunts) >= 60 and len({h["id"] for h in hunts}) == len(hunts)
    for h in hunts:
        assert re.fullmatch(r"[a-z0-9-]+", h["id"])
        assert h["pack"] in {"collection", "command-and-control", "credential-access", "defense-impairment",
                             "discovery", "execution", "exfiltration", "impact", "initial-access", "lateral-movement",
                             "persistence", "privilege-escalation", "stealth", "reconnaissance", "resource-development"}


@pytest.mark.parametrize("change,msg", [
    ({"id": "Bad Id"}, "id must"), ({"attack": ["T1002"]}, "attack"), ({"roles": ["siem"]}, "unknown roles"),
    ({"references": ["http://x.example"]}, "https"), ({"query": "x"}, "unknown keys"),
    ({"hypothesis": "short"}, "20-1000"), ({"platforms": ["amiga"]}, "platforms"), ({"attack": []}, "attack is required"),
])
def test_validate_rejects(change, msg):
    with pytest.raises(PackError, match=msg):
        validate({**GOOD, **change}, filename="my-hunt.yaml")


def test_validate_filename_must_match():
    with pytest.raises(PackError, match="file name"):
        validate(GOOD, filename="other.yaml")
    assert validate(GOOD, filename="my-hunt.yaml")["id"] == "my-hunt"


def test_library_dirs_add_and_override(home):
    d = home / "hunts"
    d.mkdir()
    (d / "my-hunt.yaml").write_text(yaml.safe_dump(GOOD))
    first = load_dir(builtin_dir())[0]
    (d / f"{first['id']}.yaml").write_text(yaml.safe_dump({**{k: first[k] for k in GOOD}, "name": "Replaced"}))
    (d / "broken.yaml").write_text("id: broken\n")
    cfg = config.get_config(reload=True)
    cfg.raw.setdefault("hunt", {})["library_dirs"] = [str(d)]
    hunts = {h["id"]: h for h in load_all(cfg)}
    assert "my-hunt" in hunts and hunts[first["id"]]["name"] == "Replaced" and "broken" not in hunts


def test_validate_cli(tmp_path, capsys):
    from actaeon.cli import cmd_validate_pack
    assert cmd_validate_pack(None) == 0
    (tmp_path / "my-hunt.yaml").write_text(yaml.safe_dump(GOOD))
    assert cmd_validate_pack(str(tmp_path)) == 0
    (tmp_path / "x.yaml").write_text(yaml.safe_dump({**GOOD, "id": "x-hunt"}))
    assert cmd_validate_pack(str(tmp_path)) == 1
    assert cmd_validate_pack(str(tmp_path / "missing")) == 1
    assert "FAIL" in capsys.readouterr().out


# ---- connector contract ----
def test_contract_check(tmp_path):
    from actaeon.connectors.contract import check
    from tests.test_connectors import make_hub, stdio_spec
    hub = make_hub(tmp_path, stdio_spec())
    try:
        res = check(hub, "fake")
        levels = {r["check"]: r["level"] for r in res}
        assert levels["connect and list tools"] == "OK"
        assert levels["read-only hints"] == "WARN"          # get_host, flaky, ... have no readOnlyHint
        assert levels["input schemas are JSON objects"] == "OK"
        assert any(r["check"] == "blocked by policy" and "isolate_host" in r["detail"] for r in res)
        assert not any(r["level"] == "FAIL" for r in res)
    finally:
        hub.close()


def test_contract_check_fails_on_dead_connector(tmp_path):
    from actaeon.connectors.contract import check
    from tests.test_connectors import make_hub, stdio_spec
    hub = make_hub(tmp_path, stdio_spec(command="/nonexistent/binary"))
    try:
        assert check(hub, "fake")[0]["level"] == "FAIL"
    finally:
        hub.close()


def test_connector_template_passes_check(tmp_path):
    import sys
    from pathlib import Path

    from actaeon.connectors.contract import check
    from actaeon.connectors.spec import parse_connectors
    from tests.test_connectors import make_hub
    tpl = Path(__file__).resolve().parents[1] / "docs" / "templates" / "connector_template.py"
    spec = parse_connectors([{"name": "tpl", "roles": ["log_search"], "transport": "stdio", "command": sys.executable,
                              "args": [str(tpl)], "query_notes": "plain text search"}])[0]
    hub = make_hub(tmp_path, spec)
    try:
        res = check(hub, "tpl")
        assert [r for r in res if r["level"] != "OK"] == []
        out = hub.call("tpl", "search", {"query": "x", "time_from": "2026-11-01T00:00:00+00:00"})
        assert '"total": 1' in out["content"]
    finally:
        hub.close()


# ---- STIX ----
def test_stix_patterns_and_stable_ids(tmp_path):
    from actaeon.intel import IntelStore
    from actaeon.intel.stix import export_store, pattern
    assert pattern("sha256", "AB" * 32) == f"[file:hashes.'SHA-256' = '{'ab' * 32}']"
    assert pattern("url", "http://x.example/a'b") == "[url:value = 'http://x.example/a\\'b']"
    assert pattern("technique", "T1059") is None
    s = IntelStore(tmp_path / "i.sqlite")
    s.add("203.0.113.9", tags=["c2"], confidence=80)
    s.add("bad.example")
    s.add("CVE-2024-3400")
    s.add("T1059.001")
    b1, b2 = export_store(s), export_store(s)
    types = sorted(o["type"] for o in b1["objects"])
    assert types == ["attack-pattern", "identity", "indicator", "indicator", "vulnerability"]
    assert [o["id"] for o in b1["objects"]] == [o["id"] for o in b2["objects"]] and b1["id"] != b2["id"]
    ind = next(o for o in b1["objects"] if o["type"] == "indicator" and "ipv4" in o["pattern"])
    assert ind["confidence"] == 80 and ind["labels"] == ["c2"] and ind["valid_from"].endswith("Z")
    assert len(export_store(s, tag="c2")["objects"]) == 2


def test_stix_roundtrip_through_importer(tmp_path):
    from actaeon.intel import IntelStore
    from actaeon.intel.feeds import import_file
    from actaeon.intel.stix import export_store
    a = IntelStore(tmp_path / "a.sqlite")
    for v in ("203.0.113.9", "bad.example", "d41d8cd98f00b204e9800998ecf8427e"):
        a.add(v)
    f = tmp_path / "b.json"
    f.write_text(json.dumps(export_store(a)))
    b = IntelStore(tmp_path / "b.sqlite")
    import_file(b, str(f), fmt="stix")
    assert {r["value"] for r in b.list()} == {"203.0.113.9", "bad.example", "d41d8cd98f00b204e9800998ecf8427e"}


def _threat_hunt():
    return {"id": "h1", "hypothesis": "beacon", "outcome": "threat", "created": "2026-11-14T10:00:00+00:00",
            "finished": "2026-11-14T10:05:00+00:00",
            "verdict": {"confidence": 85, "summary": "beacon to 203.0.113.66", "attack": ["T1071.001"],
                        "findings": [{"claim": "DEMO-WS07 beacons to update-check.example (203.0.113.66)",
                                      "evidence": ["E3"]}]}}


def test_hunt_bundle():
    from actaeon.intel.stix import hunt_bundle
    b = hunt_bundle(_threat_hunt())
    rep = next(o for o in b["objects"] if o["type"] == "report")
    pats = [o["pattern"] for o in b["objects"] if o["type"] == "indicator"]
    assert any("203.0.113.66" in p for p in pats) and any("update-check.example" in p for p in pats)
    assert len(rep["object_refs"]) == len(b["objects"]) - 2 and rep["confidence"] == 85
    empty = hunt_bundle({"id": "h2", "hypothesis": "x", "verdict": {}})
    assert [o["type"] for o in empty["objects"]] == ["identity"]


def test_taxii_output(home):
    from actaeon.outputs import dispatch
    from actaeon.outputs import validate as validate_outputs
    cfg = config.get_config(reload=True)
    cfg.raw["outputs"] = [{"name": "tip", "type": "taxii", "when": ["threat"], "min_confidence": 70,
                           "url": "https://tip.example/taxii2/api1/collections/c1/objects/",
                           "headers": {"Authorization": "Bearer ${TIP_TOKEN}"}}]
    validate_outputs(cfg.raw["outputs"])

    class S:
        def __init__(self):
            self.posts = []

        def post(self, url, data=None, headers=None, **kw):
            self.posts.append((url, json.loads(data), headers))
            return type("R", (), {"status_code": 202})()
    s = S()
    r = dispatch(cfg, _threat_hunt(), session=s)
    assert r[0]["ok"] and "STIX objects" in r[0]["detail"]
    url, body, headers = s.posts[0]
    assert url.endswith("/collections/c1/objects/")
    assert headers["Content-Type"] == "application/taxii+json;version=2.1" and body["objects"]
    low = {**_threat_hunt(), "verdict": {**_threat_hunt()["verdict"], "confidence": 40}}
    assert "skipped" in dispatch(cfg, low, session=s)[0]["detail"]


def test_stix_api(home):
    from actaeon.web import create_app
    c = create_app(config.get_config(reload=True)).test_client()
    r = c.get("/api/intel/export.stix")
    assert r.status_code == 200 and r.json["type"] == "bundle"
    assert c.get("/api/hunts/nope/stix").status_code == 404


# ---- bench model overrides ----
def test_bench_model_overrides(home):
    from actaeon.bench import markdown_row, parse_model, with_models
    cfg = config.get_config(reload=True)
    cfg.llm["roles"]["analyst"]["fallback"] = [{"provider": "ollama", "model": "x"}]
    assert parse_model("ollama/qwen3:32b") == {"provider": "ollama", "model": "qwen3:32b"}
    assert parse_model("openai_compatible/org/model")["model"] == "org/model"
    with pytest.raises(ValueError):
        parse_model("nope/model")
    c2 = with_models(cfg, "anthropic/m1", ["analyst=gemini/m2"])
    assert c2.role_cfg("planner") == {"provider": "anthropic", "model": "m1"}
    assert c2.role_cfg("analyst") == {"provider": "gemini", "model": "m2"}
    assert cfg.llm["roles"]["analyst"].get("fallback")              # original untouched
    assert with_models(cfg) is cfg
    with pytest.raises(ValueError):
        with_models(cfg, role_models=["boss=ollama/x"])
    row = markdown_row({"score": {"cases": 8, "correct": 7, "threat_precision": 1.0, "threat_recall": 0.75,
                                  "false_positives": 0, "seconds": 800, "tokens_in": 400000, "tokens_out": 8000,
                                  "cost_usd": None},
                        "models": {r: {"provider": "ollama", "model": "q"} for r in ("planner", "analyst")},
                        "when": "2026-11-14T00:00:00", "actaeon": "0.1.0b1", "cases_file": "built-in demo cases"})
    assert row.startswith("| ollama/q | built-in demo cases | 7/8 | 1.00 | 0.75 | 0 | 100 s | 51k | n/a |")
