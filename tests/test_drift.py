"""Inventory drift: baseline, no change, new items, new hosts, cut-off hosts, ignore rules."""
import json
import re

import pytest

from actaeon import config
from actaeon.hunt import drift, service


class InvHub:
    """A fake inventory source: top_values lists hosts, search returns each host's ports (compacted)."""

    def __init__(self, inv, totals=None):
        self.inv, self.totals, self.calls = inv, totals or {}, []

    def call(self, conn, tool, args, **kw):
        self.calls.append((tool, args))
        if tool == "top_values":
            body = {"buckets": [{"value": h, "count": len(v)} for h, v in self.inv.items()]}
        else:
            host = args["query"].split('"')[1]
            rows = [{"source": {"port": p}, "process": {"name": n}} for p, n in self.inv.get(host, [])]
            body = {"total": self.totals.get(host, len(rows)), "common": {"host": {"name": host}}, "hits": rows}
        return {"content": "<<UNTRUSTED-DATA a source=x>>\n" + json.dumps(body) + "\n<<END-UNTRUSTED-DATA a>>",
                "is_error": False}


TARGET = {"name": "ports", "connector": "inv", "index": "inv-ports", "host_field": "host.name",
          "item_fields": ["source.port", "process.name"], "ignore": ["^6[0-9]{4} "]}


def setup(home, target=TARGET):
    cfg = config.get_config(reload=True)
    cfg.raw["drift"] = {"targets": [target]}
    return cfg


def test_validate_target():
    assert drift.validate_target(TARGET)["item_fields"] == ["source.port", "process.name"]
    for bad in ({**TARGET, "name": "Bad Name"}, {**TARGET, "item_fields": []}, {**TARGET, "ignore": ["("]},
                {k: v for k, v in TARGET.items() if k != "host_field"}):
        with pytest.raises((ValueError, re.error)):
            drift.validate_target(bad)


def test_rows_expand_compacted_hits():
    r = drift.rows({"common": {"host": {"name": "a"}}, "hits": [{"source.port": 22}, {"source": {"port": 80}}]})
    assert r == [{"host.name": "a", "source.port": 22}, {"host.name": "a", "source.port": 80}]


def test_baseline_then_changes(home):
    cfg = setup(home)
    inv = {"web01": [(22, "sshd"), (443, "nginx")], "db01": [(5432, "postgres")]}
    st = service.store_for(cfg)
    h1 = drift.run(cfg, InvHub(inv), st)[0]
    assert h1["outcome"] == "no_results" and "Baseline" in h1["verdict"]["summary"]
    h2 = drift.run(cfg, InvHub(inv), st)[0]
    assert h2["outcome"] == "no_results" and "Nothing new" in h2["verdict"]["summary"]
    inv2 = {"web01": [(22, "sshd"), (4444, "nc"), (61000, "ephemeral")], "db01": [(5432, "postgres")],
            "new01": [(22, "sshd")]}
    h3 = drift.run(cfg, InvHub(inv2), st)[0]
    claims = [f["claim"] for f in h3["verdict"]["findings"]]
    assert h3["outcome"] == "inconclusive" and h3["verdict"]["needs_review"]
    assert "New on web01: 4444 | nc" in claims                      # the planted listener
    assert not any("61000" in c for c in claims)                     # ignored by the rule
    assert any(c.startswith("New host in the inventory: new01") for c in claims)
    assert "disappeared" in h3["verdict"]["summary"]                 # 443 went away
    ev = h3["verdict"]["findings"][0]["evidence"][0]
    assert any(f"E{s['n']}" == ev and s["kind"] == "call" for s in st.get(h3["id"])["steps"])


def test_cut_off_host_is_not_compared(home):
    cfg = setup(home)
    st = service.store_for(cfg)
    drift.run(cfg, InvHub({"a": [(22, "sshd")]}), st)
    h = drift.run(cfg, InvHub({"a": [(22, "sshd"), (80, "x")]}, totals={"a": 9999}), st)[0]
    assert h["verdict"]["findings"] == [] and "cut off" in h["verdict"]["gaps"][0] and h["verdict"]["needs_review"]


def test_unreadable_inventory_is_logs_missing(home):
    cfg = setup(home)
    h = drift.run(cfg, InvHub({}), service.store_for(cfg))[0]
    assert h["outcome"] == "logs_missing"


def test_service_cli_and_api(home, monkeypatch, capsys):
    cfg = setup(home)
    monkeypatch.setattr(service, "_hub", lambda c, hub=None: hub or InvHub({"web01": [(22, "sshd")]}))
    h = service.run_drift(cfg)
    assert h["id"] and h["origin"] == "drift:ports"
    p = home / "config.yaml"
    import yaml
    d = yaml.safe_load(p.read_text())
    d["drift"] = {"targets": [TARGET]}
    p.write_text(yaml.safe_dump(d))
    config.get_config(reload=True)
    from actaeon import cli
    with pytest.raises(SystemExit):
        cli.cli_main(["drift", "status"])
    assert "ports" in capsys.readouterr().out
    from actaeon.web import create_app
    c = create_app(config.get_config(reload=True)).test_client()
    r = c.get("/api/drift").json
    assert r["targets"][0]["name"] == "ports" and r["runs"]


def test_truncated_result_is_incomplete(home):
    cfg = setup(home)
    st = service.store_for(cfg)

    class Trunc(InvHub):
        def call(self, conn, tool, args, **kw):
            r = super().call(conn, tool, args, **kw)
            if tool == "search":
                r["truncated"] = True
            return r
    drift.run(cfg, InvHub({"a": [(22, "sshd")]}), st)
    h = drift.run(cfg, Trunc({"a": [(22, "sshd")]}), st)[0]
    assert "cut off" in h["verdict"]["gaps"][0] and h["verdict"]["findings"] == []
