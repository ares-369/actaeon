import json

import pytest

from actaeon import config
from actaeon.bridges.local_intel import build
from actaeon.intel import IntelStore, extract
from actaeon.intel.extract import guess_type, refang
from actaeon.intel.feeds import import_file, parse, pull_feed, validate_feed
from actaeon.web import create_app

ADVISORY = """Actor used hxxps://evil-cdn[.]example/payload.exe and 198.51.100[.]23 for C2.
Dropper invoice.docx (sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08)
md5 d41d8cd98f00b204e9800998ecf8427e. Contact: ops[@]bad-mail.example. Exploits CVE-2024-3400.
Techniques: T1566.001, T1059 and T1071.001. Not an IOC: 999.1.1.1 or report.pdf"""


def test_extract_advisory():
    f = extract(ADVISORY)
    assert f["url"] == ["https://evil-cdn.example/payload.exe"]
    assert "evil-cdn.example" in f["domain"] and "bad-mail.example" in f["domain"]
    assert f["ipv4"] == ["198.51.100.23"]
    assert f["sha256"] and f["md5"] == ["d41d8cd98f00b204e9800998ecf8427e"]
    assert f["email"] == ["ops@bad-mail.example"]
    assert f["cve"] == ["CVE-2024-3400"]
    assert f["technique"] == ["T1566.001", "T1059", "T1071.001"]
    assert "invoice.docx" not in f.get("domain", []) and "report.pdf" not in f.get("domain", [])
    assert "999.1.1.1" not in f.get("ipv4", [])


@pytest.mark.parametrize("v,t", [("1.2.3.4", "ipv4"), ("Example.COM", "domain"), ("CVE-2021-44228", "cve"),
                                 ("a" * 64, "sha256"), ("hxxp://x[.]example/a", "url"), ("T1003.001", "technique"),
                                 ("hello", None), ("file.exe", None), ("2001:db8::1", "ipv6")])
def test_guess_type(v, t):
    assert guess_type(v) == t


def test_ipv6_noise():
    assert extract("at 10:30:00 from :: and 2001:db8::1") == {"ipv6": ["2001:db8::1"]}


def test_refang():
    assert refang("hxxps://a(.)b[.]c") == "https://a.b.c"


def test_store_ledger(tmp_path):
    s = IntelStore(tmp_path / "i.sqlite")
    assert s.add("Evil.Example")["status"] == "new"
    r = s.add("evil.example", source="feed:x", confidence=80, tags=["c2"])
    assert r["status"] == "updated"
    row = s.lookup("EVIL.example")["matches"][0]
    assert row["seen_count"] == 2 and row["confidence"] == 80 and row["tags"] == ["c2"]
    assert row["source"] == "manual,feed:x"
    assert s.lookup("www.evil.example")["related"][0]["value"] == "evil.example"
    with pytest.raises(ValueError):
        s.add("not an indicator")
    assert s.deactivate(row["id"]) and s.list() == []


def test_changed_since(tmp_path):
    s = IntelStore(tmp_path / "i.sqlite")
    s.add("1.2.3.4")
    assert s.list(changed_since="2999-01-01") == []
    assert len(s.list(changed_since="2000-01-01")) == 1


def test_advisory(tmp_path):
    s = IntelStore(tmp_path / "i.sqlite")
    r = s.add_advisory("Campaign X", ADVISORY, confidence=70)
    a = s.advisory(r["advisory_id"])
    assert a["techniques"] == ["T1566.001", "T1059", "T1071.001"] and a["cves"] == ["CVE-2024-3400"]
    assert {i["value"] for i in a["indicators"]} >= {"198.51.100.23", "evil-cdn.example"}
    assert f"advisory:{r['advisory_id']}" in a["indicators"][0]["tags"]
    assert s.stats()["advisories"] == 1


def test_parse_formats():
    assert parse("# c\n1.2.3.4 comment\n\nevil.example\n", "text") == ["1.2.3.4", "evil.example"]
    assert parse("ioc,kind\n1.2.3.4,ip\n", "csv", value_field="ioc") == ["1.2.3.4"]
    assert parse("1.2.3.4,x\n5.6.7.8,y\n", "csv") == ["1.2.3.4", "5.6.7.8"]
    bundle = {"objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.5'] OR "
                                                          "[file:hashes.'SHA-256' = '" + "b" * 64 + "']"}]}
    assert parse(json.dumps(bundle), "stix") == ["203.0.113.5", "b" * 64]
    doc = {"vulnerabilities": [{"cveID": "CVE-2024-1"}, {"cveID": "CVE-2024-2"}]}
    assert parse(json.dumps(doc), "json", list_key="vulnerabilities", value_field="cveID") == ["CVE-2024-1", "CVE-2024-2"]
    with pytest.raises(ValueError):
        parse("{}", "json", list_key="nope")


def test_import_file(tmp_path):
    s = IntelStore(tmp_path / "i.sqlite")
    f = tmp_path / "iocs.txt"
    f.write_text("1.2.3.4\nnot-valid\nevil.example\n")
    r = import_file(s, str(f), "text", confidence=60)
    assert (r["new"], r["skipped"]) == (2, 1)


def test_pull_feed(tmp_path):
    class R:
        text = "1.2.3.4\n5.6.7.8\n"

        def raise_for_status(self):
            pass

    class S:
        def get(self, url, **kw):
            return R()
    s = IntelStore(tmp_path / "i.sqlite")
    r = pull_feed(s, {"name": "f1", "url": "https://feed.example/x.txt", "tags": ["feed"]}, session=S())
    assert r["new"] == 2 and s.list(tag="feed")
    with pytest.raises(ValueError):
        validate_feed({"name": "Bad", "url": "https://x"})
    with pytest.raises(ValueError):
        validate_feed({"name": "ok", "url": "file:///etc/passwd"})


def test_bridge_is_read_only(tmp_path):
    s = IntelStore(tmp_path / "i.sqlite")
    s.add("1.2.3.4", confidence=90)
    srv = build(s)
    names = set(srv.tools)
    assert names == {"lookup", "list_indicators", "list_advisories", "get_advisory", "extract_indicators", "intel_stats"}
    from actaeon.connectors.policy import looks_write
    assert not any(looks_write(t.describe()) for t in srv.tools.values())
    r = srv.handle({"id": 1, "method": "tools/call", "params": {"name": "lookup", "arguments": {"value": "1.2.3.4"}}})
    assert r["result"]["structuredContent"]["found"]
    r = srv.handle({"id": 2, "method": "tools/call", "params": {"name": "list_indicators",
                                                                "arguments": {"min_confidence": 95}}})
    assert r["result"]["structuredContent"]["count"] == 0


def test_hub_has_local_intel(home):
    from actaeon.connectors import get_hub
    hub = get_hub(config.get_config(reload=True))
    assert "local-intel" in hub.specs
    IntelStore(home / "data" / "intel.sqlite").add("203.0.113.7")
    names = {t["name"] for t in hub.tools_for_role("intel")}
    assert "lookup" in names
    out = hub.call("local-intel", "lookup", {"value": "203.0.113.7"})
    assert '"found": true' in out["content"]


def test_local_intel_can_be_off(home):
    from tests.conftest import write_cfg
    write_cfg(home, lambda d: d["intel"].update(local=False))
    from actaeon.connectors import get_hub
    assert "local-intel" not in get_hub(config.load_config(), reload=True).specs


def test_intel_api(home):
    c = create_app(config.get_config(reload=True)).test_client()
    assert c.post("/api/intel/indicators", json={"text": ADVISORY, "preview": True}).json["found"]["cve"]
    r = c.post("/api/intel/indicators", json={"text": "1.2.3.4 and evil.example", "confidence": 70, "tags": "a,b"}).json
    assert r["new"] == 2
    r = c.post("/api/intel/indicators", json={"values": ["5.6.7.8", "junk"]}).json
    assert len(r["added"]) == 1 and r["errors"]
    assert c.get("/api/intel/lookup?value=evil.example").json["found"]
    a = c.post("/api/intel/advisories", json={"title": "T", "text": ADVISORY}).json
    assert c.get(f"/api/intel/advisories/{a['advisory_id']}").json["title"] == "T"
    assert c.post("/api/intel/advisories", json={"title": "x"}).status_code == 400
    assert c.get("/api/intel/stats").json["indicators"] >= 3
    assert c.post("/api/intel/feeds/none/pull").status_code == 404


def test_viewer_cannot_add_intel(home, monkeypatch):
    import base64

    from tests.conftest import write_cfg
    write_cfg(home, lambda d: d["auth"].update(mode="basic", default_role="viewer"))
    monkeypatch.setenv("ACTAEON_AUTH_PASSWORD", "pw")
    h = {"Authorization": "Basic " + base64.b64encode(b"actaeon:pw").decode()}
    c = create_app(config.load_config()).test_client()
    assert c.post("/api/intel/indicators", json={"values": ["1.2.3.4"]}, headers=h).status_code == 403
    assert c.get("/api/intel/stats", headers=h).status_code == 200


def test_bad_feed_fails_config(home):
    from tests.conftest import write_cfg
    write_cfg(home, lambda d: d["intel"].update(feeds=[{"name": "x", "url": "ftp://nope"}]))
    with pytest.raises(ValueError):
        config.load_config()


def test_strict_links_keep_only_defanged(tmp_path):
    s = IntelStore(tmp_path / "i.sqlite")
    text = ("See https://publisher.example/advisories and https://reference.example/doc for details. "
            "C2: hxxps://evil-c2[.]example/gate and bad-drop[.]example, mail lure[@]phish.example, "
            "IP 198.51.100.99, hash " + "c" * 64 + ". T1105")
    r = s.add_advisory("Adv", text, url="https://www.publisher.example/adv/1", strict_links=True)
    vals = {i["value"] for i in s.advisory(r["advisory_id"])["indicators"]}
    assert {"https://evil-c2.example/gate", "evil-c2.example", "bad-drop.example", "lure@phish.example",
            "198.51.100.99", "c" * 64, "T1105"} <= vals
    assert not any("publisher.example" in v or "reference.example" in v for v in vals)
    assert "https://reference.example/doc" in r["skipped_links"]
    r2 = s.add_advisory("Manual", "https://reference.example/doc")   # not strict: analyst text kept as is
    assert s.advisory(r2["advisory_id"])["indicators"]
