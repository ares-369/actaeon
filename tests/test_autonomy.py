import json

import pytest

from actaeon import config
from actaeon.bridges.server import ToolInputError
from actaeon.bridges.web import WebBridge, leak_check
from actaeon.hunt import service
from actaeon.intel.web import WebIntel, parse_feed
from actaeon.providers.base import LLMResult
from actaeon.providers.cli import CliProvider, flatten
from tests.conftest import write_cfg

RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Campaign A</title><link>https://news.example/a</link><description>C2 at hxxp://bad-a[.]example T1105</description></item>
<item><title>Patch notes</title><link>https://news.example/b</link><description>Nothing to see</description></item>
</channel></rss>"""
ATOM = """<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>t</title>
<entry><title>Atom item</title><link rel="alternate" href="https://news.example/c"/><summary>T1059.001 seen</summary></entry></feed>"""


def test_parse_feeds():
    assert [i["title"] for i in parse_feed(RSS)] == ["Campaign A", "Patch notes"]
    assert parse_feed(ATOM)[0]["link"] == "https://news.example/c"
    from actaeon.intel.fetch import FetchError
    with pytest.raises(FetchError):
        parse_feed('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><rss/>')


def fake_fetch(pages):
    def f(url, allow_private=False):
        if url not in pages:
            from actaeon.intel.fetch import FetchError
            raise FetchError("nope")
        body = pages[url]
        if body.lstrip().startswith("<?xml"):
            return {"url": url, "title": "", "text": body, "raw": body}
        return {"url": url, "title": "Article", "text": body}
    return f


def test_web_intel_pull_dedupes_and_filters(tmp_path):
    from actaeon.intel import IntelStore
    st = IntelStore(tmp_path / "i.sqlite")
    pages = {"https://news.example/feed": RSS, "https://news.example/a": "More: 203.0.113.77 used for C2.",
             "https://news.example/b": "Release notes."}
    w = WebIntel(st, {"sources": [{"name": "news", "url": "https://news.example/feed", "keywords": ["c2"]}]},
                 fetch=fake_fetch(pages))
    r = w.pull()
    assert len(r["new_advisories"]) == 1 and r["skipped"] == 1
    adv = st.advisory(r["new_advisories"][0]["id"])
    assert {"bad-a.example", "203.0.113.77"} <= {i["value"] for i in adv["indicators"]} and "T1105" in adv["techniques"]
    assert w.pull()["new_advisories"] == []          # remembered
    r = WebIntel(st, {"sources": [{"name": "Bad Name", "url": "x"}]}, fetch=fake_fetch(pages)).pull()
    assert r["errors"]


def test_web_intel_auto_hunt(home, monkeypatch):
    import actaeon.intel.web as wmod
    pages = {"https://news.example/feed": RSS, "https://news.example/a": "203.0.113.77", "https://news.example/b": "x"}
    monkeypatch.setattr(wmod, "fetch_url", fake_fetch(pages))
    write_cfg(home, lambda d: d["intel"]["web"].update(auto_hunt=True, sources=[
        {"name": "news", "url": "https://news.example/feed"}]))
    cfg = config.load_config()
    started = []
    monkeypatch.setattr(service, "start_hunt", lambda jobs, cfg, hyp, **kw: started.append((hyp, kw["origin"])) or "h1")
    r = service.run_web_intel(cfg, jobs=object())
    assert len(r["new_advisories"]) == 2 and len(started) == 1      # only the advisory with indicators/techniques
    assert started[0][1].startswith("advisory:") and "Campaign A" in started[0][0]


@pytest.mark.parametrize("text", ["10.1.2.3 beacon", "user@corp.example", "host ws-1234 example corp", "WS-1234"])
def test_leak_check_refuses(text):
    with pytest.raises(ToolInputError):
        import re
        leak_check(text, ["example corp"], [re.compile(r"\bWS-\d{4}\b")])


def test_leak_check_allows_public():
    leak_check("8.8.8.8 CVE-2024-3400 beacon loader", ["example corp"])


def test_web_bridge(monkeypatch):
    class S:
        def get(self, url, params=None, **kw):
            assert params["format"] == "json"
            class R:
                status_code = 200

                def json(self):
                    return {"results": [{"title": "T", "url": "https://x.example", "content": "snippet"}]}
            return R()
    b = WebBridge("https://search.example/search", ["corp"], session=S(),
                  fetch=fake_fetch({"https://x.example": "page text"}))
    srv = b.build()
    assert set(srv.tools) == {"fetch_page", "search_web"}
    assert b.search_web({"query": "CVE-2024-3400"})["results"][0]["url"] == "https://x.example"
    assert b.fetch_page({"url": "https://x.example"})["text"] == "page text"
    with pytest.raises(ToolInputError):
        b.search_web({"query": "corp vpn"})
    assert set(WebBridge("").build().tools) == {"fetch_page"}


def test_web_connector_only_when_enabled(home):
    from actaeon.connectors import get_hub
    assert "web" not in get_hub(config.get_config(reload=True), reload=True).specs
    write_cfg(home, lambda d: (d["intel"]["web"].update(tools=True, search_url="https://s.example/search"),
                               d["privacy"].update(terms=["corp.example"])))
    spec = get_hub(config.load_config(), reload=True).specs["web"]
    assert spec.roles == ["intel"] and "--block-term" in spec.args and "corp.example" in spec.args


# ---- autopilot ----
class GenLLM:
    def __init__(self, reply):
        self.reply, self.seen = reply, []

    def for_role(self, role):
        outer = self

        class B:
            provider = type("P", (), {"name": "fake"})()
            model = "m"

            def chat(self, messages, **kw):
                outer.seen.append(messages)
                return LLMResult(text=json.dumps(outer.reply))
        return B()


def test_autopilot_propose_and_run(home, monkeypatch):
    write_cfg(home, lambda d: d.update(connectors=[{"name": "logs", "roles": ["log_search"], "transport": "stdio",
                                                    "command": "x"}]))
    cfg = config.load_config()
    from actaeon.intel import IntelStore
    IntelStore(cfg.data_dir / "intel.sqlite").add_advisory("Campaign Z", "uses 203.0.113.5 and T1105")
    llm = GenLLM({"hypotheses": [
        {"hypothesis": "A host contacted 203.0.113.5 (advisory 1) in the last 14 days.", "why": "new advisory",
         "attack": ["T1105", "bogus"], "roles": ["log_search"], "source": "advisory:1"},
        {"hypothesis": "Sign-ins from many countries for one account.", "roles": ["identity"], "source": "coverage"},
        {"hypothesis": "A host contacted 203.0.113.5 (advisory 1) in the last 14 days!", "roles": ["log_search"]},
    ]})
    started = []
    monkeypatch.setattr(service, "start_hunt", lambda jobs, cfg, hyp, **kw: started.append(kw) or f"h{len(started)}")
    r = service.run_autopilot(cfg, object(), llm=llm)
    assert [h["attack"] for h in r["hypotheses"]] == [["T1105"]]
    assert {x["rejected"] for x in r["rejected"]} == {"needs roles not connected: identity", "too similar to a recent hunt"}
    assert len(started) == 1 and started[0]["origin"] == "autopilot:advisory:1"
    assert "203.0.113.5" in started[0]["context"] and "new advisory" in started[0]["context"]
    prompt = llm.seen[0][1]["content"]
    assert "Campaign Z" in prompt and "UNTRUSTED-DATA" in prompt and "Coverage gaps" in prompt
    r = service.run_autopilot(cfg, object(), llm=llm, dry_run=True)
    assert r["started"] == [] and r["dry_run"]


def test_autopilot_needs_data_connector(home):
    r = service.run_autopilot(config.get_config(reload=True), object(), llm=GenLLM({}))
    assert r["hypotheses"] == [] and "no data connectors" in r["note"]


def test_autopilot_daily_cap(home, monkeypatch):
    write_cfg(home, lambda d: (d.update(connectors=[{"name": "logs", "roles": ["log_search"], "transport": "stdio",
                                                      "command": "x"}]), d["autopilot"].update(max_hunts_per_day=1)))
    cfg = config.load_config()
    service.store_for(cfg).create("earlier", origin="autopilot:coverage")
    monkeypatch.setattr(service, "start_hunt", lambda *a, **k: "x")
    llm = GenLLM({"hypotheses": [{"hypothesis": "Something new and testable here", "roles": ["log_search"]}]})
    assert service.run_autopilot(cfg, object(), llm=llm)["started"] == []


# ---- cli provider ----
def test_cli_provider(tmp_path):
    script = tmp_path / "fake-cli"
    script.write_text("#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in -p=*) printf '%s' \"${a#-p=}\" | tail -c 40;; esac; done\n")
    script.chmod(0o755)
    p = CliProvider({"command": [str(script), "--model", "{model}", "-p={prompt}"], "default_model": "m1",
                     "cwd": str(tmp_path)})
    r = p.chat([{"role": "system", "content": "sys"}, {"role": "user", "content": "hello there"}])
    assert not r.error and "hello there" in r.text
    bad = CliProvider({"command": ["/bin/sh", "-c", "echo boom >&2; exit 3"], "cwd": str(tmp_path)})
    assert "exit 3" in bad.chat([{"role": "user", "content": "x"}]).error
    assert CliProvider({}).chat([]).error


def test_flatten_fits_limit():
    msgs = [{"role": "system", "content": "S"}] + [{"role": "user", "content": "x" * 50_000} for _ in range(5)] + \
           [{"role": "user", "content": "LAST"}]
    out = flatten(msgs, 60_000)
    assert len(out.encode()) <= 60_000 and out.startswith("### SYSTEM") and "LAST" in out


class _Judge:
    """A reporter model that answers the relevance prompt with a fixed JSON reply."""

    def __init__(self, reply):
        self.reply, self.calls = reply, 0

    def for_role(self, role):
        outer = self

        class B:
            def chat(self, messages, **kw):
                outer.calls += 1
                return LLMResult(text=json.dumps(outer.reply))
        return B()


def test_relevance_terms_then_model(home):
    from actaeon.intel.relevance import assess
    write_cfg(home, lambda d: d.update(environment={"platforms": ["linux"], "products": ["nginx", "OpenSSH"]}))
    cfg = config.load_config()
    adv = {"title": "Exchange zero-day exploited", "text": "Microsoft Exchange servers attacked", "techniques": ["T1190"]}
    judge = _Judge({"relevant": True, "score": 90, "why": "x"})
    d = assess(cfg, adv, llm=judge)
    assert d["relevant"] is False and d["method"] == "terms" and judge.calls == 0     # no term: no model call
    adv = {"title": "OpenSSH flaw lets attackers run code", "text": "regreSSHion in OpenSSH on Linux servers"}
    judge = _Judge({"relevant": True, "score": 85, "why": "OpenSSH runs on the Linux hosts",
                    "products": ["OpenSSH"], "hypothesis": "sshd crashed or spawned an unusual child in the last 7 days"})
    d = assess(cfg, adv, llm=judge)
    assert d["relevant"] and d["method"] == "model" and d["matched"] == ["linux", "OpenSSH"] and "sshd" in d["hypothesis"]
    d = assess(cfg, {"title": "nginx funding round", "text": "nginx company raises money"},
               llm=_Judge({"relevant": False, "score": 5, "why": "business news"}))
    assert d["relevant"] is False and d["hypothesis"] == ""
    d = assess(cfg, {"title": "nginx bug", "text": "nginx"}, llm=_Judge({"relevant": True, "score": 30, "why": "weak"}))
    assert d["relevant"] is False                      # below min_score 50


def test_web_intel_hunts_only_relevant_and_records_ledger(home, monkeypatch):
    import actaeon.intel.web as wmod
    feed = """<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>OpenSSH bug exploited</title><link>https://news.example/s</link><description>OpenSSH attacks T1190</description></item>
<item><title>Windows driver flaw</title><link>https://news.example/w</link><description>Windows kernel T1068</description></item>
</channel></rss>"""
    pages = {"https://news.example/feed": feed, "https://news.example/s": "OpenSSH", "https://news.example/w": "Windows"}
    monkeypatch.setattr(wmod, "fetch_url", fake_fetch(pages))
    write_cfg(home, lambda d: (d["intel"]["web"].update(auto_hunt=True, sources=[
        {"name": "news", "url": "https://news.example/feed"}]), d.update(environment={"products": ["OpenSSH"]})))
    cfg = config.load_config()
    started = []
    monkeypatch.setattr(service, "start_hunt", lambda jobs, cfg, hyp, **kw: started.append(hyp) or "h-ssh")
    judge = _Judge({"relevant": True, "score": 80, "why": "OpenSSH runs here", "hypothesis": "sshd exploited here"})
    r = service.run_web_intel(cfg, jobs=object(), llm=judge)
    assert started == ["sshd exploited here"] and judge.calls == 1          # the Windows item never reached the model
    ledger = {a["title"]: a for a in service.intel_for(cfg).advisories()}
    assert ledger["OpenSSH bug exploited"]["hunt_id"] == "h-ssh" and ledger["OpenSSH bug exploited"]["relevance"]["relevant"]
    assert ledger["Windows driver flaw"]["relevance"]["relevant"] is False and ledger["Windows driver flaw"]["hunt_id"] == ""
    assert {x["relevant"] for x in r["relevance"]} == {True, False}
