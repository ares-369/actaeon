import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from actaeon.bridges.openapi import OpenApiBridge
from actaeon.bridges.search_index import SearchIndexBridge
from actaeon.bridges.server import McpServer, ToolInputError
from actaeon.bridges.taxii import TaxiiBridge
from actaeon.connectors import ConnectorHub, parse_connectors
from actaeon.connectors.audit import AuditLog


class Resp:
    def __init__(self, data, status=200):
        self.status_code, self._d = status, data
        self.text = json.dumps(data)
        self.content = self.text.encode()

    def json(self):
        return self._d


class FakeSession:
    def __init__(self, routes):
        self.routes, self.calls, self.headers = routes, [], {}

    def _hit(self, method, url, **kw):
        self.calls.append((method, url, kw))
        for key, val in self.routes.items():
            if key in url:
                return Resp(val(kw) if callable(val) else val)
        return Resp({"error": "nope"}, 404)

    def get(self, url, **kw):
        return self._hit("GET", url, **kw)

    def post(self, url, **kw):
        return self._hit("POST", url, **kw)


# ---- MCP server core ----
def test_server_core():
    s = McpServer("t")
    s.tool("echo", "e", {"type": "object"})(lambda a: {"got": a})

    def bad(a):
        raise ToolInputError("nope")
    s.tool("bad", "b", {"type": "object"})(bad)
    assert s.handle({"id": 1, "method": "initialize"})["result"]["serverInfo"]["name"] == "t"
    assert s.handle({"method": "notifications/initialized"}) is None
    assert [t["name"] for t in s.handle({"id": 2, "method": "tools/list"})["result"]["tools"]] == ["echo", "bad"]
    r = s.handle({"id": 3, "method": "tools/call", "params": {"name": "echo", "arguments": {"x": 1}}})["result"]
    assert r["structuredContent"] == {"got": {"x": 1}}
    assert s.handle({"id": 4, "method": "tools/call", "params": {"name": "bad"}})["result"]["isError"]
    assert "error" in s.handle({"id": 5, "method": "tools/call", "params": {"name": "zzz"}})
    assert "error" in s.handle({"id": 6, "method": "sampling/createMessage"})


# ---- search index ----
def si(routes, **kw):
    return SearchIndexBridge("https://idx.example", ["events-*"], session=FakeSession(routes), **kw)


def test_search_builds_bounded_query():
    b = si({"_search": {"hits": {"total": {"value": 3}, "hits": [{"_index": "events-1", "_id": "a",
                                                                   "_source": {"x": 1}}]}}})
    out = b.search({"index": "events-*", "query": "process.name:cmd.exe", "size": 9999, "time_from": "now-2d"})
    assert out["total"] == 3 and out["hits"][0]["x"] == 1
    body = b.http.calls[0][2]["json"]
    assert body["size"] == 500
    assert "range" in body["query"]["bool"]["filter"][0]
    assert body["query"]["bool"]["must"][0]["query_string"]["query"] == "process.name:cmd.exe"


@pytest.mark.parametrize("args", [
    {"index": "secret-index"},
    {"index": "events-*,other"},
    {"index": "_all"},
    {"index": "events-1/../x"},
    {"index": "events-1", "time_from": "now-90d"},
    {"index": "events-1", "time_from": "now", "time_to": "now-1h"},
    {"index": "events-1", "dsl": {"script": {"source": "x"}}},
    {"index": "events-1", "dsl": {"bool": {"filter": [{"script_score": {}}]}}},
])
def test_search_guards(args):
    with pytest.raises(ToolInputError):
        si({}).search(args)


def test_top_values_and_fields():
    b = si({"_search": {"aggregations": {"v": {"buckets": [{"key": "a", "doc_count": 2}], "sum_other_doc_count": 0}}},
            "_mapping": {"events-1": {"mappings": {"properties": {"host": {"properties": {"name": {"type": "keyword"}}},
                                                                 "@timestamp": {"type": "date"}}}}}})
    t = b.top_values({"index": "events-1", "field": "host.name", "rare": True})
    assert t["buckets"] == [{"value": "a", "count": 2}] and t["order"] == "rarest"
    assert b.http.calls[0][2]["json"]["aggs"]["v"]["terms"]["order"] == {"_count": "asc"}
    assert b.get_fields({"index": "events-1"})["fields"]["host.name"] == "keyword"
    with pytest.raises(ToolInputError):
        b.top_values({"index": "events-1", "field": "a b"})


def test_first_seen_compares_with_baseline():
    def agg(kw):
        terms = [f for f in kw["json"]["query"]["bool"]["filter"] if "terms" in f]
        buckets = ([{"key": "old.exe", "doc_count": 40}] if terms else
                   [{"key": "old.exe", "doc_count": 50}, {"key": "new.exe", "doc_count": 1}])
        return {"aggregations": {"v": {"buckets": buckets}}}
    b = si({"_search": agg})
    out = b.first_seen({"index": "events-1", "field": "process.name", "time_from": "now-1d", "baseline_days": 7})
    assert out["new"] == [{"value": "new.exe", "count": 1}] and out["recent_values"] == 2
    base = b.http.calls[1][2]["json"]["query"]["bool"]["filter"]
    assert base[1] == {"terms": {"process.name": ["old.exe", "new.exe"]}}
    with pytest.raises(ToolInputError):
        b.first_seen({"index": "events-1", "field": "process.name", "time_from": "now-20d", "baseline_days": 20})


def test_demo_first_seen():
    from actaeon.bridges.demo import DemoBridge
    out = DemoBridge().first_seen({"index": "demo-events", "field": "process.name", "time_from": "now-2d",
                                    "baseline_days": 10})
    assert {"value": "schtasks.exe", "count": 1} in out["new"]


def test_list_indices_filtered():
    b = si({"_cat/indices": [{"index": "events-1"}, {"index": "users"}, {"index": ".hidden"}]})
    assert [i["index"] for i in b.list_indices({})["indices"]] == ["events-1"]


def test_only_read_endpoints_called():
    b = si({"_search": {"hits": {"hits": []}}, "_count": {"count": 0}})
    b.search({"index": "events-1"})
    b.count({"index": "events-1"})
    for _m, url, _ in b.http.calls:
        assert url.endswith(("/_search", "/_count"))


# ---- TAXII ----
IND = {"type": "indicator", "id": "indicator--" + "0" * 8 + "-0000-0000-0000-" + "0" * 12, "name": "bad ip",
       "pattern": "[ipv4-addr:value = '203.0.113.9']", "valid_from": "2026-01-01T00:00:00Z"}


def test_taxii_flow():
    pages = {"n": 0}

    def objects(kw):
        pages["n"] += 1
        if pages["n"] == 1:
            return {"objects": [IND], "more": True, "next": "p2"}
        return {"objects": [{**IND, "pattern": "[domain-name:value = 'x.example']"}], "more": False}
    t = TaxiiBridge("https://taxii.example/api1", session=FakeSession({
        "/objects/": objects, "collections/": {"collections": [{"id": "c1", "title": "C", "can_read": True},
                                                              {"id": "c2", "can_read": False}]}}))
    assert [c["id"] for c in t.list_collections({})["collections"]] == ["c1"]
    r = t.find_indicator({"value": "203.0.113.9"})
    assert len(r["matches"]) == 1 and r["scanned"] == 2
    assert t.http.headers["Accept"].startswith("application/taxii+json")
    assert all(m == "GET" for m, _, _ in t.http.calls)


def test_taxii_guards():
    t = TaxiiBridge("https://t.example/", collections=["c1"], session=FakeSession({}))
    for args in ({"collection": "c9"}, {"collection": "c1", "type": "evil"}):
        with pytest.raises(ToolInputError):
            t.get_objects(args)
    with pytest.raises(ToolInputError):
        t.get_object({"collection": "c1", "id": "../../etc"})
    with pytest.raises(ToolInputError):
        t.find_indicator({"value": "a"})


# ---- OpenAPI ----
SPEC = {
    "openapi": "3.0.0", "info": {"title": "Demo"}, "servers": [{"url": "https://api.example/v1"}],
    "components": {"parameters": {"Lim": {"name": "limit", "in": "query", "schema": {"type": "integer"}}}},
    "paths": {
        "/hosts/{id}": {"get": {"operationId": "getHost", "parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]},
            "delete": {"operationId": "deleteHost"}},
        "/hosts": {"get": {"operationId": "listHosts", "parameters": [{"$ref": "#/components/parameters/Lim"}]},
                   "post": {"operationId": "createHost"}},
        "/search": {"post": {"operationId": "restSearch"}},
    },
}


def test_openapi_exposes_reads_only():
    b = OpenApiBridge(SPEC, allow_post=["restSearch"], session=FakeSession({"/hosts": {"ok": 1}, "/search": {"r": 1}}))
    assert set(b.collect()) == {"getHost", "listHosts", "restSearch"}
    assert b.ops["listHosts"]["schema"]["properties"]["limit"]["type"] == "integer"
    assert json.loads(b.call("getHost", {"id": "a/../../admin"})) == {"ok": 1}
    assert b.http.calls[0][1] == "https://api.example/v1/hosts/a%2F..%2F..%2Fadmin"
    b.call("restSearch", {"body": {"value": "x"}})
    assert b.http.calls[1][0] == "POST" and b.http.calls[1][2]["json"] == {"value": "x"}
    with pytest.raises(ToolInputError):
        b.call("getHost", {})


def test_openapi_include_and_limit():
    assert set(OpenApiBridge(SPEC, include=["list*"], session=FakeSession({})).collect()) == {"listHosts"}
    with pytest.raises(ValueError):
        OpenApiBridge(SPEC, max_tools=1, session=FakeSession({})).collect()
    with pytest.raises(ValueError):
        OpenApiBridge({"paths": {}}, session=FakeSession({}))


# ---- end to end: hub -> stdio bridge -> local HTTP index ----
class _Idx(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, data):
        b = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if urlparse(self.path).path == "/_cat/indices":
            assert parse_qs(urlparse(self.path).query)["format"] == ["json"]
            self._send([{"index": "events-2026"}])

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        assert self.headers.get("Authorization", "").startswith("Basic ")
        self._send({"hits": {"total": {"value": 1}, "hits": [{"_index": "events-2026", "_id": "1",
                                                             "_source": {"msg": "hello"}}]}})


def test_bridge_end_to_end(tmp_path, monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), _Idx)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("IDX_URL", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("IDX_PASS", "pw")
    spec = parse_connectors([{"name": "logs", "roles": ["log_search"], "transport": "stdio", "command": "actaeon",
                              "args": ["bridge", "search-index", "--url", "${IDX_URL}", "--index", "events-*"],
                              "env": {"BRIDGE_USERNAME": "u", "BRIDGE_PASSWORD": "${IDX_PASS}"},
                              "timeout_sec": 10, "rate_per_min": 6000}])[0]
    hub = ConnectorHub([spec], AuditLog(tmp_path / "a.sqlite"), sleep=lambda s: None)
    try:
        r = hub.test("logs")
        assert r["ok"] and r["allowed"] == r["tools"] == 6 and r["probe"] == "list_indices", r
        out = hub.call("logs", "search", {"index": "events-2026", "query": "msg:hello"})
        assert "hello" in out["content"] and not out["is_error"]
        bad = hub.call("logs", "search", {"index": "users"})
        assert bad["is_error"] and "outside the allowed" in bad["content"]
    finally:
        hub.close()
        srv.shutdown()


def test_cli_has_bridges():
    import subprocess
    r = subprocess.run([sys.executable, "-m", "actaeon", "bridge", "--help"], capture_output=True, text=True)
    assert "search-index" in r.stdout and "taxii" in r.stdout and "openapi" in r.stdout


def test_connector_test_reads_the_source(tmp_path, monkeypatch):
    class Deny(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(401)
            self.end_headers()
    srv = HTTPServer(("127.0.0.1", 0), Deny)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    spec = parse_connectors([{"name": "logs", "roles": ["log_search"], "transport": "stdio", "command": "actaeon",
                              "args": ["bridge", "search-index", "--url", f"http://127.0.0.1:{srv.server_port}",
                                       "--index", "x-*"], "timeout_sec": 10}])[0]
    hub = ConnectorHub([spec], AuditLog(tmp_path / "a.sqlite"), sleep=lambda s: None)
    try:
        r = hub.test("logs")
        assert not r["ok"] and "401" in r["error"]
    finally:
        hub.close()
        srv.shutdown()


def test_snapshot_mode_no_time_bounds():
    b = SearchIndexBridge("https://idx.example", ["inventory-*"], session=FakeSession(
        {"_search": {"hits": {"total": {"value": 2}, "hits": [{"_index": "inventory-processes-x",
                                                               "_id": "a", "_source": {"process": {"name": "bash"}}}]}}}),
        snapshot=True)
    out = b.search({"index": "inventory-processes*", "query": "process.name:bash"})
    body = b.http.calls[0][2]["json"]
    assert "sort" not in body                                   # snapshot: no time sort
    assert all("range" not in str(f) for f in body["query"]["bool"].get("filter", []))   # no time range
    assert out["total"] == 2 and out["hits"][0]["process"]["name"] == "bash"
    with pytest.raises(ToolInputError):
        b.first_seen({"index": "inventory-processes*", "field": "process.name"})


def test_snapshot_tools_advertise_no_time_args():
    b = SearchIndexBridge("https://idx.example", ["inv-*"], session=FakeSession({}), snapshot=True)
    srv = b.build()
    out = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    tools = {t["name"]: t for t in out["result"]["tools"]}
    assert "first_seen" not in tools
    for name in ("search", "count", "top_values"):
        props = tools[name]["inputSchema"]["properties"]
        assert "time_from" not in props and "time_to" not in props, name


def test_bridge_now_pins_relative_times(monkeypatch):
    from actaeon.bridges.common import parse_time
    monkeypatch.setenv("BRIDGE_NOW", "2026-11-13T09:00:00Z")
    assert parse_time("now-7d", default="now").isoformat() == "2026-11-06T09:00:00+00:00"
    assert parse_time("", default="now").isoformat() == "2026-11-13T09:00:00+00:00"
    monkeypatch.delenv("BRIDGE_NOW")
    assert parse_time("now", default="now").year >= 2026
