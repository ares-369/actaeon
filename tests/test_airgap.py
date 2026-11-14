"""Air-gapped use: nothing in the default setup or the offline demo opens a network connection.

The guard covers this process (web app, hunt engine, intel, reports). Connector bridges run as
child processes; in the demo they read in-memory sample data.
"""
import ipaddress
import re
import socket
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _local(host) -> bool:
    if host is None:
        return True
    h = str(host)
    if h in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(h.split("%")[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture
def no_network(monkeypatch):
    attempts = []
    real_connect, real_gai = socket.socket.connect, socket.getaddrinfo

    def connect(self, addr):
        if self.family in (socket.AF_INET, socket.AF_INET6) and not _local(addr[0]):
            attempts.append(addr)
            raise OSError(f"air-gap test: outbound connection to {addr} refused")
        return real_connect(self, addr)

    def gai(host, *a, **kw):
        if not _local(host):
            attempts.append(host)
            raise socket.gaierror(f"air-gap test: lookup of {host} refused")
        return real_gai(host, *a, **kw)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", gai)
    return attempts


def test_default_config_reaches_nothing_outside():
    cfg = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    assert cfg["intel"]["feeds"] == [] and cfg["intel"]["web"]["interval_minutes"] == 0
    assert cfg["intel"]["web"]["tools"] is False and cfg["intel"]["web"]["sources"] == []
    assert cfg["intel"]["web"]["auto_hunt"] is False and cfg["autopilot"]["interval_minutes"] == 0
    assert not cfg.get("outputs")
    for role in cfg["llm"]["roles"].values():
        assert role["provider"] == "ollama"
    assert re.match(r"https?://(localhost|127\.0\.0\.1)", cfg["llm"]["providers"]["ollama"]["base_url"])


def test_ui_loads_nothing_from_outside():
    pages = [ROOT / "actaeon/templates/index.html", ROOT / "actaeon/static/app.js", ROOT / "actaeon/static/app.css"]
    for p in pages:
        text = p.read_text()
        assert not re.search(r"(src|href)\s*=\s*[\"']https?://", text), p
        assert not re.search(r"url\(\s*[\"']?https?://", text), p
        assert not re.search(r"\b(fetch|import)\(\s*[\"'`]https?://", text), p
    css = (ROOT / "actaeon/static/mdi/css/icons.css").read_text()
    assert not re.search(r"url\(\s*[\"']?https?://", css)


def test_offline_demo_and_ui_make_no_connections(tmp_path, monkeypatch, capsys, no_network):
    from actaeon import cli
    from actaeon import config as c
    from actaeon.connectors import hub as h
    monkeypatch.delenv("ACTAEON_CONFIG", raising=False)
    try:
        cli.cmd_demo(type("A", (), {"dir": str(tmp_path / "demo"), "offline": True, "run": True, "port": 8611})())
        assert "verdict: threat" in capsys.readouterr().out
        monkeypatch.setenv("ACTAEON_HOME", str(tmp_path / "demo"))
        monkeypatch.setenv("ACTAEON_CONFIG", str(tmp_path / "demo" / "config.yaml"))
        c._CONFIG, h._HUB = None, None
        from actaeon.web import create_app
        client = create_app(c.load_config()).test_client()
        hunts = client.get("/api/hunts").json
        hid = (hunts["hunts"] if isinstance(hunts, dict) else hunts)[0]["id"]
        for path in ("/", "/api/library", "/api/intel/stats", "/api/coverage", "/api/leads", "/api/intel/export.stix",
                     f"/api/hunts/{hid}", f"/api/hunts/{hid}/stix", f"/api/hunts/{hid}/report.md",
                     f"/api/hunts/{hid}/export.csv"):
            assert client.get(path).status_code == 200, path
    finally:
        c._CONFIG, h._HUB = None, None
    assert no_network == []


def test_guard_works(no_network):
    with pytest.raises(OSError):
        socket.create_connection(("192.0.2.1", 443), timeout=1)
    assert no_network
