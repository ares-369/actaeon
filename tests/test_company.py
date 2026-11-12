import yaml

from actaeon import config
from actaeon.company import init_company
from actaeon.doctor import run as doctor
from tests.conftest import write_cfg


def test_init_company(tmp_path):
    files = init_company(str(tmp_path / "corp"), name="Corp SOC")
    assert {"config.yaml", ".env.example", ".env", "README.md", "notes/logs.md", "docker-compose.override.yml",
            ".gitignore"} <= set(files)
    cfg = yaml.safe_load((tmp_path / "corp" / "config.yaml").read_text())
    assert cfg["auth"]["mode"] == "oidc" and cfg["hunt"]["verify"] is True
    assert cfg["connectors"][0]["tools"]["deny"] and cfg["outputs"][0]["type"] == "email"
    assert ".env" in (tmp_path / "corp" / ".gitignore").read_text()
    import pytest
    with pytest.raises(FileExistsError):
        init_company(str(tmp_path / "corp"))


def levels(rows, area):
    return {r["level"] for r in rows if r["area"] == area}


def test_doctor_flags_problems(home):
    rows = doctor(config.get_config(reload=True), offline=True)
    assert "FAIL" in levels(rows, "connectors")            # no data connector
    assert "WARN" in levels(rows, "outputs") and "WARN" in levels(rows, "models")
    write_cfg(home, lambda d: (d.update(connectors=[{"name": "logs", "roles": ["log_search"], "transport": "stdio",
                                                     "command": "actaeon", "args": ["bridge", "demo"],
                                                     "query_notes": "fields..."}]),
                               d["llm"]["roles"]["analyst"].update(provider="gemini"),
                               d["privacy"].update(mask_for=["anthropic"])))
    rows = doctor(config.load_config())
    msgs = " ".join(r["message"] for r in rows)
    assert "logs: " in msgs and "list_indices read OK" in msgs
    assert "prompts to gemini are not masked" in msgs


def test_connector_form_api(home):
    from actaeon.web import create_app
    c = create_app(config.get_config(reload=True)).test_client()
    new = {"name": "edr", "roles": ["endpoint"], "transport": "http", "url": "https://edr-mcp.example/mcp",
           "auth": {"type": "bearer", "token_env": "EDR_TOKEN"}, "dialect": "", "query_notes": ""}
    r = c.post("/api/settings/connectors", json={"connector": new, "preview": True}).json
    assert r["changed"] and "edr-mcp.example" in r["diff"]
    assert "connectors" not in yaml.safe_load((home / "config.yaml").read_text()) or not \
        yaml.safe_load((home / "config.yaml").read_text())["connectors"]
    assert c.post("/api/settings/connectors", json={"connector": new}).json["changed"]
    saved = yaml.safe_load((home / "config.yaml").read_text())["connectors"]
    assert saved[0]["name"] == "edr" and "dialect" not in saved[0]          # empty fields left out
    assert any(x["name"] == "edr" for x in c.get("/api/connectors").json)
    bad = dict(new, auth={"type": "bearer", "token": "plaintext"})
    assert c.post("/api/settings/connectors", json={"connector": bad}).status_code == 400
    assert c.post("/api/settings/connectors", json={"remove": "edr"}).json["changed"]


def test_doctor_cli_exit_code(home, capsys):
    import pytest

    from actaeon import cli
    with pytest.raises(SystemExit) as e:
        cli.cli_main(["doctor", "--offline"])
    assert e.value.code == 1 and "FAIL connectors" in capsys.readouterr().out
