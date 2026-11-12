import pytest

from actaeon import __version__, cli


def test_version(capsys):
    cli.cli_main(["version"])
    assert capsys.readouterr().out.strip() == __version__


def test_init(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTAEON_HOME", str(tmp_path / "h"))
    assert cli.cmd_init() == 0
    assert (tmp_path / "h" / "config.yaml").exists()
    assert "ACTAEON_SECRET_KEY=" in (tmp_path / "h" / ".env").read_text()


def test_models(home, capsys):
    with pytest.raises(SystemExit):
        cli.cli_main(["models"])
    assert "planner" in capsys.readouterr().out


def test_connectors_cli(home, capsys):
    import sys
    from pathlib import Path

    from tests.conftest import write_cfg
    fake = str(Path(__file__).parent / "fixtures" / "fake_mcp.py")
    write_cfg(home, lambda d: d.update(connectors=[{
        "name": "fake", "roles": ["intel"], "transport": "stdio", "command": sys.executable, "args": [fake]}]))
    from actaeon import config
    config.get_config(reload=True)
    with pytest.raises(SystemExit) as e:
        cli.cli_main(["connectors", "test"])
    assert e.value.code == 0 and "4/6 tools allowed" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.cli_main(["connectors", "tools", "fake"])
    assert "BLOCK isolate_host" in capsys.readouterr().out
