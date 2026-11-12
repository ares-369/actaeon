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
