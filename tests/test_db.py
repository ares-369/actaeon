"""Storage layer: SQLite by default; the PostgreSQL adapter's translation is checked here without a server.
The whole suite runs against a real PostgreSQL in CI (ACTAEON_DB_URL)."""
import sqlite3

import pytest

from actaeon import db


def test_default_is_sqlite(tmp_path, monkeypatch):
    monkeypatch.delenv("ACTAEON_DB_URL", raising=False)
    db.configure("")
    assert not db.is_pg() and db.kind() == "sqlite"
    c = db.connect(tmp_path / "x.sqlite")
    assert isinstance(c, sqlite3.Connection) and c.row_factory is sqlite3.Row


@pytest.mark.parametrize("sql,want", [
    ("SELECT * FROM t WHERE a=? AND b=?", "SELECT * FROM t WHERE a=%s AND b=%s"),
    ("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, n INTEGER NOT NULL)",
     "CREATE TABLE t (id BIGSERIAL PRIMARY KEY, n BIGINT NOT NULL)"),
    ("SELECT * FROM i WHERE value LIKE ? OR note NOT LIKE ?", "SELECT * FROM i WHERE value ILIKE %s OR note NOT ILIKE %s"),
    ("INSERT INTO lead_events (lead_id, ts, user, action) VALUES (?,?,?,?)",
     'INSERT INTO lead_events (lead_id, ts, "user", action) VALUES (%s,%s,%s,%s)'),
    ("SELECT * FROM conversations WHERE user=? AND username=?",
     'SELECT * FROM conversations WHERE "user"=%s AND username=%s'),
    ("SELECT '50%? done' AS x, 3 % 2", "SELECT '50%%? done' AS x, 3 %% 2"),
    ("ALTER TABLE jobs ADD COLUMN control TEXT DEFAULT 'run'", "ALTER TABLE jobs ADD COLUMN control TEXT DEFAULT 'run'"),
])
def test_translate(sql, want):
    assert db.translate(sql) == want


def test_row_and_split():
    r = db.Row(["a", "b"], (1, "x"))
    assert r[0] == 1 and r["b"] == "x" and dict(r) == {"a": 1, "b": "x"} and r.keys() == ["a", "b"]
    with pytest.raises(IndexError):
        r["c"]
    assert db._split("CREATE TABLE a (x TEXT DEFAULT ';');\n CREATE TABLE b (y INTEGER);  ") == [
        "CREATE TABLE a (x TEXT DEFAULT ';')", "CREATE TABLE b (y INTEGER)"]
    assert db._params((True, False, 3, "s")) == (1, 0, 3, "s")


def test_configure_checks():
    with pytest.raises(ValueError):
        db.configure("mysql://x")
    with pytest.raises(ValueError):
        db.configure("postgresql://h/d", schema="Bad-Schema")
    db.configure("")


def test_schema_per_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTAEON_DB_SCHEMA_PER_DIR", "1")
    a, b = db._schema_for(tmp_path / "a" / "x.sqlite"), db._schema_for(tmp_path / "b" / "x.sqlite")
    assert a != b and a == db._schema_for(tmp_path / "a" / "y.sqlite") and a.startswith("t_")


def test_config_database_section(home, monkeypatch):
    from actaeon import config
    monkeypatch.delenv("ACTAEON_DB_URL", raising=False)
    config.get_config(reload=True)
    assert db.kind() == "sqlite"
    p = home / "config.yaml"
    p.write_text(p.read_text().replace('  url: ""\n  schema: actaeon', '  url: "postgresql://u:${DBPW}@h/d"\n'
                                       '  schema: soc', 1))
    monkeypatch.setenv("DBPW", "pw")
    try:
        config.get_config(reload=True)
        assert db.url() == "postgresql://u:pw@h/d" and db._settings["schema"] == "soc"
    finally:
        db.configure("")


def test_init_postgres_writes_env(tmp_path, monkeypatch, capsys):
    from actaeon import cli
    monkeypatch.setenv("ACTAEON_HOME", str(tmp_path))
    monkeypatch.delenv("ACTAEON_DB_URL", raising=False)
    monkeypatch.setenv("ACTAEON_DB_TIMEOUT", "1")
    try:
        rc = cli.cmd_init(database="postgres", db_url="postgresql://u:secret@127.0.0.1:1/none")
    finally:
        db.configure("")
    env = (tmp_path / ".env").read_text()
    assert "ACTAEON_DB_URL=postgresql://u:secret@127.0.0.1:1/none" in env
    assert oct((tmp_path / ".env").stat().st_mode)[-3:] == "600"
    assert rc == 1 and "could not connect" in capsys.readouterr().out     # nothing listens there
    assert "u:secret@" not in (tmp_path / "config.yaml").read_text()
