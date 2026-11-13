import sqlite3

import pytest

from actaeon.bridges.server import ToolInputError
from actaeon.bridges.sql import SqlBridge, check_sql


@pytest.fixture()
def db(tmp_path):
    p = tmp_path / "logs.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE alerts (id INTEGER, host TEXT, title TEXT)")
    c.executemany("INSERT INTO alerts VALUES (?,?,?)", [(i, f"h{i % 3}", "x" * (5 if i else 3000)) for i in range(300)])
    c.execute("CREATE TABLE secrets (k TEXT)")
    c.commit()
    c.close()
    return p


@pytest.mark.parametrize("sql", [
    "DELETE FROM alerts", "SELECT 1; DROP TABLE alerts", "UPDATE alerts SET host='x'",
    "WITH x AS (SELECT 1) INSERT INTO alerts SELECT * FROM x", "ATTACH DATABASE 'x' AS y", "PRAGMA writable_schema=1",
    "SELECT * FROM alerts INTO OUTFILE '/tmp/x'", "", "CREATE TABLE z(a)",
])
def test_refused(sql):
    with pytest.raises(ToolInputError):
        check_sql(sql)


def test_allowed_shapes():
    assert check_sql("select host, count(*) from alerts group by host;") .startswith("select")
    assert check_sql("SELECT 'a; DROP TABLE x' AS s")          # inside a string literal is fine
    assert check_sql("SELECT replace(host, 'h', '') FROM alerts -- update later")


def test_sqlite_tools(db):
    b = SqlBridge(f"sqlite:///{db}", max_rows=50)
    assert b.list_tables({})["tables"] == ["alerts", "secrets"]
    d = b.describe_table({"table": "alerts", "sample": 2})
    assert d["columns"]["host"] == "TEXT" and len(d["sample"]) == 2 and d["sample"][0]["title"].endswith("(cut)")
    q = b.query({"sql": "SELECT * FROM alerts"})
    assert q["returned"] == 50 and q["truncated"]
    assert b.query({"sql": "SELECT host, COUNT(*) n FROM alerts GROUP BY host ORDER BY host"})["rows"][0] == ["h0", 100]
    with pytest.raises(ToolInputError):
        b.describe_table({"table": "alerts; drop"})


def test_sqlite_is_read_only_even_past_the_checks(db):
    b = SqlBridge(f"sqlite:///{db}")
    with pytest.raises(sqlite3.DatabaseError):
        b.conn().execute("DELETE FROM alerts")
    assert b.query({"sql": "SELECT COUNT(*) FROM alerts"})["rows"] == [[300]]


def test_table_allow_list(db):
    b = SqlBridge(f"sqlite:///{db}", tables=["alerts"])
    assert b.list_tables({})["tables"] == ["alerts"]
    with pytest.raises(ToolInputError):
        b.query({"sql": "SELECT * FROM secrets"})
    with pytest.raises(ToolInputError):
        b.query({"sql": "SELECT a.id FROM alerts a JOIN secrets s ON 1=1"})
