"""SQL bridge: read-only queries over a SQLite file, MySQL/MariaDB or PostgreSQL.

Guards, all at once:
  - one statement only, and it must start with SELECT, WITH, SHOW, DESCRIBE or EXPLAIN
  - SQLite is opened read-only (``mode=ro``) and an authorizer refuses anything but reads
  - MySQL and PostgreSQL sessions are put in a read-only transaction with a statement timeout
  - rows are capped and long values cut
Use a read-only database account anyway.

URL forms: ``sqlite:///path/to.db``, ``mysql://user@host:3306/db``, ``postgresql://user@host/db``.
Passwords come from BRIDGE_PASSWORD (never the URL); MySQL needs the ``pymysql`` package and
PostgreSQL ``psycopg``.
"""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
from typing import Any
from urllib.parse import quote, unquote, urlparse

from .common import cap
from .server import McpServer, ToolInputError

_START = re.compile(r"^\s*(select|with|show|describe|desc|explain)\b", re.I)
_WRITE = re.compile(r"\b(insert|update|delete|merge|upsert|create|alter|drop|truncate|grant|revoke|"
                    r"attach|detach|pragma|vacuum|reindex|copy|load_file|into\s+outfile|into\s+dumpfile|"
                    r"call|exec|execute|lock|unlock|set|handler|load\s+data)\b", re.I)
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$.]{0,127}$")


def _strip_sql(sql: str) -> str:
    """The statement without comments and string literals (for the safety checks only)."""
    s = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    s = re.sub(r"(--|#)[^\n]*", " ", s)
    s = re.sub(r"'(?:''|\\.|[^'\\])*'", "''", s)
    s = re.sub(r'"(?:""|[^"])*"', '""', s)
    return s


def check_sql(sql: str) -> str:
    sql = (sql or "").strip().rstrip(";").strip()
    if not sql:
        raise ToolInputError("sql is required")
    bare = _strip_sql(sql)
    if ";" in bare:
        raise ToolInputError("one statement only")
    if not _START.match(bare):
        raise ToolInputError("only SELECT, WITH, SHOW, DESCRIBE or EXPLAIN statements are allowed")
    m = _WRITE.search(bare)
    if m:
        raise ToolInputError(f"read-only bridge: {m.group(1)!r} is not allowed")
    return sql


_READ_PRAGMAS = {"table_info", "table_xinfo", "index_list", "index_info"}


def _sqlite_authorizer(action, arg1=None, arg2=None, *_):
    if action == sqlite3.SQLITE_PRAGMA:
        return sqlite3.SQLITE_OK if str(arg1).lower() in _READ_PRAGMAS else sqlite3.SQLITE_DENY
    allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
    for name in ("SQLITE_RECURSIVE",):
        if hasattr(sqlite3, name):
            allowed.add(getattr(sqlite3, name))
    return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY


class SqlBridge:
    def __init__(self, url: str, max_rows: int = 200, max_cell: int = 2000, timeout_sec: int = 30,
                 tables: list[str] | None = None, connect=None):
        self.url, self.max_rows, self.max_cell, self.timeout = url, max_rows, max_cell, timeout_sec
        self.allowed = [t.lower() for t in tables or []]
        u = urlparse(url)
        self.kind = {"sqlite": "sqlite", "mysql": "mysql", "mariadb": "mysql", "postgres": "postgresql",
                     "postgresql": "postgresql"}.get(u.scheme)
        if not self.kind:
            raise ValueError("url must start with sqlite://, mysql:// or postgresql://")
        self._connect = connect
        self._conn = None

    # ---- connections ----
    def conn(self):
        if self._conn is not None:
            return self._conn
        if self._connect:
            self._conn = self._connect()
            return self._conn
        u = urlparse(self.url)
        if self.kind == "sqlite":
            path = "/" + os.path.normpath(unquote(self.url[len("sqlite://"):])).lstrip("/")   # sqlite:///abs -> /abs
            if not os.path.isfile(path):
                raise ToolInputError(f"database file not found: {path}")
            c = sqlite3.connect(f"file:{quote(path)}?mode=ro", uri=True, check_same_thread=False)
            c.set_authorizer(_sqlite_authorizer)
            self._conn = c
        elif self.kind == "mysql":
            import pymysql  # optional
            c = pymysql.connect(host=u.hostname, port=u.port or 3306, user=unquote(u.username or ""),
                                password=os.getenv("BRIDGE_PASSWORD", ""), database=u.path.lstrip("/"),
                                read_timeout=self.timeout, connect_timeout=10)
            with c.cursor() as cur:
                cur.execute("SET SESSION TRANSACTION READ ONLY")
                cur.execute(f"SET SESSION MAX_EXECUTION_TIME={int(self.timeout * 1000)}")
            self._conn = c
        else:
            import psycopg  # optional
            c = psycopg.connect(host=u.hostname, port=u.port or 5432, user=unquote(u.username or ""),
                                password=os.getenv("BRIDGE_PASSWORD", ""), dbname=u.path.lstrip("/"),
                                connect_timeout=10)
            c.execute("SET default_transaction_read_only = on")
            c.execute(f"SET statement_timeout = {int(self.timeout * 1000)}")
            c.commit()
            self._conn = c
        return self._conn

    def _rows(self, sql: str, params: tuple = ()) -> tuple[list[str], list[tuple], bool]:
        c = self.conn()
        cur = c.cursor()
        try:
            cur.execute(sql, params)
            cols = [d[0] for d in cur.description or []]
            rows = cur.fetchmany(self.max_rows + 1)
        finally:
            cur.close()
            if self.kind == "postgresql":
                c.rollback()
        return cols, rows[: self.max_rows], len(rows) > self.max_rows

    def _cell(self, v: Any) -> Any:
        if isinstance(v, (bytes, bytearray)):
            return f"<{len(v)} bytes>"
        if isinstance(v, str) and len(v) > self.max_cell:
            return v[: self.max_cell] + "...(cut)"
        if v is None or isinstance(v, (int, float, bool)):
            return v
        return str(v) if not isinstance(v, str) else v

    def _quoted(self, name: str) -> str:
        """A table name already checked by _table_ok (letters, digits, _ . $ only), quoted for this database."""
        q = "`" if self.kind == "mysql" else '"'
        return ".".join(q + part + q for part in name.split("."))

    def _table_ok(self, name: str) -> str:
        if not _IDENT.match(name or ""):
            raise ToolInputError("table must be a plain table name")
        if self.allowed and name.lower() not in self.allowed:
            raise ToolInputError(f"table {name!r} is not on this bridge's allow list")
        return name

    # ---- tools ----
    def list_tables(self, args: dict) -> dict:
        if self.kind == "sqlite":
            _, rows, _ = self._rows("SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name")
        elif self.kind == "mysql":
            _, rows, _ = self._rows("SHOW TABLES")
        else:
            _, rows, _ = self._rows("SELECT table_name FROM information_schema.tables WHERE table_schema "
                                    "NOT IN ('pg_catalog','information_schema') ORDER BY table_name")
        names = [r[0] for r in rows if not self.allowed or str(r[0]).lower() in self.allowed]
        return {"database": self.kind, "tables": names}

    def describe_table(self, args: dict) -> dict:
        t = self._table_ok(str(args.get("table", "")))
        if self.kind == "sqlite":
            _, rows, _ = self._rows("SELECT name, type FROM pragma_table_info(?)", (t,))
        elif self.kind == "mysql":
            _, rows, _ = self._rows("SELECT column_name, data_type FROM information_schema.columns "
                                    "WHERE table_schema = DATABASE() AND table_name = %s ORDER BY ordinal_position", (t,))
        else:
            _, rows, _ = self._rows("SELECT column_name, data_type FROM information_schema.columns "
                                    "WHERE table_name = %s ORDER BY ordinal_position", (t,))
        if not rows:
            raise ToolInputError(f"table {t!r} not found")
        out = {"table": t, "columns": {r[0]: r[1] for r in rows}}
        n = cap(args.get("sample"), 0, 5) if args.get("sample") else 0
        if n:
            # Identifiers cannot be bound as parameters; t passed _table_ok (and the allow list) and is quoted.
            sql = "SELECT * FROM " + self._quoted(t) + " LIMIT " + ("?" if self.kind == "sqlite" else "%s")  # nosec B608
            cols, sample, _ = self._rows(sql, (n,))
            out["sample"] = [{c: self._cell(v) for c, v in zip(cols, r, strict=False)} for r in sample]
        return out

    def query(self, args: dict) -> dict:
        sql = check_sql(str(args.get("sql", "")))
        if self.allowed:
            used = {m.lower() for m in re.findall(r"\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_$.]*)", _strip_sql(sql), re.I)}
            bad = sorted(used - set(self.allowed))
            if bad:
                raise ToolInputError(f"table(s) not on the allow list: {', '.join(bad)}")
        try:
            cols, rows, more = self._rows(sql)
        except ToolInputError:
            raise
        except Exception as exc:
            if self.kind == "sqlite" and "not authorized" in str(exc):
                raise ToolInputError("read-only bridge: statement refused") from exc
            raise ToolInputError(f"query failed: {str(exc)[:300]}") from exc
        return {"columns": cols, "rows": [[self._cell(v) for v in r] for r in rows], "returned": len(rows),
                "truncated": more, "note": f"capped at {self.max_rows} rows; aggregate or add WHERE/LIMIT" if more else ""}

    def build(self) -> McpServer:
        srv = McpServer("actaeon-sql", instructions=(
            f"Read-only SQL bridge ({self.kind}). Call list_tables, then describe_table, then query with one "
            f"SELECT. Results are capped at {self.max_rows} rows; aggregate (COUNT, GROUP BY) for big tables."))
        srv.tool("list_tables", "List tables and views.", {"type": "object", "properties": {}})(self.list_tables)
        srv.tool("describe_table", "Column names and types of a table, optionally a few sample rows.",
                 {"type": "object", "properties": {"table": {"type": "string"},
                  "sample": {"type": "integer", "description": "sample rows to include (max 5)"}},
                  "required": ["table"]})(self.describe_table)
        srv.tool("query", "Run one read-only SELECT (or WITH/SHOW/DESCRIBE/EXPLAIN) statement.",
                 {"type": "object", "properties": {"sql": {"type": "string", "description": "one SELECT statement"}},
                  "required": ["sql"]})(self.query)
        return srv


def add_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--url", required=True, help="sqlite:///file.db, mysql://user@host/db or postgresql://user@host/db")
    p.add_argument("--table", action="append", default=[], help="allowed table (repeatable; default all)")
    p.add_argument("--max-rows", type=int, default=200)
    p.add_argument("--timeout", type=int, default=30, help="statement timeout in seconds")


def run(a: argparse.Namespace) -> None:
    SqlBridge(a.url, max_rows=a.max_rows, timeout_sec=a.timeout, tables=a.table).build().serve()
