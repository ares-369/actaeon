"""Copy an existing SQLite data folder into PostgreSQL: ``actaeon db migrate --to postgresql://...``.

Every store creates its tables in the target schema first, then each SQLite table's rows are copied as they
are (ids, timestamps, the audit log's hash chain). Afterwards ``actaeon audit verify`` against the new
database checks the copied audit chain. The target schema must be empty of hunts unless ``force`` is set,
so a second run cannot duplicate data. The SQLite files are only read, never changed.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from . import db

FILES = ("hunts.sqlite", "intel.sqlite", "audit.sqlite", "actaeon.sqlite")
_FTS_SHADOW = ("_data", "_idx", "_content", "_docsize", "_config")


def _create_tables(data_dir: Path) -> None:
    """Instantiate every store against the (already configured) PostgreSQL target so its tables exist."""
    from .assistant import Conversations
    from .connectors.audit import AuditLog
    from .hunt.chat import ChatLog
    from .hunt.detection import DetectionStore
    from .hunt.drift import DriftStore
    from .hunt.entities import EntityStore
    from .hunt.library import Library
    from .hunt.memory import HuntMemory
    from .hunt.store import HuntStore
    from .intel import IntelStore
    from .jobs import JobManager
    from .leads import LeadStore
    from .rules.store import RuleStore
    hp = data_dir / "hunts.sqlite"
    for cls in (HuntStore, Library, HuntMemory, LeadStore, ChatLog, DetectionStore, Conversations, EntityStore,
                DriftStore, RuleStore):
        cls(hp)
    IntelStore(data_dir / "intel.sqlite")
    AuditLog(data_dir / "audit.sqlite")
    JobManager(data_dir / "actaeon.sqlite", mode="queue").pool.shutdown(wait=False)


def _source_tables(con: sqlite3.Connection) -> list[str]:
    names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    virtual = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE sql LIKE 'CREATE VIRTUAL TABLE%'")}
    # FTS5 keeps its index in shadow tables (<name>_data, ...): copy the virtual table's rows, not those
    return [n for n in names if not any(n == v + s for v in virtual for s in _FTS_SHADOW)] + \
        [v for v in virtual if v not in names]


def migrate(data_dir: Path, url: str, *, schema: str = "actaeon", force: bool = False) -> dict:
    data_dir = Path(data_dir)
    db.configure(url, schema)
    _create_tables(data_dir)
    copied: dict[str, int] = {}
    with db.connect(data_dir / "hunts.sqlite") as t:
        existing = t.execute("SELECT COUNT(*) FROM hunts").fetchone()[0]
    if existing and not force:
        raise RuntimeError(f"the target schema {schema!r} already has {existing} hunt(s); refusing to copy over it")
    for name in FILES:
        src = data_dir / name
        if not src.exists():
            continue
        con = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        try:
            for table in _source_tables(con):
                rows = con.execute(f'SELECT * FROM "{table}"').fetchall()   # nosec B608 - names from sqlite_master
                if not rows:
                    continue
                cols = rows[0].keys()
                with db.connect(data_dir / name) as t:
                    target_cols = {r[1] for r in t.execute(f"PRAGMA table_info({table})")}
                    use = [c for c in cols if c in target_cols]
                    if not use:
                        continue
                    sql = (f"INSERT INTO {table} ({', '.join(use)}) VALUES ({', '.join('?' for _ in use)})")  # nosec B608
                    for r in rows:
                        t.execute(sql, tuple(r[c] for c in use))
                    if "id" in use and _serial(t, table):
                        t.execute(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "  # nosec B608
                                  f"(SELECT COALESCE(MAX(id), 1) FROM {table}))")
                copied[table] = len(rows)
        finally:
            con.close()
    return {"schema": schema, "tables": copied, "rows": sum(copied.values())}


def _serial(t, table: str) -> bool:
    r = t.execute("SELECT column_default FROM information_schema.columns WHERE table_schema = current_schema() "
                  "AND table_name = ? AND column_name = 'id'", (table,)).fetchone()
    return bool(r and r[0] and str(r[0]).startswith("nextval"))
