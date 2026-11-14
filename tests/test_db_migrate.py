"""SQLite -> PostgreSQL migration. Runs where a PostgreSQL server is available (the CI job sets ACTAEON_DB_URL)."""
import json
import os
import uuid

import pytest

from actaeon import db

PG = os.getenv("ACTAEON_DB_URL")
pytestmark = pytest.mark.skipif(not PG, reason="needs a PostgreSQL server (ACTAEON_DB_URL)")


def test_migrate_sqlite_folder(tmp_path, monkeypatch):
    from actaeon.connectors.audit import AuditLog
    from actaeon.hunt.memory import HuntMemory
    from actaeon.hunt.store import HuntStore
    from actaeon.leads import LeadStore
    data = tmp_path / "data"
    # build the SQLite source with PostgreSQL switched off for this part
    monkeypatch.setattr(db, "url", lambda: None)
    st = HuntStore(data / "hunts.sqlite")
    hid = st.create("migrated hunt")
    st.add_step(hid, 2, "call", connector="logs", tool="search", ok=True, result='{"total": 1}')
    st.update(hid, status="done", outcome="threat", verdict=json.dumps({"outcome": "threat", "findings": []}))
    LeadStore(st.path).open_for(st.get(hid))
    HuntMemory(st.path).add_note("backup01 uploads nightly", author="ann")
    a = AuditLog(data / "audit.sqlite")
    for i in range(3):
        a.record(connector="logs", tool="search", arguments={"q": i}, decision="allowed", status="ok", actor="user")
    monkeypatch.undo()
    from actaeon.db_migrate import migrate
    schema = "m_" + uuid.uuid4().hex[:10]
    monkeypatch.delenv("ACTAEON_DB_SCHEMA_PER_DIR", raising=False)
    try:
        out = migrate(data, PG, schema=schema)
        assert out["tables"]["hunts"] == 1 and out["tables"]["steps"] == 1 and out["tables"]["audit"] == 3
        st2 = HuntStore(data / "hunts.sqlite")                       # now reads from PostgreSQL
        assert st2.get(hid)["outcome"] == "threat" and st2.get(hid)["steps"][0]["tool"] == "search"
        assert LeadStore(st2.path).by_hunt(hid)
        assert "backup01" in HuntMemory(st2.path).context("backup01 uploads")
        v = AuditLog(data / "audit.sqlite").verify()
        assert v["ok"] and v["rows_checked"] == 3
        new = st2.create("after migration")                           # sequences continue past copied ids
        assert new
        with pytest.raises(RuntimeError, match="already has"):
            migrate(data, PG, schema=schema)
    finally:
        db.configure("")
