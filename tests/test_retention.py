"""Retention: old finished hunts go, open work and the audit log stay."""
import json

from actaeon import config
from actaeon.hunt import service
from actaeon.retention import purge


def _old_hunt(cfg, days_old, status="done", lead=None):
    st = service.store_for(cfg)
    hid = st.create("old hunt")
    st.add_step(hid, 2, "call", connector="logs", tool="search", ok=True, result="{}")
    st.update(hid, status=status, outcome="threat", verdict=json.dumps({"outcome": "threat", "findings": []}))
    from datetime import datetime, timedelta, timezone

    from actaeon import db
    when = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat(timespec="seconds")
    with db.connect(st.path) as c:
        c.execute("UPDATE hunts SET created=? WHERE id=?", (when, hid))
    if lead:
        leads = service.leads_for(cfg)
        lr = leads.open_for(st.get(hid))
        if lead == "closed":
            leads.close(lr["id"], "ann", "false_positive", "checked")
    return hid


def test_purge(home):
    cfg = config.get_config(reload=True)
    keep_new = _old_hunt(cfg, 2)
    gone = _old_hunt(cfg, 100)
    gone_closed = _old_hunt(cfg, 100, lead="closed")
    keep_open = _old_hunt(cfg, 100, lead="open")
    keep_running = _old_hunt(cfg, 100, status="running")
    cfg.raw["retention"] = {"hunts_days": 30}
    dry = purge(cfg, dry_run=True)
    assert dry["hunts"] == 2 and dry["leads"] == 1 and dry["kept_open_lead"] == 1
    st = service.store_for(cfg)
    assert st.get(gone)                                                # dry run deleted nothing
    real = purge(cfg)
    assert real["hunts"] == 2
    assert st.get(gone) is None and st.get(gone_closed) is None
    assert st.get(keep_new) and st.get(keep_open) and st.get(keep_running)
    assert service.leads_for(cfg).by_hunt(gone_closed) is None and service.leads_for(cfg).by_hunt(keep_open)


def test_off_by_default_and_admin_only(home):
    cfg = config.get_config(reload=True)
    h = _old_hunt(cfg, 400)
    assert purge(cfg)["hunts"] == 0 and service.store_for(cfg).get(h)
    from actaeon.auth import check_rbac_permission
    assert not check_rbac_permission("operator", "POST", "/api/retention")[0]
