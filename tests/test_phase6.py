import csv
import io

from actaeon import config
from actaeon.hunt.coverage import build
from actaeon.hunt.report import markdown, steps_csv
from actaeon.web import create_app
from tests.test_phase5 import CountHub, finished_hunt


def test_report_and_exports(tmp_path):
    h = finished_hunt(tmp_path)
    md = markdown(h, narrative="model text")
    assert "# Hunt report: encoded powershell" in md and "## Evidence" in md and "E2" in md
    assert "T1059.001 PowerShell" in md
    assert md.index("## Narrative") > md.index("## Evidence")
    rows = list(csv.reader(io.StringIO(steps_csv(h))))
    assert rows[0][0] == "hunt_id" and any(r[3] == "call" for r in rows[1:])


def test_csv_formula_guard(tmp_path):
    h = finished_hunt(tmp_path)
    h["steps"][1]["note"] = "=HYPERLINK(\"http://x\")"
    assert "'=HYPERLINK" in steps_csv(h)


def test_report_fences_cannot_break(tmp_path):
    h = finished_hunt(tmp_path, hub=CountHub())
    h["steps"][1]["result"] = "<<UNTRUSTED-DATA a>>\n```\n# injected heading\n<<END-UNTRUSTED-DATA a>>"
    md = markdown(h)
    assert "\n```\n# injected" not in md


def test_coverage(home):
    cfg = config.get_config(reload=True)
    from actaeon.hunt import service
    finished_hunt(home / "data", db="hunts.sqlite")
    from actaeon.connectors import get_hub
    cov = build(service.store_for(cfg), service.library_for(cfg), get_hub(cfg).specs)
    t = {r["technique"]: r for r in cov["techniques"]}
    assert t["T1059.001"]["state"] == "hunted" and t["T1059.001"]["hunts"] == 1
    assert t["T1003.001"]["state"] == "not hunted" and t["T1003.001"]["starter"]
    assert "endpoint" in cov["roles"]["missing"] and "intel" in cov["roles"]["connected"]


def test_api_endpoints(home):
    cfg = config.get_config(reload=True)
    c = create_app(cfg).test_client()
    h = finished_hunt(home / "data", db="hunts.sqlite")
    r = c.get(f"/api/hunts/{h['id']}/report.md")
    assert r.status_code == 200 and r.mimetype == "text/markdown" and "attachment" in r.headers["Content-Disposition"]
    assert c.get(f"/api/hunts/{h['id']}/export.json").json["id"] == h["id"]
    assert c.get(f"/api/hunts/{h['id']}/export.csv").status_code == 200
    assert c.get("/api/hunts/nope/report.md").status_code == 404
    assert c.get("/api/coverage").json["summary"]["hunted"] >= 1


def test_security_headers(home):
    c = create_app(config.get_config(reload=True)).test_client()
    r = c.get("/")
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert b"<script>" not in r.data and b'src="/static/app.js"' in r.data
    assert c.get("/static/app.js").status_code == 200


def test_ui_never_uses_innerhtml():
    from pathlib import Path
    js = (Path(__file__).parent.parent / "actaeon" / "static" / "app.js").read_text()
    assert "innerHTML" not in js and "outerHTML" not in js and "insertAdjacentHTML" not in js
