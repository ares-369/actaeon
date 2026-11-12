import io
import zipfile

import pytest

from actaeon import config
from actaeon.reporting import case_doc, hunt_doc, render, summary_doc
from tests.test_timeline import step

HUNT = {"id": "h1", "hypothesis": "Office started <script>alert(1)</script> encoded PowerShell", "created": "2026-11-10",
        "finished": "2026-11-10", "status": "done", "origin": "manual", "actor": "alice",
        "verdict": {"outcome": "threat", "confidence": 85, "summary": "bad & <b>bold</b>", "attack": ["T1059.001"],
                    "findings": [{"claim": "WS07", "evidence": ["E2"]}], "verification": {"result": "confirmed",
                                                                                      "reason": "still active"}},
        "steps": [dict(step(2, [{"@timestamp": "2026-11-10T10:00:00Z", "host": {"name": "WS07"},
                                 "event": {"action": "start"}, "process": {"name": "a.exe"}}]),
                       arguments={"query": "q"})]}
CASE = {"id": 7, "title": "threat: x", "severity": "high", "status": "closed", "assignee": "alice",
        "resolution": "true_positive", "created": "2026-11-10T10:00:00+00:00", "acknowledged_at": None,
        "closed_at": None, "closed_by": "alice",
        "events": [{"ts": "2026-11-10T10:00:00+00:00", "user": "system", "action": "opened", "detail": "d"}]}


@pytest.mark.parametrize("fmt", ["pdf", "docx", "md"])
def test_render_hunt_and_case(fmt):
    for doc in (hunt_doc(HUNT, case=CASE), case_doc(CASE, HUNT)):
        data = render(doc, fmt)
        assert len(data) > 500
        if fmt == "pdf":
            assert data[:5] == b"%PDF-"
            from pypdf import PdfReader
            text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(data)).pages)
            assert "<script>alert(1)</script>" in text and "WS07" in text     # shown as text, not markup
        elif fmt == "docx":
            xml = zipfile.ZipFile(io.BytesIO(data)).read("word/document.xml").decode()
            assert "WS07" in xml and "&lt;script&gt;" in xml
        else:
            assert b"## Timeline" in data and b"Second look: confirmed" in data


def test_bad_format():
    with pytest.raises(ValueError):
        render(hunt_doc(HUNT), "exe")


def test_summary_and_api(home):
    from actaeon.hunt import service
    from actaeon.web import create_app
    cfg = config.get_config(reload=True)
    st = service.store_for(cfg)
    hid = st.create("Office started encoded PowerShell")
    st.update(hid, status="done", outcome="threat", verdict={"outcome": "threat", "confidence": 80, "summary": "s",
                                                              "attack": ["T1059.001"]})
    service.send_outputs(cfg, st.get(hid))
    md = render(summary_doc(cfg, 7), "md").decode()
    assert "Threat verdicts | 1" in md and "T1059.001" in md and "Cases open now | 1" in md
    c = create_app(cfg).test_client()
    r = c.get("/api/reports/summary.pdf?days=30")
    assert r.status_code == 200 and r.data[:5] == b"%PDF-" and "attachment" in r.headers["Content-Disposition"]
    assert c.get(f"/api/hunts/{hid}/report.docx").status_code == 200
    cid = service.cases_for(cfg).list()[0]["id"]
    assert c.get(f"/api/cases/{cid}/report.pdf").data[:5] == b"%PDF-"
    assert c.get("/api/cases/999/report.pdf").status_code == 404
    assert c.get(f"/api/hunts/{hid}/report.exe").status_code == 400


def test_report_cli(home, tmp_path):
    from actaeon import cli
    config.get_config(reload=True)
    out = tmp_path / "s.docx"
    cli.cli_main(["report", "summary", "--format", "docx", "-o", str(out)])
    assert out.exists() and out.stat().st_size > 1000
