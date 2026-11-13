"""Reports as PDF, Word (docx) or Markdown, from the stored records (no model).

  hunt report     verdict, verification, findings, timeline, queries and evidence
  lead report     case status, resolution and history, then the hunt report
  summary report  a period (default 7 days): hunts by outcome, leads opened/closed, resolutions,
                  time to acknowledge and close, open leads, threats and top techniques

Evidence comes from data sources and is untrusted: it is always written as plain
text (escaped for PDF), never interpreted. PDF and Word need the ``reports`` extra.
"""

from __future__ import annotations

import io
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

from .hunt.attack_names import name as tname
from .hunt.report import OUTCOME_TEXT
from .hunt.signals import payload

FORMATS = ("pdf", "docx", "md")
MIMES = {"pdf": "application/pdf", "md": "text/markdown",
         "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}


# ---------- content (format-free blocks) ----------
def _hunt_blocks(h: dict, *, evidence_chars: int = 1500) -> list[tuple]:
    from .hunt.timeline import build, describe
    v = h.get("verdict") or {}
    ver = v.get("verification") or {}
    b: list[tuple] = [("h2", f"Verdict: {OUTCOME_TEXT.get(v.get('outcome'), v.get('outcome') or '-')} "
                             f"(confidence {v.get('confidence', 0)})"),
                      ("p", v.get("summary") or "-")]
    if ver:
        b.append(("p", f"Second look: {ver.get('result')}. {ver.get('reason', '')}"))
    if v.get("findings"):
        b += [("h3", "Findings"), ("bullets", [f"{f['claim']} ({', '.join(f['evidence'])})" for f in v["findings"]])]
    if v.get("unsupported_claims"):
        b += [("h3", "Claims without evidence (not verified)"), ("bullets", [f["claim"] for f in v["unsupported_claims"]])]
    techs = list(dict.fromkeys(((h.get("plan") or {}).get("attack") or []) + (v.get("attack") or [])))
    if techs:
        b += [("h3", "MITRE ATT&CK"), ("bullets", [f"{t} {tname(t)}".strip() for t in techs])]
    for title, key in (("Gaps", "gaps"), ("Next steps", "next_steps"), ("Checks applied", "checks")):
        if v.get(key):
            b += [("h3", title), ("bullets", list(v[key]))]
    tl = build(h, limit=60)
    if tl["events"]:
        b += [("h2", f"Timeline ({tl['total']} events)"),
              ("table", ["Time (UTC)", "Host", "User", "What", "State", "Ev"],
               [[r["time"][:19].replace("T", " "), r["host"], r["user"], describe(r)[:160], r["state"], r["evidence"]]
                for r in tl["events"]])]
    calls = [s for s in h.get("steps") or [] if s["kind"] == "call"]
    if calls:
        b += [("h2", "Queries"), ("table", ["Ev", "Tool", "Arguments", "OK"],
                                  [[f"E{s['n']}", f"{s['connector']}.{s['tool']}",
                                    json.dumps(s.get("arguments"), default=str)[:300], "yes" if s["ok"] else "no"]
                                   for s in calls])]
        b.append(("h2", "Evidence (data from the sources)"))
        for s in calls[:25]:
            b += [("h3", f"E{s['n']} {s['connector']}.{s['tool']}"),
                  ("code", payload(s.get("result") or "")[:evidence_chars] or "(empty)")]
    return b


def hunt_doc(h: dict, *, lead: dict | None = None) -> dict:
    meta = [("Hunt id", h["id"]), ("Hypothesis", h["hypothesis"]), ("Started", h.get("created", "")),
            ("Finished", h.get("finished") or "-"), ("Status", h["status"]), ("Origin", h.get("origin", "")),
            ("Started by", h.get("actor") or "-")]
    if h.get("models"):
        meta.append(("Models", ", ".join(f"{r}: {m['provider']}/{m['model']}" for r, m in h["models"].items()
                                         if isinstance(m, dict) and "provider" in m)))
        u = h["models"].get("usage") or {}
        if u.get("calls"):
            meta.append(("Model use", f"{u['calls']} calls, {u['tokens_in']:,} tokens in, {u['tokens_out']:,} out"
                         + (f", about ${u['cost_usd']:.4f}" if u.get("cost_usd") is not None else "")))
    if lead:
        meta.append(("Lead", f"#{lead['id']} {lead['status']} {lead.get('resolution') or ''}".strip()))
    return {"title": f"Hunt report: {h['hypothesis'][:120]}", "blocks": [("kv", meta), *_hunt_blocks(h)]}


def lead_doc(lead: dict, h: dict) -> dict:
    meta = [("Lead", f"#{lead['id']}"), ("Title", lead["title"]), ("Severity", lead["severity"]),
            ("Status", lead["status"]), ("Assignee", lead["assignee"] or "-"),
            ("Resolution", (lead.get("resolution") or "-").replace("_", " ")), ("Opened", lead["created"]),
            ("Acknowledged", lead.get("acknowledged_at") or "-"), ("Closed", lead.get("closed_at") or "-"),
            ("Closed by", lead.get("closed_by") or "-")]
    hist = ("table", ["Time (UTC)", "User", "Action", "Detail"],
            [[e["ts"][:19].replace("T", " "), e["user"], e["action"], e["detail"][:300]] for e in lead["events"]])
    return {"title": f"Lead #{lead['id']}: {lead['title'][:120]}",
            "blocks": [("kv", meta), ("h2", "History"), hist, ("h1", "Hunt"), ("kv", [("Hunt id", h["id"]), ("Hypothesis", h["hypothesis"])]), *_hunt_blocks(h)]}


def summary_doc(cfg, days: int = 7) -> dict:
    from .hunt import service as hs
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    hunts = [h for h in hs.store_for(cfg).list(limit=5000) if h["created"] >= since]
    cs = hs.leads_for(cfg)
    allcases = cs.list(limit=100000)
    opened = [c for c in allcases if c["created"] >= since]
    closed = [c for c in allcases if (c.get("closed_at") or "") >= since]
    st = cs.stats()
    outcomes = Counter((h.get("outcome") or "none") for h in hunts)
    origins = Counter(h["origin"].split(":")[0] for h in hunts)
    techs = Counter(t for h in hunts for t in ((h.get("verdict") or {}).get("attack") or []))
    threats = [h for h in hunts if h.get("outcome") == "threat"]
    open_leads = [c for c in allcases if c["status"] != "closed"]
    blocks: list[tuple] = [
        ("kv", [("Period", f"last {days} days (since {since[:10]})"), ("Generated", datetime.now(timezone.utc)
                                                                         .isoformat(timespec="minutes")),
                ("Instance", cfg.instance_name)]),
        ("h2", "At a glance"),
        ("table", ["Measure", "Value"], [
            ["Hunts run", len(hunts)], ["Threat verdicts", outcomes.get("threat", 0)],
            ["Leads opened", len(opened)], ["Leads closed", len(closed)], ["Leads open now", len(open_leads)],
            ["Mean time to acknowledge (min, all time)", st["mean_minutes_to_acknowledge"] or "-"],
            ["Mean time to close (min, all time)", st["mean_minutes_to_close"] or "-"]]),
        ("h2", "Hunts by outcome"),
        ("table", ["Outcome", "Hunts"], [[OUTCOME_TEXT.get(k, k), n] for k, n in outcomes.most_common()]),
        ("h2", "Hunts by origin"), ("table", ["Origin", "Hunts"], [[k, n] for k, n in origins.most_common()]),
        ("h2", "Leads closed by resolution"),
        ("table", ["Resolution", "Leads"], [[k.replace("_", " "), n] for k, n in
                                            Counter(c["resolution"] for c in closed).most_common()]),
        ("h2", "Open leads"),
        ("table", ["Lead", "Severity", "Status", "Assignee", "Title"],
         [[f"#{c['id']}", c["severity"], c["status"], c["assignee"] or "-", c["title"][:120]] for c in open_leads[:50]]),
        ("h2", "Threats found"),
        ("table", ["When", "Hunt", "Confidence", "Hypothesis"],
         [[h["created"][:16].replace("T", " "), h["id"], (h.get("verdict") or {}).get("confidence"), h["hypothesis"][:140]]
          for h in threats[:50]]),
        ("h2", "Top ATT&CK techniques in verdicts"),
        ("table", ["Technique", "Name", "Hunts"], [[t, tname(t), n] for t, n in techs.most_common(15)]),
        ("p", "Figures come from Actaeon's own records. Findings are leads that analysts confirm; see each lead."),
    ]
    return {"title": f"Threat hunting summary: last {days} days", "blocks": blocks}


# ---------- renderers ----------
def to_markdown(doc: dict) -> bytes:
    out = [f"# {doc['title']}", ""]
    cell = lambda x: str(x).replace("|", "\\|").replace("\n", " ")  # noqa: E731
    for blk in doc["blocks"]:
        k = blk[0]
        if k in ("h1", "h2", "h3"):
            out += ["#" * (int(k[1]) + 1) + " " + blk[1], ""]
        elif k == "p":
            out += [str(blk[1]), ""]
        elif k == "bullets":
            out += [f"- {x}" for x in blk[1]] + [""]
        elif k == "kv":
            out += [f"- **{a}:** {cell(b)}" for a, b in blk[1]] + [""]
        elif k == "table":
            if blk[2]:
                out += ["| " + " | ".join(blk[1]) + " |", "|" + "---|" * len(blk[1])]
                out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in blk[2]] + [""]
            else:
                out += ["(none)", ""]
        elif k == "code":
            out += ["```", str(blk[1]).replace("```", "'''"), "```", ""]
    return "\n".join(out).encode()


def to_docx(doc: dict) -> bytes:
    try:
        from docx import Document
        from docx.shared import Pt
    except ImportError as exc:
        raise RuntimeError("Word reports need the reports extra: pip install 'actaeon[reports]'") from exc
    d = Document()
    d.add_heading(doc["title"], 0)
    for blk in doc["blocks"]:
        k = blk[0]
        if k in ("h1", "h2", "h3"):
            d.add_heading(str(blk[1]), int(k[1]))
        elif k == "p":
            d.add_paragraph(str(blk[1]))
        elif k == "bullets":
            for x in blk[1]:
                d.add_paragraph(str(x), style="List Bullet")
        elif k == "kv":
            t = d.add_table(rows=0, cols=2)
            t.style = "Light Grid Accent 1"
            for a, b in blk[1]:
                row = t.add_row().cells
                row[0].text, row[1].text = str(a), str(b)
        elif k == "table":
            if not blk[2]:
                d.add_paragraph("(none)")
                continue
            t = d.add_table(rows=1, cols=len(blk[1]))
            t.style = "Light Grid Accent 1"
            for i, hcell in enumerate(blk[1]):
                t.rows[0].cells[i].text = str(hcell)
            for r in blk[2]:
                cells = t.add_row().cells
                for i, c in enumerate(r):
                    cells[i].text = str(c)
        elif k == "code":
            p = d.add_paragraph()
            run = p.add_run(str(blk[1]))
            run.font.name, run.font.size = "Courier New", Pt(8)
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def to_pdf(doc: dict) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("PDF reports need the reports extra: pip install 'actaeon[reports]'") from exc
    ss = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=ss["BodyText"], fontSize=8, leading=10)
    code = ParagraphStyle("code", parent=ss["Code"], fontSize=7, leading=8.5)
    P = lambda t, st=ss["BodyText"]: Paragraph(escape(str(t)), st)  # noqa: E731  untrusted text is escaped
    story = [P(doc["title"], ss["Title"])]
    width = A4[0] - 30 * mm
    for blk in doc["blocks"]:
        k = blk[0]
        if k in ("h1", "h2", "h3"):
            story += [Spacer(1, 4), P(blk[1], ss[{"h1": "Heading1", "h2": "Heading2", "h3": "Heading3"}[k]])]
        elif k == "p":
            story.append(P(blk[1]))
        elif k == "bullets":
            story += [P(f"\u2022 {x}") for x in blk[1]]
        elif k in ("kv", "table"):
            head, rows = (None, blk[1]) if k == "kv" else (blk[1], blk[2])
            if not rows:
                story.append(P("(none)", small))
                continue
            data = ([[P(h, small) for h in head]] if head else []) + [[P(c, small) for c in r] for r in rows]
            ncol = len(data[0])
            t = Table(data, colWidths=[width / ncol] * ncol if k == "table" else [width * 0.28, width * 0.72],
                      repeatRows=1 if head else 0)
            style = [("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]
            if head:
                style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dde6f3")))
            t.setStyle(TableStyle(style))
            story += [t, Spacer(1, 4)]
        elif k == "code":
            story.append(Preformatted(str(blk[1])[:4000], code, maxLineLength=110))
    buf = io.BytesIO()

    def footer(canvas, d):
        canvas.setFont("Helvetica", 7)
        canvas.drawString(15 * mm, 8 * mm, f"Actaeon  |  {doc['title'][:90]}  |  page {d.page}")
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm,
                      bottomMargin=14 * mm, title=doc["title"]).build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


def render(doc: dict, fmt: str) -> bytes:
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {FORMATS}")
    return {"md": to_markdown, "docx": to_docx, "pdf": to_pdf}[fmt](doc)
