"""Outputs: send hunt results somewhere when they finish.

    outputs:
      - name: soc-mail
        type: email
        when: [threat]                     # threat | needs_review | benign | no_results | logs_missing | inconclusive | all
        smtp_host: "mail.example.org"
        smtp_port: 587
        starttls: true
        username_env: SMTP_USER            # optional
        password_env: SMTP_PASSWORD        # optional
        from: "actaeon@example.org"
        to: ["soc@example.org"]
        to_critical: ["soc-leads@example.org"]   # added when confidence >= critical_confidence
        critical_confidence: 80
      - name: audit-sheet
        type: excel
        when: [all]
        path: "/var/lib/actaeon/hunt-audit.xlsx"
      - name: chat-hook
        type: webhook
        when: [threat, needs_review]
        url: "https://hooks.example.org/actaeon"
        headers: {Authorization: "Bearer ${HOOK_TOKEN}"}
      - name: open-case
        type: mcp_tool                     # e.g. a case-management tool on a connector
        when: [threat]
        connector: cases
        tool: create_case
        arguments: {title: "{title}", description: "{summary}", severity: "{severity}"}

``mcp_tool`` outputs go through the connector policy: the connector needs
``allow_write: true`` and the tool named exactly in ``tools.allow``. Outputs never
contain raw tool results; they carry the verdict, findings, evidence ids,
queries and a link. A failed output is recorded on the hunt and never stops it.
"""

from __future__ import annotations

import json
import re
import smtplib
import ssl
import threading
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import requests

TYPES = ("email", "excel", "webhook", "mcp_tool")
EVENTS = ("threat", "needs_review", "benign", "no_results", "logs_missing", "inconclusive", "all")
_XLSX_LOCK = threading.Lock()
HEADERS = ["Time (UTC)", "Hunt id", "Origin", "Hypothesis", "Outcome", "Confidence", "Needs review", "Summary",
           "Findings", "Indicators", "Queries executed", "Result per query", "ATT&CK", "Link"]


def validate(outputs: list) -> None:
    names = set()
    for o in outputs or []:
        n = str(o.get("name", ""))
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", n) or n in names:
            raise ValueError(f"outputs: name {n!r} must be unique, lowercase letters, digits, _ or -")
        names.add(n)
        if o.get("type") not in TYPES:
            raise ValueError(f"outputs.{n}: type must be one of {TYPES}")
        bad = set(o.get("when") or ["threat"]) - set(EVENTS)
        if bad:
            raise ValueError(f"outputs.{n}: unknown 'when' values {sorted(bad)}; use {EVENTS}")
        need = {"email": ("smtp_host", "from", "to"), "excel": ("path",), "webhook": ("url",),
                "mcp_tool": ("connector", "tool")}[o["type"]]
        missing = [k for k in need if not o.get(k)]
        if missing:
            raise ValueError(f"outputs.{n}: missing {', '.join(missing)}")
        for k in ("password", "token", "secret"):
            if o.get(k):
                raise ValueError(f"outputs.{n}: put secrets in .env and use {k}_env")


def events_of(h: dict) -> set[str]:
    v = h.get("verdict") or {}
    o = h.get("outcome") or v.get("outcome") or "inconclusive"
    ev = {"all", "benign" if o == "telemetry_found_benign" else o}
    if v.get("needs_review"):
        ev.add("needs_review")
    return ev


def facts(h: dict, base_url: str = "") -> dict[str, Any]:
    v = h.get("verdict") or {}
    calls = [s for s in h.get("steps") or [] if s["kind"] == "call"]
    queries = [f"E{s['n']} {s['connector']}.{s['tool']} {json.dumps(s.get('arguments'), default=str)[:300]}" for s in calls]
    results = [f"E{s['n']} {'ok' if s['ok'] else 'failed'} {s.get('note') or ''}".strip() for s in calls]
    from .intel.extract import extract
    found = extract(" ".join(f["claim"] for f in v.get("findings") or []) + " " + h.get("hypothesis", ""))
    inds = [x for k in ("ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email") for x in found.get(k, [])]
    conf = int(v.get("confidence") or 0)
    outcome = h.get("outcome") or v.get("outcome") or ""
    severity = "high" if outcome == "threat" and conf >= 80 else "medium" if outcome == "threat" else "low"
    link = f"{base_url.rstrip('/')}/#hunt/{h['id']}" if base_url else ""
    return {"hunt_id": h["id"], "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "origin": h.get("origin", ""), "hypothesis": h.get("hypothesis", ""), "outcome": outcome,
            "confidence": conf, "needs_review": bool(v.get("needs_review")), "summary": v.get("summary", ""),
            "findings": [f"{f['claim']} ({', '.join(f['evidence'])})" for f in v.get("findings") or []],
            "indicators": inds[:50], "queries": queries, "results": results, "attack": v.get("attack") or [],
            "link": link, "severity": severity,
            "title": f"[Actaeon] {outcome.replace('_', ' ')}: {h.get('hypothesis', '')[:120]}"}


def _fill(t: Any, f: dict) -> Any:
    if isinstance(t, str):
        return re.sub(r"\{(\w+)\}", lambda m: str(f.get(m.group(1), m.group(0))) if not isinstance(
            f.get(m.group(1)), list) else "; ".join(map(str, f[m.group(1)])), t)
    if isinstance(t, dict):
        return {k: _fill(v, f) for k, v in t.items()}
    if isinstance(t, list):
        return [_fill(v, f) for v in t]
    return t


def _email_text(f: dict) -> str:
    lines = [f"Outcome: {f['outcome']} (confidence {f['confidence']}){'  NEEDS REVIEW' if f['needs_review'] else ''}",
             f"Hypothesis: {f['hypothesis']}", "", f["summary"], ""]
    if f["findings"]:
        lines += ["Findings (evidence ids refer to the hunt record):", *[f"- {x}" for x in f["findings"]], ""]
    if f["indicators"]:
        lines += ["Indicators: " + ", ".join(f["indicators"]), ""]
    if f["attack"]:
        lines += ["ATT&CK: " + ", ".join(f["attack"]), ""]
    if f["queries"]:
        lines += ["Queries executed:", *[f"- {q}" for q in f["queries"][:20]], ""]
    if f["link"]:
        lines.append(f"Open the hunt: {f['link']}")
    lines.append(f"Hunt id: {f['hunt_id']}  Origin: {f['origin']}")
    lines.append("Sent by Actaeon. Findings are leads for an analyst to confirm.")
    return "\n".join(lines)


def send_email(o: dict, f: dict, env=None, smtp_cls=None) -> str:
    import os
    env = env or os.environ
    to = list(o.get("to") or [])
    if f["outcome"] == "threat" and f["confidence"] >= int(o.get("critical_confidence", 80)):
        to += list(o.get("to_critical") or [])
    msg = EmailMessage()
    msg["Subject"] = _fill(o.get("subject", "{title}"), f)[:200]
    msg["From"] = o["from"]
    msg["To"] = ", ".join(dict.fromkeys(to))
    msg.set_content(_email_text(f))
    smtp_cls = smtp_cls or (smtplib.SMTP_SSL if o.get("ssl") else smtplib.SMTP)
    with smtp_cls(o["smtp_host"], int(o.get("smtp_port", 465 if o.get("ssl") else 587)), timeout=30) as s:
        if o.get("starttls", True) and not o.get("ssl"):
            s.starttls(context=ssl.create_default_context())
        user = env.get(str(o.get("username_env", "")), "") if o.get("username_env") else ""
        if user:
            s.login(user, env.get(str(o.get("password_env", "")), ""))
        s.send_message(msg)
    return f"sent to {len(set(to))} recipient(s)"


def append_excel(o: dict, f: dict) -> str:
    try:
        from openpyxl import Workbook, load_workbook
    except ImportError as exc:
        raise RuntimeError("excel outputs need the excel extra: pip install 'actaeon[excel]'") from exc
    path = Path(str(o["path"])).expanduser()
    sheet = str(o.get("sheet", "Hunts"))[:31]
    row = [f["time"], f["hunt_id"], f["origin"], f["hypothesis"], f["outcome"], f["confidence"],
           "yes" if f["needs_review"] else "no", f["summary"], "\n".join(f["findings"]), ", ".join(f["indicators"]),
           "\n".join(f["queries"]), "\n".join(f["results"]), ", ".join(f["attack"]), f["link"]]
    # spreadsheet apps run cells that start with = + - @ as formulas
    row = [("'" + c) if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") else c for c in row]
    with _XLSX_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        new_sheet = True
        if path.exists():
            wb = load_workbook(path)
            new_sheet = sheet not in wb.sheetnames
            ws = wb.create_sheet(sheet) if new_sheet else wb[sheet]
        else:
            wb = Workbook()
            ws = wb.active
            ws.title = sheet
        if new_sheet:
            ws.append(HEADERS)
        ws.append([str(c)[:32000] if isinstance(c, str) else c for c in row])
        tmp = path.with_suffix(".tmp.xlsx")
        wb.save(tmp)
        tmp.replace(path)
    return f"row added to {path.name}"


def send_webhook(o: dict, f: dict, session=None) -> str:
    from .connectors.spec import expand_env
    headers = {str(k): expand_env(str(v)) for k, v in (o.get("headers") or {}).items()}
    body = _fill(o["body"], f) if o.get("body") else f
    r = (session or requests).post(str(o["url"]), json=body, headers=headers, timeout=20)
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}")
    return f"HTTP {r.status_code}"


def call_tool(o: dict, f: dict, hub) -> str:
    args = _fill(o.get("arguments") or {}, f)
    out = hub.call(str(o["connector"]), str(o["tool"]), args, actor="outputs", hunt_id=f["hunt_id"])
    if out.get("is_error"):
        raise RuntimeError("the tool returned an error")
    return f"{o['connector']}.{o['tool']} called"


def dispatch(cfg, h: dict, *, hub=None, only: str | None = None, smtp_cls=None, session=None) -> list[dict]:
    """Send ``h`` to every matching output. Returns [{name, ok, detail}]; never raises."""
    outs = (cfg.raw or {}).get("outputs") or []
    ev = events_of(h)
    f = facts(h, getattr(cfg, "external_url", "") or "")
    results = []
    for o in outs:
        if only and o.get("name") != only:
            continue
        if not only and not (set(o.get("when") or ["threat"]) & ev):
            continue
        if o.get("origins") and not any(h.get("origin", "").startswith(p) for p in o["origins"]):
            continue
        try:
            t = o["type"]
            if t == "email":
                detail = send_email(o, f, smtp_cls=smtp_cls)
            elif t == "excel":
                detail = append_excel(o, f)
            elif t == "webhook":
                detail = send_webhook(o, f, session=session)
            else:
                if hub is None:
                    from .connectors import get_hub
                    hub = get_hub(cfg)
                detail = call_tool(o, f, hub)
            results.append({"name": o["name"], "ok": True, "detail": detail})
        except Exception as exc:
            results.append({"name": o.get("name"), "ok": False, "detail": f"{type(exc).__name__}: {exc}"[:300]})
    return results
