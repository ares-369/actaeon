"""Outputs for alert cases: the same outputs as hunts (email, webhook, mcp_tool), other events.

    outputs:
      - name: soc-mail
        type: email
        when: [case_true_positive, case_needs_analyst]   # case_<verdict>, case_action_proposed, case_all
        min_severity: 50                                 # optional: only cases at or above this (0-100)
        ...

Outputs carry the verdict, summary, findings, entities, proposed actions and a link; never raw tool
results. A failed output is noted on the case and never stops triage.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

CASE_EVENTS = ("case_true_positive", "case_false_positive", "case_benign", "case_needs_analyst", "case_logs_missing",
               "case_action_proposed", "case_all")


def events_of(case: dict) -> set[str]:
    ev = {"case_all"}
    if case.get("verdict"):
        ev.add("case_" + case["verdict"])
    if any(a.get("status") == "proposed" for a in case.get("actions") or []):
        ev.add("case_action_proposed")
    return ev


def facts(case: dict, base_url: str = "") -> dict[str, Any]:
    r = case.get("report") or {}
    link = f"{base_url.rstrip('/')}/#case/{case['id']}" if base_url else ""
    return {
        "case_id": case["id"], "hunt_id": f"case:{case['id']}",
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "title": f"[Actaeon] {str(case.get('verdict') or '').replace('_', ' ')}: {case.get('title', '')[:120]}",
        "verdict": case.get("verdict") or "", "outcome": case.get("verdict") or "",
        "confidence": int(case.get("confidence") or 0),
        "severity": case.get("severity_label") or "", "severity_score": int(case.get("severity") or 0),
        "summary": case.get("summary") or "", "alerts": len(case.get("alerts") or []),
        "findings": [f"{f.get('text', '')} ({', '.join(f.get('evidence') or [])})" for f in r.get("findings") or []],
        "entities": [f"{e['type']}={e['value']}" for e in (case.get("entities") or [])[:40]],
        "attack": case.get("attack") or [],
        "fix": "; ".join((r.get("fix") or {}).get("steps") or []),
        "actions": [f"{a['name']} on {a['target']} ({a['status']})" for a in case.get("actions") or []],
        "link": link,
    }


def email_text(f: dict) -> str:
    lines = [f"Verdict: {f['verdict']} (confidence {f['confidence']}, severity {f['severity']})",
             f"Alerts in the case: {f['alerts']}", "", f["summary"], ""]
    for label, key in (("Findings (evidence ids refer to the case record)", "findings"), ("Entities", "entities"),
                       ("Proposed actions (need approval)", "actions")):
        if f[key]:
            lines += [label + ":", *[f"- {x}" for x in f[key]], ""]
    if f["fix"]:
        lines += ["Fix: " + f["fix"], ""]
    if f["attack"]:
        lines += ["ATT&CK: " + ", ".join(f["attack"]), ""]
    if f["link"]:
        lines.append(f"Open the case: {f['link']}")
    lines.append(f"Case id: {f['case_id']}")
    lines.append("Sent by Actaeon. The verdict is an AI assessment for an analyst to confirm.")
    return "\n".join(lines)


def _send_email(o: dict, f: dict, smtp_cls=None) -> str:
    import os
    import smtplib
    import ssl
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = re.sub(r"\{(\w+)\}", lambda m: str(f.get(m.group(1), m.group(0))), o.get("subject", "{title}"))[:200]
    msg["From"] = o["from"]
    msg["To"] = ", ".join(dict.fromkeys(o.get("to") or []))
    msg.set_content(email_text(f))
    smtp_cls = smtp_cls or (smtplib.SMTP_SSL if o.get("ssl") else smtplib.SMTP)
    with smtp_cls(o["smtp_host"], int(o.get("smtp_port", 465 if o.get("ssl") else 587)), timeout=30) as s:
        if o.get("starttls", True) and not o.get("ssl"):
            s.starttls(context=ssl.create_default_context())
        user = os.environ.get(str(o.get("username_env", "")), "") if o.get("username_env") else ""
        if user:
            s.login(user, os.environ.get(str(o.get("password_env", "")), ""))
        s.send_message(msg)
    return f"sent to {len(set(o.get('to') or []))} recipient(s)"


def dispatch(cfg, case: dict, *, hub=None, only: str | None = None, smtp_cls=None, session=None) -> list[dict]:
    """Send the case to every output whose ``when`` lists one of its events. Returns [{name, ok, detail}]."""
    from ..outputs import call_tool, send_webhook
    outs = (cfg.raw or {}).get("outputs") or []
    ev = events_of(case)
    f = facts(case, getattr(cfg, "external_url", "") or "")
    results = []
    for o in outs:
        if only and o.get("name") != only:
            continue
        if not only and not (set(o.get("when") or []) & ev):
            continue
        if not only and int(case.get("severity") or 0) < int(o.get("min_severity", 0) or 0):
            continue
        if case.get("restricted") and not o.get("include_restricted"):
            results.append({"name": o.get("name"), "ok": True,
                            "detail": "skipped: restricted case (set include_restricted: true to send)"})
            continue
        try:
            t = o["type"]
            if t == "email":
                detail = _send_email(o, f, smtp_cls=smtp_cls)
            elif t == "webhook":
                detail = send_webhook(o, f, session=session)
            elif t == "mcp_tool":
                if hub is None:
                    from ..connectors import get_hub
                    hub = get_hub(cfg)
                detail = call_tool(o, f, hub)
            else:
                continue                      # hunt-only output types (taxii)
            results.append({"name": o["name"], "ok": True, "detail": detail})
        except Exception as exc:
            results.append({"name": o.get("name"), "ok": False, "detail": f"{type(exc).__name__}: {exc}"[:300]})
    return results
