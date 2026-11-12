"""Hunt reports and exports, built from the stored record (no model needed).

An optional narrative from the reporter model can be added; it is labelled as
model-written and placed after the factual record.
"""

from __future__ import annotations

import csv
import io
import json

from .attack_names import name
from .signals import payload

OUTCOME_TEXT = {
    "threat": "Threat found", "no_results": "No results", "telemetry_found_benign": "Activity found, benign",
    "logs_missing": "Logs missing", "inconclusive": "Inconclusive",
}


def _md_escape(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def markdown(h: dict, *, narrative: str = "", max_evidence_chars: int = 3000) -> str:
    v = h.get("verdict") or {}
    p = h.get("plan") or {}
    out = [f"# Hunt report: {h['hypothesis']}", "",
           f"- Hunt id: `{h['id']}`", f"- Started: {h['created']}  Finished: {h.get('finished') or '-'}",
           f"- Status: {h['status']}  Origin: {h.get('origin', '')}  By: {h.get('actor') or '-'}"]
    if h.get("models"):
        out.append("- Models: " + ", ".join(f"{r} = {m['provider']}/{m['model']}" for r, m in h["models"].items()))
    out += ["", f"## Verdict: {OUTCOME_TEXT.get(v.get('outcome'), v.get('outcome', '-'))} "
                f"(confidence {v.get('confidence', 0)})", "", v.get("summary", "") or "-", ""]
    if v.get("findings"):
        out.append("### Findings (each cites evidence below)")
        out += [f"- {f['claim']} ({', '.join(f['evidence'])})" for f in v["findings"]]
        out.append("")
    if v.get("unsupported_claims"):
        out.append("### Claims without evidence (not verified)")
        out += [f"- {f['claim']}" for f in v["unsupported_claims"]]
        out.append("")
    techs = list(dict.fromkeys((p.get("attack") or []) + (v.get("attack") or [])))
    if techs:
        out.append("### ATT&CK")
        out += [f"- {t} {name(t)}".rstrip() for t in techs]
        out.append("")
    for title, key in (("Gaps", "gaps"), ("Next steps", "next_steps"), ("Checks applied", "checks")):
        if v.get(key):
            out.append(f"### {title}")
            out += [f"- {x}" for x in v[key]]
            out.append("")
    if p:
        out += ["## Plan", "", p.get("summary", ""), ""]
        out += [f"- [{s['role']}] {s['goal']}" for s in p.get("steps") or []]
        if p.get("missing_roles"):
            out.append(f"- No connector for: {', '.join(p['missing_roles'])}")
        out.append("")
    out += ["## Steps", "", "| # | Kind | Tool | OK | ms | Note |", "|---|---|---|---|---|---|"]
    for s in h.get("steps") or []:
        if s["kind"] == "verdict":
            continue
        tool = f"{s['connector']}.{s['tool']}" if s.get("tool") else ""
        ok = "" if s["ok"] is None else ("yes" if s["ok"] else "no")
        out.append(f"| E{s['n']} | {s['kind']} | {_md_escape(tool)} | {ok} | {s['ms'] or ''} | "
                   f"{_md_escape((s.get('note') or s.get('why') or '')[:160])} |")
    out += ["", "## Evidence", ""]
    for s in h.get("steps") or []:
        if s["kind"] != "call":
            continue
        body = payload(s.get("result") or "")
        if len(body) > max_evidence_chars:
            body = body[:max_evidence_chars] + "\n[truncated; full result in the JSON export]"
        out += [f"### E{s['n']}: {s['connector']}.{s['tool']}", "", "Arguments:", "",
                "```json", json.dumps(s.get("arguments"), indent=1), "```", "",
                "Result (data from the source):", "", "```", body.replace("```", "'''"), "```", ""]
    if narrative:
        out += ["## Narrative (written by the reporter model; check it against the record above)", "", narrative, ""]
    return "\n".join(out)


def steps_csv(h: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["hunt_id", "step", "ts", "kind", "connector", "tool", "role", "ok", "ms", "arguments", "note",
                "result_chars"])
    for s in h.get("steps") or []:
        cells = [h["id"], f"E{s['n']}", s["ts"], s["kind"], s.get("connector") or "", s.get("tool") or "",
                 s.get("role") or "", "" if s["ok"] is None else int(s["ok"]), s.get("ms") or "",
                 json.dumps(s.get("arguments")) if s.get("arguments") is not None else "",
                 (s.get("note") or "")[:500], len(s.get("result") or "")]
        # keep spreadsheet apps from treating cell text as a formula
        w.writerow([("'" + c) if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") else c for c in cells])
    return buf.getvalue()


def narrative(llm, h: dict) -> str:
    """Ask the reporter model for a short write-up of the record. Returns '' on failure."""
    from ..connectors.untrusted import SYSTEM_RULE
    v = h.get("verdict") or {}
    facts = {"hypothesis": h["hypothesis"], "verdict": {k: v.get(k) for k in
             ("outcome", "confidence", "summary", "findings", "gaps", "next_steps", "attack")},
             "steps": [{"id": f"E{s['n']}", "tool": f"{s['connector']}.{s['tool']}", "ok": s["ok"],
                        "result": payload(s.get("result") or "")[:800]} for s in h.get("steps") or []
                       if s["kind"] == "call"][:15]}
    msgs = [{"role": "system", "content": "Write a short, plain hunt summary for a SOC lead: what was tested, what "
             "was searched, what was found, and what to do next. Cite evidence ids like (E3). Do not add facts "
             "that are not in the record. No more than 250 words. " + SYSTEM_RULE},
            {"role": "user", "content": json.dumps(facts)}]
    try:
        res = llm.for_role("reporter").chat(msgs, max_tokens=700)
    except Exception:
        return ""
    return "" if res.error else (res.text or "").strip()
