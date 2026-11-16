"""Alert-case tools for Actaeon's MCP server. There is no tool to approve a response action: approvals
are for people, in the UI or the API, so an agent can never approve an action it asked for."""

from __future__ import annotations

from typing import Any

from ..bridges.server import ToolInputError

OPERATOR_TOOLS = {"submit_alerts", "triage_case"}


def _slim(c: dict, *, evidence: bool = False) -> dict:
    keep = ("id", "title", "status", "verdict", "confidence", "severity", "severity_label", "summary", "created",
            "triaged_at", "analyst_verdict", "closed_at", "attack")
    out = {k: c.get(k) for k in keep}
    r = c.get("report") or {}
    out.update({k: r.get(k) for k in ("findings", "fix", "gaps", "next_steps", "checks") if r.get(k)})
    if "alerts" in c:
        out["alerts"] = [{k: a.get(k) for k in ("id", "ts", "title", "rule_id", "severity", "entities")}
                         for a in c["alerts"][:50]]
    if "actions" in c:
        out["actions"] = [{k: a.get(k) for k in ("id", "name", "target", "status", "reason")} for a in c["actions"]]
    if evidence and "steps" in c:
        out["evidence"] = [{"id": f"E{s['n']}", "tool": f"{s['connector']}.{s['tool']}", "ok": s["ok"],
                            "arguments": s["arguments"], "result": (s.get("result") or "")[:3000]}
                           for s in c["steps"] if s["kind"] == "call"]
    return out


def add_tools(add, cfg, jobs, *, work: dict) -> None:
    from ..access import can_see
    from . import service
    from .intake import ingest
    from .report import case_markdown

    def store():
        return service.store_for(cfg)

    def visible(c: dict) -> bool:
        return can_see(c.get("restricted") or [])

    def list_cases(a: dict) -> Any:
        rows = store().cases(status=a.get("status") or None, verdict=a.get("verdict") or None,
                             open_only=bool(a.get("open_only")), limit=min(200, int(a.get("limit", 50))))
        return {"cases": [{k: c.get(k) for k in ("id", "title", "status", "verdict", "confidence", "severity_label",
                                                 "created", "alert_count", "pending_actions")}
                          for c in rows if visible(c)]}

    def get_case(a: dict) -> Any:
        c = store().get_case(str(a.get("id", "")))
        if not c or not visible(c):
            raise ToolInputError("no such case")
        return case_markdown(c) if a.get("format") == "markdown" else _slim(c, evidence=bool(a.get("evidence")))

    def submit_alerts(a: dict) -> Any:
        items = a.get("alerts")
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list):
            raise ToolInputError("alerts must be an object or a list of objects")
        out = ingest(cfg, store(), items, source=str(a.get("source") or "mcp")[:40])
        if cfg.soc.auto:
            out["queued"] = service.queue_new(cfg, jobs)
        return out

    def triage(a: dict) -> Any:
        cid = str(a.get("id", ""))
        c = store().get_case(cid, full=False)
        if not c or not visible(c):
            raise ToolInputError("no such case")
        return {"id": cid, "job_id": service.submit_triage(cfg, jobs, cid, actor="mcp", manual=True)}

    add("list_cases", "Alert cases (most severe first) with the AI verdict.",
        {"status": {"type": "string"}, "verdict": {"type": "string"}, "open_only": {"type": "boolean"},
         "limit": {"type": "integer"}}, list_cases)
    add("get_case", "One alert case: alerts, verdict, findings, fix, proposed actions. evidence=true adds tool "
        "results; format=markdown gives the report.",
        {"id": {"type": "string"}, "evidence": {"type": "boolean"},
         "format": {"type": "string", "enum": ["json", "markdown"]}}, get_case, required=["id"])
    add("submit_alerts", "Send one alert or a list of alerts (JSON objects) into the triage queue.",
        {"alerts": {"type": "array", "items": {"type": "object"}}, "source": {"type": "string"}}, submit_alerts,
        required=["alerts"], ann=work)
    add("triage_case", "Start (or redo) the AI investigation of an alert case; poll get_case until its status "
        "is not 'triaging'.", {"id": {"type": "string"}}, triage, required=["id"], ann=work)
