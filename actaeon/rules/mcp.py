"""Read-only rule library tools for Actaeon's MCP server (agents can read rules and coverage, not approve)."""

from __future__ import annotations

from typing import Any

from ..bridges.server import ToolInputError


def add_tools(add, cfg) -> None:
    from . import service as S
    from .config import of

    def need_on() -> None:
        if not of(cfg).enabled:
            raise ToolInputError("the rule library is off (rules.enabled: false)")

    def list_rules(a: dict) -> Any:
        need_on()
        rows = S.store_for(cfg).list(status=a.get("status") or None, q=str(a.get("q", ""))[:200],
                                     technique=str(a.get("technique", "")).upper()[:20], limit=200)
        return {"rules": [{k: r.get(k) for k in ("id", "title", "status", "version", "level", "attack", "last_run")}
                          for r in rows if S.visible(r)]}

    def get_rule(a: dict) -> Any:
        need_on()
        d = S.detail(cfg, str(a.get("id", "")), actor="mcp")
        if not d:
            raise ToolInputError("no such rule")
        return {k: d.get(k) for k in ("id", "title", "status", "version", "sigma", "attack", "lint", "last_run",
                                      "ready_problems", "approved_by", "approved_at")} | {
            "tests": [{k: t[k] for k in ("name", "expect", "origin")} for t in d["tests"]]}

    def cov(a: dict) -> Any:
        need_on()
        c = S.coverage(cfg)
        if a.get("gaps_only"):
            c["techniques"] = [x for x in c["techniques"] if x["gap"]]
        return c

    add("list_rules", "Detection rules in the library (status draft/testing/ready/retired), filter by technique.",
        {"status": {"type": "string"}, "q": {"type": "string"}, "technique": {"type": "string"}}, list_rules)
    add("get_rule", "One detection rule: Sigma text, tests, lint and what stops it being ready.",
        {"id": {"type": "string"}}, get_rule, required=["id"])
    add("rule_coverage", "ATT&CK techniques covered by ready rules, and gaps (techniques hunts or cases found "
        "with no ready rule).", {"gaps_only": {"type": "boolean"}}, cov)
