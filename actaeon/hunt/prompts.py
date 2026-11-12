"""Prompts for the planner and analyst roles. Kept short so small local models cope."""

from __future__ import annotations

import json

from ..connectors.untrusted import SYSTEM_RULE

OUTCOME_HELP = """outcome must be one of:
- threat: evidence shows malicious or clearly suspicious activity (cite it)
- no_results: the relevant data was searched and nothing matched
- telemetry_found_benign: matching activity exists but it is explained and benign (cite it)
- logs_missing: the data needed to test the hypothesis is not there or could not be searched
- inconclusive: something else stopped a clear answer"""

PLANNER_SYSTEM = f"""You plan threat hunts. You do not run tools.
Given a hypothesis and the data roles available, reply with ONE JSON object:
{{"summary": "one sentence", "attack": ["T1059.001"], "steps": [{{"role": "log_search", "goal": "what to look for and why"}}], "data_needed": ["log_search"]}}
Use MITRE ATT&CK technique IDs you are confident about. Use only the roles listed. 2 to 8 steps.
{SYSTEM_RULE}"""

ANALYST_SYSTEM = f"""You are a careful threat hunter testing one hypothesis with read-only tools.
Reply with exactly ONE JSON object and nothing else. Either call a tool:
{{"thought": "short reason", "action": "call", "connector": "name", "tool": "tool_name", "arguments": {{}}}}
or give the verdict:
{{"action": "verdict", "outcome": "no_results", "confidence": 60, "summary": "two or three sentences",
 "findings": [{{"claim": "what you found", "evidence": ["E2"]}}], "attack": ["T1059.001"],
 "gaps": ["data you could not check"], "next_steps": ["what an analyst should do next"]}}

Rules:
- Each tool result is labelled E1, E2, ... Cite only those labels. Never state a fact you cannot cite.
- Learn field names before searching (for example get_fields) and always bound searches by time.
- Pivot on what you find (host, user, hash, IP, domain), and check intel for indicators you see.
- If a command line looks encoded or obfuscated, decode it with an analysis tool before judging it.
- Missing data is not a clean result: if the data was not searchable, the outcome is logs_missing.
- Before calling something a threat, corroborate it: pivot to a second query (same host, user or destination
  around that time) and look up indicators in intel. Lower your confidence when only one result supports it.
- Prefer few, precise queries. Do not repeat a call you already made.
{OUTCOME_HELP}
{SYSTEM_RULE}"""


def catalogue(tools: list[dict]) -> str:
    """Compact tool list for the prompt."""
    lines = []
    for t in tools:
        props = (t.get("inputSchema") or {}).get("properties") or {}
        req = set((t.get("inputSchema") or {}).get("required") or [])
        params = ", ".join(f"{k} ({(v or {}).get('type', 'any')}{', required' if k in req else ''})"
                           for k, v in list(props.items())[:15])
        dialect = f" [query syntax: {t['dialect']}]" if t.get("dialect") else ""
        lines.append(f"- connector \"{t['connector']}\", tool \"{t['name']}\" (role {t['role']}){dialect}: "
                     f"{t.get('description', '')[:200]} | args: {params or 'none'}")
    return "\n".join(lines) or "(no tools available)"


def planner_user(hypothesis: str, roles: dict[str, list[str]], context: str) -> str:
    avail = ", ".join(f"{r} ({', '.join(c)})" for r, c in roles.items()) or "none"
    return f"Hypothesis: {hypothesis}\nAvailable data roles (connectors): {avail}\n{context}".strip()


def analyst_user(hypothesis: str, plan: dict | None, tools: list[dict], context: str, max_steps: int) -> str:
    p = json.dumps(plan, indent=1) if plan else "(no plan; decide the steps yourself)"
    return (f"Hypothesis: {hypothesis}\n\nPlan:\n{p}\n\nTools:\n{catalogue(tools)}\n\n"
            f"{context}\nYou may make at most {max_steps} tool calls. Start now.").strip()
