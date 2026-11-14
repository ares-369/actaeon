"""Prompts for the planner and analyst roles. Kept short so small local models cope."""

from __future__ import annotations

import json

from ..connectors.untrusted import SYSTEM_RULE

OUTCOME_HELP = """outcome must be one of:
- threat: evidence shows malicious or clearly suspicious activity (cite it)
- no_results: the relevant data was searched and nothing matched
- telemetry_found_benign: matching activity exists but it is explained and benign (cite it)
- logs_missing: the data needed to test the hypothesis is not there or could not be searched. If the kind of
  event the hypothesis needs (for example Windows process-access events, or email logs) never appears in any
  source at all, that is logs_missing, not no_results, even if your searches ran fine. Say so with
  "needed_data_present": false.
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
 "gaps": ["data you could not check"], "next_steps": ["what an analyst should do next"],
 "needed_data_present": true}}

Rules:
- Each tool result is labelled E1, E2, ... Cite only those labels. Never state a fact you cannot cite.
- Learn field names before searching (for example get_fields) and always bound searches by time.
- Pivot on what you find (host, user, hash, IP, domain), and check intel for indicators you see.
- If a command line looks encoded or obfuscated, decode it with an analysis tool before judging it.
- Missing data is not a clean result: if the data was not searchable, the outcome is logs_missing.
- Before calling something a threat, corroborate it: pivot to a second query (same host, user or destination
  around that time) and look up indicators in intel. Lower your confidence when only one result supports it.
- For "unusual", "new" or "rare" hypotheses, stack first: least common values (top_values with rare) or values
  first seen against a baseline (first_seen), then look closer at the few outliers.
- Prefer few, precise queries. Do not repeat a call you already made.
- Stop as soon as the evidence answers the hypothesis either way: once you have the activity plus the
  corroboration above, or you have searched the data the hypothesis needs and found nothing, give the verdict.
  More calls that only confirm what you already know cost time and tokens and do not make the verdict better.
{OUTCOME_HELP}
{SYSTEM_RULE}"""


def catalogue(tools: list[dict], compact: bool = False) -> str:
    """Tool list for the prompt. Compact mode keeps descriptions short and lists required args first."""
    lines = []
    for t in tools:
        props = (t.get("inputSchema") or {}).get("properties") or {}
        req = set((t.get("inputSchema") or {}).get("required") or [])
        items = list(props.items())
        if compact:
            items = [kv for kv in items if kv[0] in req] + [kv for kv in items if kv[0] not in req][:4]
        params = ", ".join(f"{k} ({(v or {}).get('type', 'any')}{', required' if k in req else ''})"
                           for k, v in items[:15])
        dialect = f" [query syntax: {t['dialect']}]" if t.get("dialect") and not compact else ""
        desc = t.get("description", "")[: 80 if compact else 200]
        lines.append(f"- connector \"{t['connector']}\", tool \"{t['name']}\" (role {t['role']}){dialect}: "
                     f"{desc} | args: {params or 'none'}")
    return "\n".join(lines) or "(no tools available)"


def guides(entries: dict[str, dict], compact: bool = False) -> str:
    """Per-connector query guidance: dialect, notes, examples from config, and queries that found data before."""
    out = []
    cap = 1200 if compact else 4000
    for conn, g in entries.items():
        parts = []
        if g.get("dialect"):
            parts.append(f"Query language: {g['dialect']}")
        if g.get("notes"):
            parts.append(g["notes"][:cap])
        ex = [e for e in g.get("examples") or []][: 3 if compact else 8]
        if ex:
            parts.append("Examples:\n" + "\n".join(f"- {e.get('goal') or 'example'}: {e['query']}" for e in ex))
        learned = [q for q in g.get("learned") or []][: 2 if compact else 5]
        if learned:
            parts.append("Queries that returned data here before:\n" + "\n".join(f"- {q}" for q in learned))
        if parts:
            out.append(f"### {conn}\n" + "\n".join(parts))
    return ("Query guides (how to search each connector):\n" + "\n\n".join(out)) if out else ""


def planner_user(hypothesis: str, roles: dict[str, list[str]], context: str) -> str:
    avail = ", ".join(f"{r} ({', '.join(c)})" for r, c in roles.items()) or "none"
    return f"Hypothesis: {hypothesis}\nAvailable data roles (connectors): {avail}\n{context}".strip()


def analyst_user(hypothesis: str, plan: dict | None, tools: list[dict], context: str, max_steps: int,
                 guide_text: str = "", compact: bool = False) -> str:
    p = json.dumps(plan, indent=None if compact else 1) if plan else "(no plan; decide the steps yourself)"
    g = f"{guide_text}\n\n" if guide_text else ""
    return (f"Hypothesis: {hypothesis}\n\nPlan:\n{p}\n\nTools:\n{catalogue(tools, compact)}\n\n{g}"
            f"{context}\nYou may make at most {max_steps} tool calls. Start now.").strip()
