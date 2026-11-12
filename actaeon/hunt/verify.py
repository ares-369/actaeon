"""Second look: re-query to decide whether a threat is real.

After a hunt (or sweep) ends in ``threat``, a verifier pass runs on the analyst
model with fresh instructions: try to prove the finding wrong. It re-runs or
widens the key searches, checks whether the activity is still happening, looks
for a benign explanation (admin tools, software updates, known service accounts,
analyst notes), and checks a second data source. Its calls are added to the hunt
as evidence. Result:

  confirmed    independent evidence supports the threat (confidence may rise to 95)
  refuted      evidence shows a benign explanation: outcome becomes inconclusive,
               flagged for review (a threat is never silently dismissed)
  unconfirmed  could not confirm: confidence capped at 60, flagged for review
"""

from __future__ import annotations

import json

from ..connectors.untrusted import SYSTEM_RULE
from .signals import payload
from .toolloop import available_tools, run_loop

MAX_CALLS = 6
VERIFY_SYSTEM = f"""You are a second, sceptical analyst. Another analyst concluded THREAT. Your job is to test that.
Re-run or widen the key searches, check whether the activity continues, look for a benign explanation (admin
tools, software updates, known service accounts, the analyst notes), and check a second data source.
Reply with exactly ONE JSON object. Either a read-only tool call:
{{"action": "call", "connector": "name", "tool": "tool_name", "arguments": {{}}, "thought": "what this tests"}}
or your result:
{{"action": "verify", "result": "confirmed|refuted|unconfirmed", "reason": "two sentences", "evidence": ["E9"]}}
Use confirmed only with independent evidence you cite. Use refuted only with evidence of a benign explanation.
Bound every search by time. At most {MAX_CALLS} calls.
{SYSTEM_RULE}"""


def _brief(h: dict) -> str:
    v = h.get("verdict") or {}
    lines = [f"Hypothesis: {h['hypothesis']}", f"Verdict: {v.get('outcome')} (confidence {v.get('confidence')}): "
             f"{v.get('summary', '')}"]
    lines += [f"Finding: {f['claim']} ({', '.join(f['evidence'])})" for f in v.get("findings") or []]
    for s in [s for s in h.get("steps") or [] if s["kind"] == "call" and s["ok"]][-8:]:
        lines.append(f"E{s['n']} {s['connector']}.{s['tool']} {json.dumps(s.get('arguments'), default=str)[:300]}\n"
                     f"<<UNTRUSTED-DATA v>>\n{payload(s.get('result') or '')[:1500]}\n<<END-UNTRUSTED-DATA v>>")
    return "\n".join(lines)


def verify(cfg, h: dict, *, llm, hub, context: str = "") -> dict:
    from . import service as hs
    store = hs.store_for(cfg)
    from .prompts import catalogue
    tools = available_tools(hub)
    user = (f"{_brief(h)}\n\n{context}\n\nTools:\n{catalogue(tools, compact=True)}\n\n"
            "Test the conclusion now.")
    final, made, calls = run_loop(llm=llm, hub=hub, store=store, hid=h["id"], system=VERIFY_SYSTEM, user=user,
                                  final_action="verify", max_calls=MAX_CALLS, max_results=cfg.hunt.max_results,
                                  actor="verifier", why_prefix="verify")
    final = final or {}
    result = final.get("result") if final.get("result") in ("confirmed", "refuted", "unconfirmed") else "unconfirmed"
    good = {f"E{s['n']}" for s in (store.get(h["id"]) or {}).get("steps") or [] if s["kind"] == "call" and s["ok"]}
    cited = [e for e in final.get("evidence") or [] if isinstance(e, str) and e in good]
    if result == "confirmed" and not set(cited) & set(made):
        result = "unconfirmed"     # confirmation needs evidence the verifier gathered itself
    return {"result": result, "reason": str(final.get("reason") or final.get("error") or final.get("text", ""))[:800],
            "evidence": cited, "new_evidence": made, "calls": calls}


def apply(h: dict, ver: dict) -> dict:
    """Fold a verification result into the verdict."""
    v = dict(h.get("verdict") or {})
    v["verification"] = ver
    checks = list(v.get("checks") or [])
    conf = int(v.get("confidence") or 0)
    if ver["result"] == "confirmed":
        v["confidence"] = min(95, max(conf, 80))
        checks.append("verified: a second pass found independent evidence")
    elif ver["result"] == "refuted":
        v["outcome"] = "inconclusive"
        v["needs_review"] = True
        v["confidence"] = min(conf, 40)
        checks.append("a second pass found a benign explanation; review before closing")
    else:
        v["confidence"] = min(conf, 60)
        v["needs_review"] = True
        checks.append("a second pass could not confirm this; review it")
    v["checks"] = checks
    return v
