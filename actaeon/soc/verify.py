"""Second look: try to prove the verdict wrong before an analyst sees it.

Two kinds:
* on a ``true_positive``: try to find a benign explanation (below);
* on a ``false_positive`` or ``benign`` verdict for a high or critical case (``soc.verify_dismissals``):
  try to show it IS a threat. A citation proves where a fact came from, not that it supports the
  dismissal, so a confident "expected activity" on a serious alert gets the same scrutiny.


A citation shows where a claim came from, not that the claim follows from it. So after the
investigator says ``true_positive``, a second pass runs on the analyst model with fresh instructions:
re-run or widen the key searches, look for a benign explanation, check another source. Its calls are
added to the case as evidence. Result:

  confirmed    it gathered and cited independent evidence (confidence at least 80, at most 95)
  refuted      it found a benign explanation: the case goes to an analyst as needs_analyst and the
               proposed actions are dropped (a threat is never silently dismissed)
  unconfirmed  it could not confirm: confidence capped at 60, with a note
"""

from __future__ import annotations

import json

from ..connectors.untrusted import SYSTEM_RULE
from ..hunt.toolloop import run_loop
from .util import payload

MAX_CALLS = 5
VERIFY_SYSTEM = f"""You are a second analyst reviewing an alert case. The first analyst concluded TRUE POSITIVE.
Your job is to test that conclusion. Re-run or widen the key searches, check whether the activity continues, look
for a benign explanation (admin tools, software updates, known service accounts, the environment notes), and check
a second data source if there is one.
Reply with exactly ONE JSON object. Either a read-only tool call:
{{"action": "call", "connector": "name", "tool": "tool_name", "arguments": {{}}, "thought": "what this tests"}}
or your result:
{{"action": "verify", "result": "confirmed|refuted|unconfirmed", "reason": "two sentences", "evidence": ["E9"]}}
Use confirmed only with evidence from your own calls that you cite. Use refuted only with evidence of a benign
explanation. Bound every search by time. At most {MAX_CALLS} calls.
{SYSTEM_RULE}"""


DISMISS_SYSTEM = f"""You are a second analyst reviewing an alert case. The first analyst concluded it is NOT a threat
(false positive or expected activity). Your job is to test that. Check that the evidence really explains THIS alert:
same host, same time, same activity. Look for signs of a real attack the first analyst missed (unusual process,
account, destination or time; the activity on other hosts; what happened just before and after).
Reply with exactly ONE JSON object. Either a read-only tool call:
{{"action": "call", "connector": "name", "tool": "tool_name", "arguments": {{}}, "thought": "what this tests"}}
or your result:
{{"action": "verify", "result": "confirmed|refuted|unconfirmed", "reason": "two sentences", "evidence": ["E9"]}}
confirmed = your own evidence supports that it is not a threat. refuted = your own evidence shows it may be a
threat. unconfirmed = you could not check it. Cite evidence from your own calls. Bound every search by time.
At most {MAX_CALLS} calls.
{SYSTEM_RULE}"""


class _Steps:
    """What the shared tool loop needs from a store, on top of the case store."""

    def __init__(self, store):
        self.store = store

    def get(self, hid: str) -> dict:
        return self.store.get_case(hid.removeprefix("case:")) or {}

    def add_step(self, hid: str, n: int, kind: str, **kw) -> None:
        self.store.add_step(hid.removeprefix("case:"), n, kind, **kw)


def _brief(case: dict, v: dict, tools: list[dict], environment: dict) -> str:
    lines = [f"Case: {v.get('title') or case.get('title')}",
             f"Verdict: {v.get('verdict')} (confidence {v.get('confidence')}): {v.get('summary', '')}"]
    from .prompts import _alerts_text
    lines.append("Alerts:\n" + _alerts_text(case.get("alerts") or [], limit=4, raw_chars=600))
    lines += [f"Finding: {f.get('text')} ({', '.join(f.get('evidence') or [])})" for f in v.get("findings") or []]
    if environment:
        lines.append("Environment: " + json.dumps(environment)[:1500])
    for s in [s for s in case.get("steps") or [] if s["kind"] == "call" and s["ok"]][-6:]:
        lines.append(f"E{s['n']} {s['connector']}.{s['tool']} {json.dumps(s.get('arguments'), default=str)[:300]}\n"
                     f"<<UNTRUSTED-DATA v>>\n{payload(s.get('result') or '')[:1200]}\n<<END-UNTRUSTED-DATA v>>")
    lines.append("Tools:")
    for t in tools:
        props = ", ".join(((t.get("inputSchema") or {}).get("properties") or {}).keys())
        lines.append(f"- {t['connector']}.{t['name']}: {t.get('description', '')[:160]} args: {props}")
    lines.append("Test the conclusion now.")
    return "\n".join(lines)


def verify(cfg, store, case_id: str, v: dict, *, llm, hub, tools: list[dict]) -> dict:
    case = store.get_case(case_id) or {}
    final, made, calls = run_loop(
        llm=llm, hub=hub, store=_Steps(store), hid=f"case:{case_id}",
        system=VERIFY_SYSTEM if v.get("verdict") == "true_positive" else DISMISS_SYSTEM,
        user=_brief(case, v, tools, (cfg.raw or {}).get("environment") or {}), final_action="verify",
        max_calls=MAX_CALLS, max_results=cfg.soc.max_results, actor="verifier", why_prefix="verify",
        max_tokens=cfg.soc.max_tokens)
    final = final or {}
    result = final.get("result") if final.get("result") in ("confirmed", "refuted", "unconfirmed") else "unconfirmed"
    good = {f"E{s['n']}" for s in (store.get_case(case_id) or {}).get("steps") or [] if s["kind"] == "call" and s["ok"]}
    cited = [e for e in final.get("evidence") or [] if isinstance(e, str) and e in good]
    if result in ("confirmed", "refuted") and not set(cited) & set(made):
        result = "unconfirmed"     # either conclusion needs evidence the verifier gathered itself
    return {"result": result, "reason": str(final.get("reason") or final.get("error") or final.get("text", ""))[:800],
            "evidence": cited, "new_evidence": made, "calls": calls}


def apply(v: dict, ver: dict) -> dict:
    """Fold the second look into the checked verdict."""
    v = dict(v)
    v["verification"] = ver
    checks = list(v.get("checks") or [])
    conf = int(v.get("confidence") or 0)
    if v.get("verdict") in ("false_positive", "benign"):
        if ver["result"] == "confirmed":
            checks.append("verified: a second pass found independent evidence that this is not a threat")
        elif ver["result"] == "refuted":
            v["verdict"] = "needs_analyst"
            v["confidence"] = min(conf, 40)
            checks.append("a second pass found signs that this may be a threat after all; review it: "
                          + ver["reason"][:300])
        else:
            v["confidence"] = min(conf, 60)
            checks.append("a second pass could not confirm that this is not a threat; review before closing")
        v["checks"] = checks
        return v
    if ver["result"] == "confirmed":
        v["confidence"] = min(95, max(conf, 80))
        checks.append("verified: a second pass found independent evidence")
    elif ver["result"] == "refuted":
        v["verdict"] = "needs_analyst"
        v["confidence"] = min(conf, 40)
        v["actions"] = []
        checks.append("a second pass found a benign explanation for this true positive; review before closing: "
                      + ver["reason"][:300])
    else:
        v["confidence"] = min(conf, 60)
        checks.append("a second pass could not confirm this true positive; review the evidence")
    v["checks"] = checks
    return v
