"""Is a new advisory relevant to this environment? Decide before spending a hunt on it.

Two steps, cheapest first:
  1. Terms: the advisory must mention something this environment runs. Terms come from
     ``environment.platforms`` and ``environment.products`` plus ``intel.web.relevance.terms``.
     No term matched means not relevant, and no model call is made.
  2. Model (when a model is available and ``intel.web.relevance.model`` is not false): the reporter
     model reads the environment profile and the advisory and answers in JSON whether the affected
     product, version or technique applies here, with a reason and a hunt hypothesis.

The decision is stored on the advisory (the intel ledger) whether it is relevant or not, so the
team can see why each article was or was not hunted.
"""

from __future__ import annotations

import json
import re

from ..connectors.untrusted import SYSTEM_RULE

RELEVANCE_SYSTEM = f"""You decide whether a security news item or advisory is relevant to ONE specific environment.
Relevant means: a product, platform or service named in the item runs in this environment, or the attack
technique it describes would work against what runs here, so a threat hunt in this environment's logs could
find it. Mentioning a technology in passing is not enough. Vendor marketing, opinion pieces, funding news and
arrests without technical detail are not relevant.
Reply with ONE JSON object only:
{{"relevant": true|false, "score": 0-100, "why": "one sentence naming the matching product or technique",
"products": ["affected products that run here"], "hypothesis": "one testable hunt hypothesis for this
environment, or empty if not relevant"}}
{SYSTEM_RULE}"""


def environment_terms(cfg) -> list[str]:
    env = (cfg.raw or {}).get("environment") or {}
    rel = (((cfg.intel or {}).get("web") or {}).get("relevance") or {})
    terms: list[str] = []
    for key in ("platforms", "products"):
        v = env.get(key) or []
        terms += v if isinstance(v, list) else [v]
    terms += rel.get("terms") or []
    out, seen = [], set()
    for t in terms:
        t = str(t).strip()
        if len(t) >= 3 and t.lower() not in seen:
            seen.add(t.lower())
            out.append(t)
    return out


def matched_terms(text: str, terms: list[str]) -> list[str]:
    low = text.lower()
    hits = []
    for t in terms:
        if re.search(r"(?<![a-z0-9])" + re.escape(t.lower()) + r"(?![a-z0-9])", low):
            hits.append(t)
    return hits


def assess(cfg, adv: dict, *, llm=None) -> dict:
    """Return {relevant, score, why, matched, products, hypothesis, method}."""
    rel_cfg = (((cfg.intel or {}).get("web") or {}).get("relevance") or {})
    terms = environment_terms(cfg)
    text = f"{adv.get('title', '')}\n{adv.get('text', '')}"
    hits = matched_terms(text[:60_000], terms)
    base = {"matched": hits[:20], "products": [], "hypothesis": ""}
    if not terms:
        has = bool(adv.get("indicators") or adv.get("techniques"))
        return {**base, "relevant": has, "score": 50 if has else 0, "method": "none",
                "why": ("no environment terms configured; it lists indicators or techniques to hunt" if has else
                        "no environment terms configured and it lists no indicators or techniques")}
    if not hits:
        return {**base, "relevant": False, "score": 0, "method": "terms",
                "why": "mentions nothing listed in the environment profile"}
    if llm is None or rel_cfg.get("model") is False:
        return {**base, "relevant": True, "score": 60, "method": "terms",
                "why": f"mentions {', '.join(hits[:5])}"}
    from ..hunt.jsonparse import first_object
    from ..hunt.service import environment_context
    user = (f"{environment_context(cfg) or 'No environment profile written.'}\n"
            f"Terms from this environment that the item mentions: {', '.join(hits[:20])}\n\n"
            f"Item (untrusted):\n<<UNTRUSTED-DATA advisory>>\nTitle: {adv.get('title', '')}\n"
            f"{(adv.get('text') or '')[:5000]}\n<<END-UNTRUSTED-DATA advisory>>")
    res = llm.for_role("reporter").chat([{"role": "system", "content": RELEVANCE_SYSTEM},
                                         {"role": "user", "content": user}], max_tokens=500)
    obj = first_object(res.text or "") if not res.error else None
    if not isinstance(obj, dict) or "relevant" not in obj:
        # Model unavailable or unclear: fall back to the term match, and say so.
        return {**base, "relevant": True, "score": 50, "method": "terms",
                "why": f"mentions {', '.join(hits[:5])} (model check failed: {(res.error or 'no JSON')[:80]})"}
    try:
        score = max(0, min(100, int(obj.get("score", 0))))
    except (TypeError, ValueError):
        score = 0
    relevant = bool(obj.get("relevant")) and score >= int(rel_cfg.get("min_score", 50))
    return {**base, "relevant": relevant, "score": score, "method": "model",
            "why": str(obj.get("why") or "")[:400],
            "products": [str(p)[:80] for p in (obj.get("products") or [])][:10],
            "hypothesis": str(obj.get("hypothesis") or "")[:500] if relevant else ""}


def as_json(decision: dict) -> str:
    return json.dumps(decision, ensure_ascii=False)
