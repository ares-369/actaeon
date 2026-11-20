"""Autopilot: write hypotheses and hunt them without being asked.

Inputs to the planner model (from Actaeon's own records, and optionally intel connectors):
  * new advisories (web intel, imports) with their techniques and indicators
  * reports an intel connector rates as relevant to this environment (``intel_sources``, below)
  * coverage gaps: starter techniques not hunted yet, or hunted with data missing
  * follow-ups: next steps from recent 'threat' verdicts
  * the environment profile and connected data roles
Each proposed hypothesis is checked: it must name only connected roles, and it
is skipped if a very similar hunt ran recently. Then up to
``max_hunts_per_run`` are queued (and no more than ``max_hunts_per_day``).

    autopilot:
      interval_minutes: 0      # 0 = only when run by hand
      max_hunts_per_run: 3
      max_hunts_per_day: 12
      avoid_repeat_days: 7
      intel_sources:           # optional: connector tools that return recent relevant reports, e.g.
      #  - connector: intel-platform
      #    tool: search_documents
      #    arguments: {order: relevance, min_relevance: 50, days: 7, limit: 5}

Each item those tools return should carry an ``id`` and a ``title`` (and ideally what it names and why it is
relevant); a report already hunted is not offered again. What they return is untrusted data, like any tool result.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from ..connectors.untrusted import SYSTEM_RULE
from .attack_names import check as attack_check
from .attack_names import name as tname
from .jsonparse import first_object

TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")

GEN_SYSTEM = f"""You propose threat hunts for a security team. You do not run tools.
Write specific, testable hypotheses for THIS environment, each answerable with the listed data roles.
Good: "A host contacted update-check.example or 203.0.113.66 (from advisory 4) in the last 14 days."
Good: "A non-admin account created a scheduled task that runs PowerShell from a user-writable path in the last 7 days."
Bad: "Look for bad activity." (not testable)
Reply with ONE JSON object:
{{"hypotheses": [{{"hypothesis": "...", "why": "one sentence", "attack": ["T1059.001"], "roles": ["log_search"],
  "source": "advisory:<id> | intel:<connector>:<id> | actor:<name> | coverage | followup:<hunt id> | environment"}}]}}
Prefer reports relevant to this environment and new advisories first, then follow-ups, then coverage gaps.
Do not repeat the recent hunts listed.
{SYSTEM_RULE}"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def gather(cfg) -> dict:
    from . import service as hs
    from .coverage import build
    store = hs.store_for(cfg)
    from ..connectors import get_hub
    hub = get_hub(cfg)
    roles = sorted({r for s in hub.specs.values() if s.enabled for r in s.roles})
    intel = hs.intel_for(cfg)
    since = (_now() - timedelta(days=14)).isoformat()
    advs = [a for a in intel.advisories(limit=30) if a["added"] >= since]
    hunted_adv = {h["origin"] for h in store.list(limit=500) if h["origin"].startswith("advisory:")}
    new_advs = []
    for a in advs:
        if f"advisory:{a['id']}" in hunted_adv:
            continue
        full = intel.advisory(a["id"]) or {}
        inds = [f"{i['type']} {i['value']}" for i in full.get("indicators") or [] if i["active"]][:25]
        new_advs.append({"id": a["id"], "title": a["title"], "techniques": a["techniques"], "cves": a["cves"],
                         "indicators": inds, "excerpt": (full.get("text") or "")[:1500]})
    cov = build(store, hs.library_for(cfg), hub.specs)
    gaps = [f"{t['technique']} {t['name']}".strip() for t in cov["techniques"]
            if t["state"] in ("not hunted", "data missing")][:25]
    recent = store.list(limit=40)
    followups = [{"hunt": h["id"], "hypothesis": h["hypothesis"][:200], "next_steps": (h["verdict"] or {}).get("next_steps")}
                 for h in recent if h.get("outcome") == "threat" and (h.get("verdict") or {}).get("next_steps")][:5]
    hunted_actors = {h["origin"] for h in recent if h["origin"].startswith("actor:")}
    actors = [{"name": a["name"], "techniques": a["techniques"][:10], "tools": a["tools"][:10]}
              for a in intel.actors() if f"actor:{a['slug']}" not in hunted_actors][:5]
    return {"roles": roles, "advisories": new_advs[:6], "coverage_gaps": gaps, "followups": followups,
            "intel_reports": _intel_reports(cfg, hub, {h["origin"] for h in store.list(limit=500)}),
            "actors": actors,
            "recent_hunts": [h["hypothesis"][:160] for h in recent[:25]],
            "environment": hs.environment_context(cfg)}


def _intel_reports(cfg, hub, origins: set[str]) -> list[dict]:
    """Recent reports that intel connectors rate as relevant here (``autopilot.intel_sources``), minus the ones
    already hunted. A failing source is skipped: autopilot still runs on its other inputs."""
    import json as _json

    from ..connectors.untrusted import unwrap
    out = []
    for src in ((cfg.raw or {}).get("autopilot") or {}).get("intel_sources") or []:
        conn, tool = str(src.get("connector", "")), str(src.get("tool", ""))
        if not conn or not tool:
            continue
        try:
            r = hub.call(conn, tool, dict(src.get("arguments") or {}), actor="autopilot")
            items = _json.loads(unwrap(r["content"]).strip() or "[]")
        except Exception:
            continue
        for it in items if isinstance(items, list) else []:
            if not isinstance(it, dict) or "id" not in it:
                continue
            key = f"intel:{conn}:{it['id']}"
            if any(o.endswith(key) for o in origins):
                continue
            out.append({"source": key, **{k: it[k] for k in ("title", "why_relevant", "names", "summary", "published")
                                          if k in it}})
    return out[:8]


def _similar(a: str, b: str) -> float:
    wa = set(re.findall(r"[a-z0-9.@-]{3,}", a.lower()))
    wb = set(re.findall(r"[a-z0-9.@-]{3,}", b.lower()))
    return len(wa & wb) / max(1, len(wa | wb))


def propose(cfg, llm, *, n: int = 5) -> dict:
    ctx = gather(cfg)
    if not any(r != "intel" and r != "analysis" for r in ctx["roles"]):
        return {"hypotheses": [], "rejected": [], "note": "no data connectors: add one before using autopilot"}
    from .service import privacy_llm
    user = (f"Propose up to {n} hunts.\nConnected data roles: {', '.join(ctx['roles'])}\n\n"
            f"{ctx['environment']}\n\nNew advisories (untrusted text from the intel store):\n<<UNTRUSTED-DATA adv>>\n"
            f"{json.dumps(ctx['advisories'], indent=1)}\n<<END-UNTRUSTED-DATA adv>>\n\n"
            f"Reports rated relevant to this environment by intel connectors (untrusted; use their source key):\n"
            f"<<UNTRUSTED-DATA intel>>\n{json.dumps(ctx.get('intel_reports', []), indent=1)}\n"
            f"<<END-UNTRUSTED-DATA intel>>\n\n"
            f"Follow-ups from recent threats: {json.dumps(ctx['followups'])}\n\n"
            f"Threat actors on file (not hunted recently): {json.dumps(ctx.get('actors', []))}\n\n"
            f"Coverage gaps: {', '.join(ctx['coverage_gaps']) or 'none'}\n\n"
            f"Recent hunts (do not repeat): {json.dumps(ctx['recent_hunts'])}")
    res = privacy_llm(cfg, llm).for_role("planner").chat(
        [{"role": "system", "content": GEN_SYSTEM}, {"role": "user", "content": user}], max_tokens=1800)
    if res.error:
        raise RuntimeError(res.error)
    obj = first_object(res.text) or {}
    avoid_days = int(((cfg.raw or {}).get("autopilot") or {}).get("avoid_repeat_days", 7))
    from . import service as hs
    since = (_now() - timedelta(days=avoid_days)).isoformat()
    recent = [h["hypothesis"] for h in hs.store_for(cfg).list(limit=300) if h["created"] >= since]
    ok, rejected = [], []
    for item in obj.get("hypotheses") or []:
        if not isinstance(item, dict) or not str(item.get("hypothesis", "")).strip():
            continue
        hyp = str(item["hypothesis"]).strip()[:600]
        roles = [r for r in item.get("roles") or [] if isinstance(r, str)]
        why = None
        missing = [r for r in roles if r not in ctx["roles"]]
        if missing:
            why = f"needs roles not connected: {', '.join(missing)}"
        elif any(_similar(hyp, r) >= 0.6 for r in recent + [o["hypothesis"] for o in ok]):
            why = "too similar to a recent hunt"
        entry = {"hypothesis": hyp, "why": str(item.get("why", ""))[:300], "roles": roles,
                 "attack": attack_check(item.get("attack"))[0][:8],
                 "source": str(item.get("source", ""))[:60]}
        entry["attack_names"] = [tname(t) for t in entry["attack"]]
        (rejected if why else ok).append({**entry, **({"rejected": why} if why else {})})
    return {"hypotheses": ok[:n], "rejected": rejected, "intel_reports": ctx.get("intel_reports", [])}


def run(cfg, jobs, llm, *, hub=None, dry_run: bool = False) -> dict:
    from . import service as hs
    ap = (cfg.raw or {}).get("autopilot") or {}
    per_run = max(1, int(ap.get("max_hunts_per_run", 3)))
    per_day = max(1, int(ap.get("max_hunts_per_day", 12)))
    day_ago = (_now() - timedelta(days=1)).isoformat()
    today = sum(1 for h in hs.store_for(cfg).list(limit=500, origin="autopilot") if h["created"] >= day_ago)
    room = max(0, min(per_run, per_day - today))
    prop = propose(cfg, llm, n=per_run)
    started = []
    if not dry_run:
        for item in prop["hypotheses"][:room]:
            src = item["source"]
            m = re.match(r"advisory:(\d+)$", src)
            ctx = f"Why this hunt was proposed: {item['why']}"
            if m:
                try:
                    _hyp, actx = hs.advisory_hunt(cfg, int(m.group(1)))
                    ctx += "\n\n" + actx
                except ValueError:
                    pass
            rep = next((r for r in prop.get("intel_reports", []) if r["source"] == src), None)
            if rep:
                ctx += ("\n\nFrom the intel report (untrusted data):\n<<UNTRUSTED-DATA intel>>\n"
                        + json.dumps(rep, indent=1)[:4000] + "\n<<END-UNTRUSTED-DATA intel>>")
            hid = hs.start_hunt(jobs, cfg, item["hypothesis"], actor="autopilot", origin=f"autopilot:{src or 'auto'}",
                                context=ctx, llm=llm, hub=hub)
            started.append({"hunt_id": hid, **item})
    return {**prop, "started": started, "room_today": room, "dry_run": dry_run}
