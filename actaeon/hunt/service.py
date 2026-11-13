"""Glue between the hunt engine, library, sweeps, memory, the job runner, config and the hub."""

from __future__ import annotations

from .engine import HuntEngine, HuntLimits
from .library import Library, replay, replay_context
from .memory import HuntMemory
from .store import HuntStore
from .sweep import Sweep


def store_for(cfg) -> HuntStore:
    return HuntStore(cfg.data_dir / "hunts.sqlite")


def library_for(cfg) -> Library:
    store_for(cfg)
    return Library(cfg.data_dir / "hunts.sqlite")


def memory_for(cfg) -> HuntMemory:
    return HuntMemory(cfg.data_dir / "hunts.sqlite")


def intel_for(cfg):
    from ..intel import IntelStore
    return IntelStore(cfg.data_dir / "intel.sqlite")


def limits_for(cfg, max_steps: int | None = None) -> HuntLimits:
    h = cfg.hunt
    steps = h.max_steps if max_steps is None else max(1, min(int(max_steps), h.max_steps))
    compact = str(((cfg.raw or {}).get("hunt") or {}).get("prompt_mode", "full")) == "compact"
    return HuntLimits(max_steps=steps, max_runtime_sec=h.max_runtime_sec, max_results=h.max_results, compact=compact)


def _hub(cfg, hub=None):
    if hub is not None:
        return hub
    from ..connectors import get_hub
    return get_hub(cfg)


def environment_context(cfg) -> str:
    """The analyst-written environment profile, so hunts fit what actually runs here."""
    env = (cfg.raw or {}).get("environment") or {}
    if not env:
        return ""
    lines = ["About this environment (written by the team):"]
    if env.get("summary"):
        lines.append(str(env["summary"])[:1500])
    for key, label in (("platforms", "Platforms in use"), ("crown_jewels", "Most important assets"),
                       ("not_present", "Not present here (do not hunt for these)"),
                       ("known_good", "Known good here (normal activity; still report it if it is being misused)"),
                       ("notes", "Notes")):
        vals = env.get(key)
        if vals:
            vals = vals if isinstance(vals, list) else [vals]
            lines.append(f"{label}: " + "; ".join(str(v)[:300] for v in vals[:30]))
    return "\n".join(lines)


def privacy_llm(cfg, llm):
    from ..privacy import PrivacyLLM
    return PrivacyLLM(llm, (cfg.raw or {}).get("privacy") or {})


def make_engine(cfg, *, checkpoint=None, on_event=None, max_steps: int | None = None, llm=None, hub=None):
    from ..providers import get_llm
    kg = ((cfg.raw or {}).get("environment") or {}).get("known_good") or []
    return HuntEngine(privacy_llm(cfg, llm or get_llm()), _hub(cfg, hub), store_for(cfg),
                      limits_for(cfg, max_steps), checkpoint=checkpoint, on_event=on_event,
                      known_good=kg if isinstance(kg, list) else [kg])


def run_hunt(cfg, hypothesis: str, *, hunt_id: str | None = None, origin: str = "manual", actor: str = "",
             context: str = "", max_steps: int | None = None, checkpoint=None, on_event=None, llm=None,
             hub=None) -> dict:
    """Run a hunt in this thread with memory context, then remember the result."""
    mem = memory_for(cfg)
    ctx = "\n\n".join(x for x in (environment_context(cfg), context, mem.context(hypothesis)) if x)
    eng = make_engine(cfg, checkpoint=checkpoint, on_event=on_event, max_steps=max_steps, llm=llm, hub=hub)
    res = eng.run(hypothesis, hunt_id=hunt_id, origin=origin, actor=actor, context=ctx)
    res = maybe_verify(cfg, res, llm=eng.llm, hub=hub)
    res = handoff(cfg, res)
    counts = eng.llm.masker.counts
    if counts:
        store = store_for(cfg)
        store.add_step(res["id"], len(res.get("steps") or []) + 1, "note", ok=True,
                       note="privacy: masked before sending to a cloud model: "
                            + ", ".join(f"{n} {k.lower()}" for k, n in sorted(counts.items())))
        res = store.get(res["id"]) or res
    mem.remember(res)
    return send_outputs(cfg, res, hub=hub)


HANDOFF_DEFAULT = ("inconclusive", "logs_missing", "unverified_threat", "error", "known_good_threat")


def handoff(cfg, h: dict) -> dict:
    """When Actaeon cannot reach a confident answer, hand the hunt to an analyst: mark it for review and
    record why, what was searched, what was missing and what to do next. A lead opens from this."""
    if not h:
        return h
    v = dict(h.get("verdict") or {})
    when = ((cfg.raw or {}).get("hunt") or {}).get("handoff", list(HANDOFF_DEFAULT))
    when = set(when if isinstance(when, list) else [when])
    out = h.get("outcome")
    reason = ""
    if h.get("status") == "error" and "error" in when:
        reason = f"The hunt failed before a verdict ({(h.get('error') or '')[:200]})."
    elif out == "inconclusive" and "inconclusive" in when:
        reason = f"Actaeon could not reach a verdict: {v.get('summary', '')[:300]}"
    elif out == "logs_missing" and "logs_missing" in when:
        reason = ("The data needed to test this is not available to Actaeon. Confirm whether it exists "
                  "elsewhere, or record that this cannot be hunted here.")
    elif out == "threat" and v.get("needs_review") and (v.get("verification") or {}).get("result") not in (
            None, "confirmed") and "unverified_threat" in when:
        reason = "A threat was reported but a second pass could not confirm it."
    elif out == "threat" and v.get("needs_review") and "known_good_threat" in when:
        reason = "The threat only names things listed as known good; check whether they are being misused."
    if not reason:
        return h
    tried = []
    for s in h.get("steps") or []:
        if s.get("kind") == "call":
            a = s.get("arguments") or {}
            what = a.get("query") or a.get("sql") or a.get("field") or ""
            tried.append(f"E{s['n']} {s.get('connector')}.{s.get('tool')} {str(what)[:140]}".strip()
                         + ("" if s.get("ok") else " (failed)"))
    v["needs_review"] = True
    v["handoff"] = {"reason": reason, "tried": tried[-15:], "missing": list(v.get("gaps") or [])[:10],
                    "next_steps": list(v.get("next_steps") or [])[:10]}
    store = store_for(cfg)
    store.update(h["id"], verdict=v)
    n = max([s["n"] for s in h.get("steps") or []] + [0]) + 1
    store.add_step(h["id"], n, "note", ok=True, note=f"handed to an analyst: {reason[:300]}")
    return store.get(h["id"]) or h


def maybe_verify(cfg, h: dict, *, llm=None, hub=None) -> dict:
    """Second pass on threats: re-query to test whether the threat is real (hunt.verify, default on)."""
    if not h or h.get("outcome") != "threat" or ((cfg.raw or {}).get("hunt") or {}).get("verify", True) is False:
        return h
    from .verify import apply, verify
    if llm is None:
        from ..providers import get_llm
        llm = privacy_llm(cfg, get_llm())
    store = store_for(cfg)
    try:
        ver = verify(cfg, h, llm=llm, hub=_hub(cfg, hub))
    except Exception as exc:
        ver = {"result": "unconfirmed", "reason": f"verification failed: {exc}"[:300], "evidence": [],
               "new_evidence": [], "calls": 0}
    v = apply(h, ver)
    n = max([s["n"] for s in (store.get(h["id"]) or {}).get("steps") or []] + [0]) + 1
    store.add_step(h["id"], n, "note", ok=True, note=f"verification: {ver['result']}: {ver['reason'][:300]}")
    store.update(h["id"], verdict=v, outcome=v["outcome"])
    return store.get(h["id"]) or h


def leads_for(cfg):
    from ..leads import LeadStore
    return LeadStore(store_for(cfg).path)


def send_outputs(cfg, h: dict, *, hub=None) -> dict:
    """Open a lead if needed, then run the configured outputs and record each one as a step."""
    if h and h.get("status") in ("done", "stopped"):
        try:
            leads_for(cfg).open_for(h)
        except Exception:
            pass
    if not h or not (cfg.raw or {}).get("outputs") or h.get("status") not in ("done", "stopped"):
        return h
    from ..outputs import dispatch
    results = dispatch(cfg, h, hub=hub)
    if not results:
        return h
    store = store_for(cfg)
    n = max([s["n"] for s in h.get("steps") or []] + [0])
    for i, r in enumerate(results, 1):
        store.add_step(h["id"], n + i, "output", connector="outputs", tool=str(r["name"]), ok=r["ok"],
                       note=r["detail"])
    return store.get(h["id"]) or h


FEEDBACK_KINDS = ("benign", "false_positive", "confirmed")


def add_feedback(cfg, hid: str, *, finding: int, kind: str, comment: str = "", author: str = "") -> dict:
    """Record an analyst's view of one finding. Benign and false-positive calls become memory notes."""
    if kind not in FEEDBACK_KINDS:
        raise ValueError(f"kind must be one of {FEEDBACK_KINDS}")
    store = store_for(cfg)
    h = store.get(hid, with_steps=False)
    if not h:
        raise LookupError("no such hunt")
    findings = (h.get("verdict") or {}).get("findings") or []
    if not 0 <= int(finding) < len(findings):
        raise ValueError("no finding with that index")
    claim = findings[int(finding)]["claim"]
    entry = {"finding": int(finding), "claim": claim, "kind": kind, "comment": comment[:1000], "by": author}
    fb = (h.get("feedback") or []) + [entry]
    store.update(hid, feedback=fb)
    note = None
    if kind in ("benign", "false_positive", "benign_true_positive"):
        label = "Known benign" if kind == "benign" else "False positive"
        note = memory_for(cfg).add_note(f"{label}: {claim}" + (f" Analyst: {comment}" if comment else ""),
                                        author=author, tags=[kind, f"hunt:{hid}"])
    return {"feedback": entry, "note": note}


def start_hunt(jobs, cfg, hypothesis: str, *, actor: str = "", origin: str = "manual", context: str = "",
               max_steps: int | None = None, llm=None, hub=None) -> str:
    """Queue a hunt on the job runner and return its id."""
    hypothesis = (hypothesis or "").strip()
    if not hypothesis:
        raise ValueError("a hypothesis is required")
    store = store_for(cfg)
    hid = store.create(hypothesis, origin=origin, actor=actor)

    def work(ctl):
        res = run_hunt(cfg, hypothesis, hunt_id=hid, origin=origin, actor=actor, context=context,
                       max_steps=max_steps, checkpoint=ctl.checkpoint, llm=llm, hub=hub)
        return {"hunt_id": hid, "outcome": res.get("outcome"), "status": res.get("status")}

    job_id = jobs.submit("hunt", {"hunt_id": hid}, work, deduplicate=False)
    store.update(hid, job_id=job_id)
    return hid


def advisory_hunt(cfg, aid: int) -> tuple[str, str]:
    """Build (hypothesis, context) for a model-driven hunt of one advisory."""
    adv = intel_for(cfg).advisory(aid)
    if not adv:
        raise ValueError("no advisory with that id")
    techs = ", ".join(adv["techniques"]) or "none listed"
    hyp = (f"Activity described in the advisory '{adv['title']}' (ATT&CK {techs}) "
           f"happened in this environment in the last 7 days.")
    inds = [f"{i['type']} {i['value']}" for i in adv["indicators"] if i["active"]][:60]
    ctx = ("Advisory text (untrusted, from the intel store):\n<<UNTRUSTED-DATA advisory>>\n"
           f"{adv['text'][:6000]}\n<<END-UNTRUSTED-DATA advisory>>\n"
           f"Indicators from it: {', '.join(inds) or 'none'}\nCVEs: {', '.join(adv['cves']) or 'none'}\n"
           "Search for the indicators and for the behaviour of the listed techniques.")
    return hyp, ctx


def run_replay(cfg, sid: int, *, hub=None, llm=None, jobs=None, actor: str = "scheduler") -> dict:
    lib = library_for(cfg)
    saved = lib.get(sid)
    if not saved:
        raise ValueError("no saved hunt with that id")
    res = replay(saved, _hub(cfg, hub), store_for(cfg), lib, max_results=cfg.hunt.max_results, actor=actor)
    res = send_outputs(cfg, res, hub=hub)
    if saved["escalate"] and (res.get("verdict") or {}).get("needs_review") and jobs is not None:
        start_hunt(jobs, cfg, saved["hypothesis"], actor=actor, origin=f"escalated:{res['id']}",
                   context=replay_context(res), llm=llm, hub=hub)
    return res


def run_sweep(cfg, *, full: bool = False, hub=None, actor: str = "scheduler", llm=None) -> dict:
    settings = (cfg.intel or {}).get("sweep") or {}
    if settings.get("triage") == "model" and llm is None:
        from ..providers import get_llm
        llm = privacy_llm(cfg, get_llm())
    sweep = Sweep(_hub(cfg, hub), intel_for(cfg), store_for(cfg), settings,
                  max_results=cfg.hunt.max_results, llm=llm)
    res = sweep.run(full=full, actor=actor)
    if llm is not None or settings.get("verify"):
        res = maybe_verify(cfg, res, llm=llm, hub=hub)
    return send_outputs(cfg, res, hub=hub)


def start_job(jobs, kind: str, meta: dict, fn) -> str:
    return jobs.submit(kind, meta, lambda ctl: {"hunt_id": fn().get("id")}, deduplicate=True)


def run_web_intel(cfg, *, jobs=None, llm=None, hub=None, only: str | None = None) -> dict:
    """Pull web intel; with intel.web.auto_hunt, queue an advisory hunt for each new advisory worth hunting."""
    from ..intel.web import WebIntel
    web = (cfg.intel or {}).get("web") or {}
    res = WebIntel(intel_for(cfg), web, allow_private=bool((cfg.intel or {}).get("allow_private_urls"))).pull(only)
    res["hunts"], res["relevance"] = [], []
    if not res["new_advisories"]:
        return {"id": None, **res}
    from ..intel.relevance import assess
    from ..providers import get_llm
    store = intel_for(cfg)
    rel_cfg = web.get("relevance") or {}
    judge = llm if llm is not None else (privacy_llm(cfg, get_llm()) if rel_cfg.get("model", True) else None)
    cap = int(web.get("max_hunts_per_pull", 3))
    for a in res["new_advisories"]:
        adv = store.advisory(a["id"]) or {}
        decision = assess(cfg, adv, llm=judge)
        hid = ""
        if decision["relevant"] and web.get("auto_hunt") and jobs is not None and len(res["hunts"]) < cap:
            hyp, ctx = advisory_hunt(cfg, a["id"])
            if decision.get("hypothesis"):
                hyp = decision["hypothesis"]
                ctx = f"Why this advisory is relevant here: {decision['why']}\n\n{ctx}"
            hid = start_hunt(jobs, cfg, hyp, actor="web-intel", origin=f"advisory:{a['id']}",
                             context=ctx, llm=llm, hub=hub)
            res["hunts"].append(hid)
        elif decision["relevant"] and web.get("auto_hunt") and jobs is not None:
            decision["why"] += " (not hunted: per-pull hunt cap reached)"
        store.set_relevance(a["id"], decision, hid)
        res["relevance"].append({"advisory": a["id"], "title": a["title"], "relevant": decision["relevant"],
                                 "why": decision["why"], "hunt_id": hid})
    return {"id": None, **res}


def run_autopilot(cfg, jobs, *, llm=None, hub=None, dry_run: bool = False) -> dict:
    from ..providers import get_llm
    from .autopilot import run
    return {"id": None, **run(cfg, jobs, llm or get_llm(), hub=hub, dry_run=dry_run)}


def actor_campaign(cfg, jobs, key: str, *, actor: str = "", llm=None, hub=None) -> dict:
    """Hunt one threat actor: sweep its indicators (with triage) and run a model hunt for its techniques and tools."""
    prof = intel_for(cfg).actor(key)
    if not prof:
        raise ValueError("no such actor")
    out = {"actor": prof["name"], "sweep_job": None, "hunt_id": None}
    settings = (cfg.intel or {}).get("sweep") or {}
    if prof["indicators"]:
        def sweep_fn():
            sw = Sweep(_hub(cfg, hub), intel_for(cfg), store_for(cfg), settings, max_results=cfg.hunt.max_results,
                       llm=llm)
            return send_outputs(cfg, sw.run(actor=actor or "campaign", tag=f"actor:{prof['slug']}",
                                            origin=f"actor:{prof['slug']}"), hub=hub)
        out["sweep_job"] = start_job(jobs, "actor-sweep", {"actor": prof["slug"]}, sweep_fn)
    from .attack_names import name as tname
    techs = ", ".join(f"{t} {tname(t)}".strip() for t in prof["techniques"][:15]) or "none recorded"
    tools = ", ".join(prof["tools"][:15]) or "none recorded"
    hyp = (f"Threat actor {prof['name']} (also known as {', '.join(prof['aliases'][:5]) or 'no aliases'}) was active "
           f"in this environment in the last 14 days: look for its techniques ({techs}) and tools ({tools}).")
    ctx = ("Actor profile (untrusted, from the intel store):\n<<UNTRUSTED-DATA actor>>\n"
           f"{prof['description'][:3000]}\n<<END-UNTRUSTED-DATA actor>>\n"
           f"Known indicators: {', '.join(i['type'] + ' ' + i['value'] for i in prof['indicators'][:40]) or 'none'}\n"
           "Hunt the behaviour of these techniques and tools, not only the indicators (those are swept separately).")
    out["hunt_id"] = start_hunt(jobs, cfg, hyp, actor=actor or "campaign", origin=f"actor:{prof['slug']}",
                                context=ctx, llm=llm, hub=hub)
    return out
