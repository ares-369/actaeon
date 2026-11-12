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
    return HuntLimits(max_steps=steps, max_runtime_sec=h.max_runtime_sec, max_results=h.max_results)


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
                       ("not_present", "Not present here (do not hunt for these)"), ("notes", "Notes")):
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
    return HuntEngine(privacy_llm(cfg, llm or get_llm()), _hub(cfg, hub), store_for(cfg),
                      limits_for(cfg, max_steps), checkpoint=checkpoint, on_event=on_event)


def run_hunt(cfg, hypothesis: str, *, hunt_id: str | None = None, origin: str = "manual", actor: str = "",
             context: str = "", max_steps: int | None = None, checkpoint=None, on_event=None, llm=None,
             hub=None) -> dict:
    """Run a hunt in this thread with memory context, then remember the result."""
    mem = memory_for(cfg)
    ctx = "\n\n".join(x for x in (environment_context(cfg), context, mem.context(hypothesis)) if x)
    eng = make_engine(cfg, checkpoint=checkpoint, on_event=on_event, max_steps=max_steps, llm=llm, hub=hub)
    res = eng.run(hypothesis, hunt_id=hunt_id, origin=origin, actor=actor, context=ctx)
    counts = eng.llm.masker.counts
    if counts:
        store = store_for(cfg)
        store.add_step(res["id"], len(res.get("steps") or []) + 1, "note", ok=True,
                       note="privacy: masked before sending to a cloud model: "
                            + ", ".join(f"{n} {k.lower()}" for k, n in sorted(counts.items())))
        res = store.get(res["id"]) or res
    mem.remember(res)
    return send_outputs(cfg, res, hub=hub)


def send_outputs(cfg, h: dict, *, hub=None) -> dict:
    """Run the configured outputs for a finished hunt and record each one as a step."""
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
    if kind in ("benign", "false_positive"):
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
    return send_outputs(cfg, sweep.run(full=full, actor=actor), hub=hub)


def start_job(jobs, kind: str, meta: dict, fn) -> str:
    return jobs.submit(kind, meta, lambda ctl: {"hunt_id": fn().get("id")}, deduplicate=True)


def run_web_intel(cfg, *, jobs=None, llm=None, hub=None, only: str | None = None) -> dict:
    """Pull web intel; with intel.web.auto_hunt, queue an advisory hunt for each new advisory worth hunting."""
    from ..intel.web import WebIntel
    web = (cfg.intel or {}).get("web") or {}
    res = WebIntel(intel_for(cfg), web, allow_private=bool((cfg.intel or {}).get("allow_private_urls"))).pull(only)
    res["hunts"] = []
    if web.get("auto_hunt") and jobs is not None:
        for a in res["new_advisories"]:
            adv = intel_for(cfg).advisory(a["id"]) or {}
            if not (adv.get("indicators") or adv.get("techniques")):
                continue
            hyp, ctx = advisory_hunt(cfg, a["id"])
            res["hunts"].append(start_hunt(jobs, cfg, hyp, actor="web-intel", origin=f"advisory:{a['id']}",
                                           context=ctx, llm=llm, hub=hub))
    return {"id": None, **res}


def run_autopilot(cfg, jobs, *, llm=None, hub=None, dry_run: bool = False) -> dict:
    from ..providers import get_llm
    from .autopilot import run
    return {"id": None, **run(cfg, jobs, llm or get_llm(), hub=hub, dry_run=dry_run)}
