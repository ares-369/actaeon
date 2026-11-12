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


def make_engine(cfg, *, checkpoint=None, on_event=None, max_steps: int | None = None, llm=None, hub=None):
    from ..providers import get_llm
    return HuntEngine(llm or get_llm(), _hub(cfg, hub), store_for(cfg), limits_for(cfg, max_steps),
                      checkpoint=checkpoint, on_event=on_event)


def run_hunt(cfg, hypothesis: str, *, hunt_id: str | None = None, origin: str = "manual", actor: str = "",
             context: str = "", max_steps: int | None = None, checkpoint=None, on_event=None, llm=None,
             hub=None) -> dict:
    """Run a hunt in this thread with memory context, then remember the result."""
    mem = memory_for(cfg)
    ctx = "\n\n".join(x for x in (context, mem.context(hypothesis)) if x)
    eng = make_engine(cfg, checkpoint=checkpoint, on_event=on_event, max_steps=max_steps, llm=llm, hub=hub)
    res = eng.run(hypothesis, hunt_id=hunt_id, origin=origin, actor=actor, context=ctx)
    mem.remember(res)
    return res


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
    if saved["escalate"] and (res.get("verdict") or {}).get("needs_review") and jobs is not None:
        start_hunt(jobs, cfg, saved["hypothesis"], actor=actor, origin=f"escalated:{res['id']}",
                   context=replay_context(res), llm=llm, hub=hub)
    return res


def run_sweep(cfg, *, full: bool = False, hub=None, actor: str = "scheduler") -> dict:
    sweep = Sweep(_hub(cfg, hub), intel_for(cfg), store_for(cfg), (cfg.intel or {}).get("sweep") or {},
                  max_results=cfg.hunt.max_results)
    return sweep.run(full=full, actor=actor)


def start_job(jobs, kind: str, meta: dict, fn) -> str:
    return jobs.submit(kind, meta, lambda ctl: {"hunt_id": fn().get("id")}, deduplicate=True)
