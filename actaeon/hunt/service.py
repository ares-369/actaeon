"""Glue between the hunt engine, the job runner, config and the hub."""

from __future__ import annotations

from .engine import HuntEngine, HuntLimits
from .store import HuntStore


def store_for(cfg) -> HuntStore:
    return HuntStore(cfg.data_dir / "hunts.sqlite")


def limits_for(cfg, max_steps: int | None = None) -> HuntLimits:
    h = cfg.hunt
    steps = h.max_steps if max_steps is None else max(1, min(int(max_steps), h.max_steps))
    return HuntLimits(max_steps=steps, max_runtime_sec=h.max_runtime_sec, max_results=h.max_results)


def make_engine(cfg, *, checkpoint=None, on_event=None, max_steps: int | None = None, llm=None, hub=None):
    from ..connectors import get_hub
    from ..providers import get_llm
    return HuntEngine(llm or get_llm(), hub or get_hub(cfg), store_for(cfg), limits_for(cfg, max_steps),
                      checkpoint=checkpoint, on_event=on_event)


def start_hunt(jobs, cfg, hypothesis: str, *, actor: str = "", origin: str = "manual", context: str = "",
               max_steps: int | None = None, llm=None, hub=None) -> str:
    """Queue a hunt on the job runner and return its id."""
    hypothesis = (hypothesis or "").strip()
    if not hypothesis:
        raise ValueError("a hypothesis is required")
    store = store_for(cfg)
    hid = store.create(hypothesis, origin=origin, actor=actor)

    def work(ctl):
        eng = make_engine(cfg, checkpoint=ctl.checkpoint, max_steps=max_steps, llm=llm, hub=hub)
        res = eng.run(hypothesis, hunt_id=hid, origin=origin, actor=actor, context=context)
        return {"hunt_id": hid, "outcome": res.get("outcome"), "status": res.get("status")}

    job_id = jobs.submit("hunt", {"hunt_id": hid}, work, deduplicate=False)
    store.update(hid, job_id=job_id)
    return hid
