"""Named background tasks, so a job can be queued in the database and run by any worker.

Each task takes JSON parameters. In ``jobs.mode: local`` the same code runs on
the server's own threads; in ``queue`` mode ``actaeon worker`` runs it.
"""

from __future__ import annotations

from typing import Any


def _cfg():
    from .config import get_config
    return get_config()


def hunt(p: dict, ctl, jobs) -> dict:
    from .hunt.service import run_hunt
    res = run_hunt(_cfg(), p["hypothesis"], hunt_id=p["hunt_id"], origin=p.get("origin", "manual"),
                   actor=p.get("actor", ""), context=p.get("context", ""), max_steps=p.get("max_steps"),
                   checkpoint=ctl.checkpoint if ctl else None)
    return {"hunt_id": p["hunt_id"], "outcome": res.get("outcome"), "status": res.get("status")}


def replay(p: dict, ctl, jobs) -> dict:
    from .hunt.service import run_replay
    return {"hunt_id": run_replay(_cfg(), int(p["saved_id"]), jobs=jobs, actor=p.get("actor", "scheduler")).get("id")}


def sweep(p: dict, ctl, jobs) -> dict:
    from .hunt.service import run_sweep
    return {"hunt_id": run_sweep(_cfg(), full=bool(p.get("full")), actor=p.get("actor", "scheduler")).get("id")}


def actor_sweep(p: dict, ctl, jobs) -> dict:
    from .hunt.service import actor_sweep as run
    return {"hunt_id": run(_cfg(), p["slug"], actor=p.get("actor", "campaign")).get("id")}


def drift(p: dict, ctl, jobs) -> dict:
    from .hunt.service import run_drift
    return {"hunt_id": run_drift(_cfg(), only=p.get("only"), jobs=jobs, actor=p.get("actor", "scheduler")).get("id")}


def web_intel(p: dict, ctl, jobs) -> dict:
    from .hunt.service import run_web_intel
    return {"hunt_id": run_web_intel(_cfg(), jobs=jobs, only=p.get("only")).get("id")}


def autopilot(p: dict, ctl, jobs) -> dict:
    from .hunt.service import run_autopilot
    return {"hunt_id": run_autopilot(_cfg(), jobs).get("id")}


def chat(p: dict, ctl, jobs) -> dict:
    from .hunt.chat import ask
    return ask(_cfg(), p["hunt_id"], p["message"], author=p.get("author", ""))


def assistant(p: dict, ctl, jobs) -> dict:
    from .assistant import ask
    return ask(_cfg(), p["message"], user=p.get("user", ""), conv_id=p.get("conv_id"))


def ticket_reply(p: dict, ctl, jobs) -> dict:
    from .tickets import answer
    return answer(_cfg(), p["hunt_id"], p["text"], who=p.get("who", ""), author=p.get("author", ""))


TASKS: dict[str, Any] = {"hunt": hunt, "replay": replay, "sweep": sweep, "actor-sweep": actor_sweep,
                         "web-intel": web_intel, "drift": drift, "autopilot": autopilot, "chat": chat, "ask": assistant,
                         "ticket-reply": ticket_reply}


def run_task(name: str, params: dict, ctl=None, *, jobs=None) -> dict:
    if name not in TASKS:
        raise ValueError(f"unknown task {name!r}")
    return TASKS[name](params, ctl, jobs) or {}
