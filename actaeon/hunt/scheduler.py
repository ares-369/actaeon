"""Background scheduler for saved-hunt replays and intel sweeps.

It runs inside the server (and, with ``actaeon worker --scheduler``, in a
worker). Only one process at a time schedules: the first to take the lock file
``<data>/scheduler.lock``. If that process stops, another takes over at its
next tick.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

from . import service

log = logging.getLogger("actaeon.scheduler")


class Scheduler:
    def __init__(self, cfg, jobs, *, tick_sec: float = 60.0):
        self.cfg, self.jobs, self.tick_sec = cfg, jobs, tick_sec
        self._stop = threading.Event()
        self._last_sweep: datetime | None = None
        self._last_web: datetime | None = None
        self._last_autopilot: datetime | None = None
        self._last_drift: datetime | None = None
        self._thread: threading.Thread | None = None
        self._lockfile = None

    def leader(self) -> bool:
        """Hold the scheduler lock (one scheduling process per data folder)."""
        if self._lockfile is not None:
            return True
        try:
            import fcntl
        except ImportError:          # no flock on this platform: run one scheduler yourself
            return True
        path = self.cfg.data_dir / "scheduler.lock"
        f = open(path, "a+")  # noqa: SIM115 - held open for the life of the process
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            return False
        self._lockfile = f
        return True

    def start(self) -> None:
        if self._thread:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="actaeon-scheduler")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(self.tick_sec):
            try:
                if self.leader():
                    self.tick()
            except Exception:
                log.exception("scheduler tick failed")

    def tick(self, now: datetime | None = None) -> list[str]:
        """Queue whatever is due. Returns the job ids queued.

        Saved-hunt replays are queued with no identity and run as the person who saved each hunt; the
        scheduler's own work (sweep, web intel, autopilot) runs as ``scheduler_access`` (see access.py)."""
        from ..access import run_as, scheduler_access
        return run_as(None, self._tick_replays, now or datetime.now(timezone.utc)) + run_as(
            scheduler_access(self.cfg), self._tick_system, now or datetime.now(timezone.utc))

    def _tick_replays(self, now: datetime) -> list[str]:
        now = now or datetime.now(timezone.utc)
        queued = []
        for s in service.library_for(self.cfg).due(now):
            sid = s["id"]
            queued.append(service.start_job(
                self.jobs, "replay", {"saved_id": sid},
                lambda sid=sid: service.run_replay(self.cfg, sid, jobs=self.jobs),
                task="replay", params={"saved_id": sid}))
            service.library_for(self.cfg).mark_run(sid, s.get("last_hits"), s.get("last_fingerprints") or [],
                                                   s.get("last_hunt_id") or "")
        return queued

    def _tick_system(self, now: datetime) -> list[str]:
        queued = []
        sw = (self.cfg.intel or {}).get("sweep") or {}
        every = int(sw.get("interval_minutes", 0) or 0)
        if every > 0 and (self._last_sweep is None or (now - self._last_sweep).total_seconds() >= every * 60):
            self._last_sweep = now
            queued.append(service.start_job(self.jobs, "sweep", {"sweep": True},
                                            lambda: service.run_sweep(self.cfg), task="sweep", params={}))
        web = (self.cfg.intel or {}).get("web") or {}
        wevery = int(web.get("interval_minutes", 0) or 0)
        if wevery > 0 and (self._last_web is None or (now - self._last_web).total_seconds() >= wevery * 60):
            self._last_web = now
            queued.append(service.start_job(self.jobs, "web-intel", {"web": True},
                                            lambda: service.run_web_intel(self.cfg, jobs=self.jobs),
                                            task="web-intel", params={}))
        dr = (self.cfg.raw or {}).get("drift") or {}
        devery = int(dr.get("interval_minutes", 0) or 0)
        if devery > 0 and dr.get("targets") and (self._last_drift is None
                                                 or (now - self._last_drift).total_seconds() >= devery * 60):
            self._last_drift = now
            queued.append(service.start_job(self.jobs, "drift", {"drift": True},
                                            lambda: service.run_drift(self.cfg, jobs=self.jobs),
                                            task="drift", params={}))
        ap = (self.cfg.raw or {}).get("autopilot") or {}
        aevery = int(ap.get("interval_minutes", 0) or 0)
        if aevery > 0 and (self._last_autopilot is None
                           or (now - self._last_autopilot).total_seconds() >= aevery * 60):
            self._last_autopilot = now
            queued.append(service.start_job(self.jobs, "autopilot", {"autopilot": True},
                                            lambda: service.run_autopilot(self.cfg, self.jobs),
                                            task="autopilot", params={}))
        return queued
