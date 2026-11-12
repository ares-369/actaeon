"""Background scheduler for saved-hunt replays and intel sweeps (runs inside the server)."""

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
        self._thread: threading.Thread | None = None

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
                self.tick()
            except Exception:
                log.exception("scheduler tick failed")

    def tick(self, now: datetime | None = None) -> list[str]:
        """Queue whatever is due. Returns the job ids queued."""
        now = now or datetime.now(timezone.utc)
        queued = []
        for s in service.library_for(self.cfg).due(now):
            sid = s["id"]
            queued.append(service.start_job(
                self.jobs, "replay", {"saved_id": sid},
                lambda sid=sid: service.run_replay(self.cfg, sid, jobs=self.jobs)))
            service.library_for(self.cfg).mark_run(sid, s.get("last_hits"), s.get("last_fingerprints") or [],
                                                   s.get("last_hunt_id") or "")
        sw = (self.cfg.intel or {}).get("sweep") or {}
        every = int(sw.get("interval_minutes", 0) or 0)
        if every > 0 and (self._last_sweep is None or (now - self._last_sweep).total_seconds() >= every * 60):
            self._last_sweep = now
            queued.append(service.start_job(self.jobs, "sweep", {"sweep": True},
                                            lambda: service.run_sweep(self.cfg)))
        web = (self.cfg.intel or {}).get("web") or {}
        wevery = int(web.get("interval_minutes", 0) or 0)
        if wevery > 0 and (self._last_web is None or (now - self._last_web).total_seconds() >= wevery * 60):
            self._last_web = now
            queued.append(service.start_job(self.jobs, "web-intel", {"web": True},
                                            lambda: service.run_web_intel(self.cfg, jobs=self.jobs)))
        ap = (self.cfg.raw or {}).get("autopilot") or {}
        aevery = int(ap.get("interval_minutes", 0) or 0)
        if aevery > 0 and (self._last_autopilot is None
                           or (now - self._last_autopilot).total_seconds() >= aevery * 60):
            self._last_autopilot = now
            queued.append(service.start_job(self.jobs, "autopilot", {"autopilot": True},
                                            lambda: service.run_autopilot(self.cfg, self.jobs)))
        return queued
