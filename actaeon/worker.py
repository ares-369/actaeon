"""``actaeon worker``: run queued jobs (``jobs.mode: queue``) outside the web server.

Run one or more workers next to ``actaeon serve``, on the same data folder.
Each claims the oldest queued task, runs it with the access of the person who
started it, and sends heartbeats; a job whose worker disappears is marked
interrupted after ``jobs.stale_after_sec``. Stop and pause from the UI reach
the worker through the database.

With SQLite, every process must share one data folder on one machine. With
PostgreSQL (``actaeon[postgres]``), workers can run on other machines.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger("actaeon.worker")


class Worker:
    def __init__(self, cfg, jobs, *, concurrency: int = 2, poll_sec: float = 2.0, name: str = "",
                 scheduler: bool = False):
        if jobs.mode != "queue":
            raise ValueError("actaeon worker needs jobs.mode: queue in config.yaml")
        self.cfg, self.jobs = cfg, jobs
        self.concurrency = max(1, int(concurrency))
        self.poll_sec = poll_sec
        self.name = name or f"{socket.gethostname()}:{os.getpid()}"
        self.pool = ThreadPoolExecutor(max_workers=self.concurrency, thread_name_prefix="actaeon-worker")
        self.running: set[str] = set()
        self._lock = threading.Lock()
        self.stop_event = threading.Event()
        self.scheduler = None
        if scheduler:
            from .hunt.scheduler import Scheduler
            self.scheduler = Scheduler(cfg, jobs)

    def _done(self, jid: str) -> None:
        with self._lock:
            self.running.discard(jid)

    def run_once(self) -> int:
        """Claim tasks while there are free slots. Returns how many were started."""
        started = 0
        while True:
            with self._lock:
                if len(self.running) >= self.concurrency:
                    return started
            job = self.jobs.claim(self.name)
            if not job:
                return started
            with self._lock:
                self.running.add(job["id"])
            log.info("running %s %s", job["task"], job["id"])
            fut = self.pool.submit(self.jobs.run_claimed, job)
            fut.add_done_callback(lambda _f, jid=job["id"]: self._done(jid))
            started += 1

    def heartbeat(self) -> None:
        from .jobs import _now
        with self._lock:
            ids = list(self.running)
        for jid in ids:
            try:
                self.jobs._set(jid, heartbeat=_now())
            except Exception:
                pass

    def run_forever(self) -> None:
        if self.scheduler:
            self.scheduler.start()
        last_beat = last_reconcile = 0.0
        while not self.stop_event.is_set():
            try:
                self.run_once()
                now = time.monotonic()
                if now - last_beat > 30:
                    self.heartbeat()
                    last_beat = now
                if now - last_reconcile > 60:
                    n = self.jobs.reconcile_stale()
                    if n:
                        log.warning("marked %d job(s) interrupted: their worker stopped", n)
                    last_reconcile = now
            except Exception:
                log.exception("worker loop error")
            self.stop_event.wait(self.poll_sec)
        if self.scheduler:
            self.scheduler.stop()
        log.info("waiting for %d running job(s) to finish", len(self.running))
        self.pool.shutdown(wait=True)


def main(concurrency: int = 2, scheduler: bool = False) -> None:
    from .config import get_config
    from .jobs import JobManager
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = get_config()
    w = Worker(cfg, JobManager.from_config(cfg), concurrency=concurrency, scheduler=scheduler)

    def stop(*_):
        log.info("stopping: finishing running jobs, claiming no new ones")
        w.stop_event.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log.info("worker %s: up to %d job(s) at once%s", w.name, w.concurrency, ", with the scheduler" if scheduler else "")
    w.run_forever()
