"""Queue mode: jobs recorded as named tasks, run by `actaeon worker`, controlled through the database."""
import time

import pytest

from actaeon import access, tasks
from actaeon.jobs import JobControl, JobManager


@pytest.fixture
def fake_task(monkeypatch):
    seen = []

    def t(p, ctl, jobs):
        seen.append({"p": p, "access": access.current(), "go": ctl.checkpoint() if ctl else None})
        return {"ok": True}
    monkeypatch.setitem(tasks.TASKS, "fake", t)
    return seen


def test_queue_records_and_worker_runs(tmp_path, fake_task):
    jm = JobManager(tmp_path / "j.sqlite", mode="queue")
    a = access.Access(user="ann", role="operator", groups=("soc",), connectors=frozenset({"logs"}))
    jid = access.run_as(a, jm.submit, "k", {"x": 1}, None, task="fake", params={"n": 5})
    assert jm.get(jid)["status"] == "queued" and fake_task == []
    assert access.run_as(a, jm.submit, "k", {"x": 1}, None, task="fake", params={"n": 5}) == jid   # deduplicated
    JobManager(tmp_path / "j.sqlite")              # a local manager starting must not touch queued tasks
    assert jm.get(jid)["status"] == "queued"
    job = jm.claim("w1")
    assert job["id"] == jid and jm.claim("w2") is None and jm.get(jid)["worker"] == "w1"
    jm.run_claimed(job)
    assert jm.get(jid)["status"] == "done" and jm.get(jid)["result"] == {"ok": True}
    assert fake_task[0]["p"] == {"n": 5} and fake_task[0]["access"] == a and fake_task[0]["go"] is True
    with pytest.raises(ValueError):
        jm.submit("k", {}, None, task="nope")


def test_remote_control(tmp_path, fake_task):
    jm = JobManager(tmp_path / "j.sqlite", mode="queue")
    q = jm.submit("k", {"a": 1}, None, task="fake")
    assert jm.cancel(q) and jm.get(q)["status"] == "cancelled" and jm.claim("w") is None
    r = jm.submit("k", {"a": 2}, None, task="fake")
    job = jm.claim("w")
    other = JobManager(tmp_path / "j.sqlite", mode="queue")    # e.g. the web server
    ctl = JobControl(jm, job["id"])
    assert other.pause(r) and jm.control_of(r) == "pause" and not other.pause(r)
    assert other.resume(r) and ctl.checkpoint() is True
    assert other.cancel(r) and ctl.checkpoint() is False
    jm.run_claimed(job)
    assert jm.get(r)["status"] == "cancelled"


def test_stale_jobs_interrupted(tmp_path, fake_task):
    jm = JobManager(tmp_path / "j.sqlite", mode="queue", stale_after_sec=60)
    jid = jm.submit("k", {}, None, task="fake")
    jm.claim("w")
    jm._set(jid, heartbeat="2000-01-01T00:00:00+00:00")
    assert jm.reconcile_stale() == 1 and jm.get(jid)["status"] == "interrupted"


def test_local_mode_runs_tasks_too(tmp_path, fake_task):
    jm = JobManager(tmp_path / "j.sqlite")
    jid = jm.submit("k", {}, None, task="fake", params={"n": 1})
    jm.pool.shutdown(wait=True)
    assert jm.get(jid)["status"] == "done" and fake_task[0]["p"] == {"n": 1}


def test_worker_loop(tmp_path, fake_task):
    from actaeon.worker import Worker
    cfg = type("C", (), {"data_dir": tmp_path, "raw": {}})()
    with pytest.raises(ValueError, match="queue"):
        Worker(cfg, JobManager(tmp_path / "l.sqlite"))
    jm = JobManager(tmp_path / "j.sqlite", mode="queue")
    ids = [jm.submit("k", {"i": i}, None, task="fake") for i in range(3)]
    w = Worker(cfg, jm, concurrency=2, poll_sec=0.05)
    assert w.run_once() == 2
    deadline = time.time() + 5
    while time.time() < deadline and any(jm.get(i)["status"] != "done" for i in ids):
        w.run_once()
        time.sleep(0.05)
    assert all(jm.get(i)["status"] == "done" for i in ids)
    w.pool.shutdown(wait=True)


def test_scheduler_single_leader(tmp_path):
    from actaeon.hunt.scheduler import Scheduler
    cfg = type("C", (), {"data_dir": tmp_path, "raw": {}, "intel": {}})()
    a, b = Scheduler(cfg, None), Scheduler(cfg, None)
    assert a.leader() and a.leader()
    import subprocess
    import sys
    code = ("import fcntl,sys; f=open(sys.argv[1],'a+')\n"
            "try:\n fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB); print('got')\nexcept OSError: print('busy')")
    out = subprocess.run([sys.executable, "-c", code, str(tmp_path / "scheduler.lock")], capture_output=True,
                         text=True).stdout.strip()
    assert out == "busy"          # another process cannot schedule while this one holds the lock
    assert not b.leader()         # a second scheduler, even in the same process, does not lead


def test_queued_hunt_end_to_end(tmp_path, monkeypatch):
    """A hunt started in queue mode does not run in the server; a worker runs it (offline demo data)."""
    from actaeon import config as c
    from actaeon.connectors import hub as h
    from actaeon.demo.setup import init_demo
    init_demo(tmp_path / "d", offline=True)
    p = tmp_path / "d" / "config.yaml"
    import yaml
    doc = yaml.safe_load(p.read_text())
    doc["jobs"] = {**(doc.get("jobs") or {}), "mode": "queue"}
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    monkeypatch.setenv("ACTAEON_HOME", str(tmp_path / "d"))
    monkeypatch.setenv("ACTAEON_CONFIG", str(p))
    from actaeon import providers
    monkeypatch.setattr(providers, "_LLM", None)     # a provider cached by an earlier test in this process
    c._CONFIG, h._HUB = None, None
    try:
        cfg = c.get_config(reload=True)
        from actaeon.hunt import service
        from actaeon.worker import Worker
        jm = JobManager.from_config(cfg)
        assert jm.mode == "queue"
        hid = service.start_hunt(jm, cfg, "An Office application started PowerShell with an encoded command on "
                                 "any host in the last 7 days.", actor="ann")
        job_id = service.store_for(cfg).get(hid)["job_id"]
        assert jm.get(job_id)["status"] == "queued"
        w = Worker(cfg, JobManager.from_config(cfg), concurrency=1)
        w.run_once()
        w.pool.shutdown(wait=True)
        hunt = service.store_for(cfg).get(hid)
        assert jm.get(job_id)["status"] == "done", jm.get(job_id)["error"]
        assert hunt["status"] == "done" and hunt["outcome"] == "threat", hunt.get("error")
    finally:
        c._CONFIG, h._HUB = None, None
