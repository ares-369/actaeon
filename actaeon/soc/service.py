"""Case lifecycle: triage, analyst decisions, tuning, and the background loop.

States: new -> triaging -> triaged (AI verdict waiting for the analyst) | needs_analyst (the AI could not
decide, or something needs a person) -> closed (by an analyst, or automatically for confident false
positives/benign when ``soc.auto_close_confidence`` is set).
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from . import response
from .engine import CaseEngine, Limits, Stopped, tokens_used
from .evidence import RecordingLLM
from .playbooks import load as load_playbooks
from .store import VERDICTS, SocStore
from .util import iso

log = logging.getLogger("actaeon.service")


def store_for(cfg) -> SocStore:
    return SocStore(cfg.data_dir / "soc.sqlite")


def _llm(cfg):
    from ..hunt.service import privacy_llm
    from ..providers import get_llm
    return privacy_llm(cfg, get_llm())


_ESC_KEY = "escalations:"


def escalations_today(store: SocStore) -> int:
    try:
        return int(store.bookmark(_ESC_KEY + iso()[:10]) or 0)
    except ValueError:
        return 0


def _escalation_name(cfg) -> str:
    e = cfg.soc.escalate
    return f"{e['provider']}/{e['model']}" if e.get("model") else e.get("provider", "")


def escalation_needed(cfg, store: SocStore, case: dict, v: dict) -> str:
    """Why this case should go to the stronger model ('' = it should not)."""
    e = cfg.soc.escalate
    if not e or cfg.soc.analysis != "ai" or int(case.get("severity") or 0) < e["min_severity"]:
        return ""
    if e["max_per_day"] and escalations_today(store) >= e["max_per_day"]:
        return ""
    when = set(e["when"])
    if "needs_analyst" in when and v["verdict"] in ("needs_analyst", "logs_missing") and not v.get("injection"):
        return "the first pass could not decide"
    if "conflict" in when and any("the fixed checks proved signs of an attack" in c for c in v.get("checks") or []):
        return "the fixed checks and the first pass disagree"
    if "unconfirmed" in when and (v.get("verification") or {}).get("result") == "unconfirmed":
        return "the second look could not confirm the first pass"
    return ""


class _OneModel:
    """Every role served by one bound model (the escalation model)."""

    def __init__(self, llm, rc: dict):
        self.llm, self.rc = llm, rc
        self.usage: dict = {}

    def for_role(self, role: str):
        b = self.llm._bind(self.rc)
        b.meter = self.usage
        return b

    def usage_summary(self, usage=None):
        return self.llm.usage_summary(self.usage if usage is None else usage)


def _escalation_llm(cfg):
    from ..privacy import PrivacyLLM
    from ..providers import get_llm
    e = cfg.soc.escalate
    return PrivacyLLM(_OneModel(get_llm(), {"provider": e["provider"], "model": e["model"]}),
                      (cfg.raw or {}).get("privacy") or {})


def triage_case(cfg, case_id: str, *, actor: str = "actaeon", checkpoint=None, manual: bool = False,
                llm=None, hub=None, store: SocStore | None = None, escalate_llm=None) -> dict:
    """Investigate one case and store the checked verdict. Returns the stored case."""
    store = store or store_for(cfg)
    case = store.get_case(case_id, full=False)
    if not case:
        raise ValueError(f"no case {case_id}")
    over = budget_reached(cfg, store)
    if not manual and over:
        store.set_case(case_id, status="new", error=f"daily budget reached ({over}); triage it by hand or wait "
                       "for tomorrow")
        return store.get_case(case_id)
    if hub is None:
        from ..connectors import get_hub
        hub = get_hub(cfg)
    llm = RecordingLLM(llm or _llm(cfg))       # keeps a digest of every prompt and reply for the evidence bundle
    store.clear_steps(case_id)
    store.set_case(case_id, status="triaging", error=None)
    started = time.monotonic()
    engine = CaseEngine(llm, hub, store, Limits(max_steps=cfg.soc.max_steps, analysis=cfg.soc.analysis,
                                                 collect=cfg.soc.collect, collect_max_calls=cfg.soc.collect_max_calls,
                                                 max_runtime_sec=cfg.soc.max_runtime_sec,
                                                 max_results=cfg.soc.max_results, max_tokens=cfg.soc.max_tokens,
                                                 first_look=cfg.soc.first_look),
                        actions=response.catalogue(cfg), environment=(cfg.raw or {}).get("environment") or {}, checkpoint=checkpoint,
                        playbooks=load_playbooks(cfg.soc.playbook_dirs), cfg=cfg)
    try:
        v = engine.run(case_id)
    except Stopped:
        store.set_case(case_id, status="new", error="stopped before a verdict")
        return store.get_case(case_id)
    except Exception as exc:
        log.exception("triage failed for %s", case_id)
        store.set_case(case_id, status="error", error=f"{type(exc).__name__}: {exc}"[:500])
        _account(store, llm)
        return store.get_case(case_id)
    serious = int(case.get("severity") or 0) >= 65
    esc = escalation_needed(cfg, store, case, v)
    if esc and escalate_llm is None:
        try:
            escalate_llm = _escalation_llm(cfg)
        except Exception as exc:
            log.warning("escalation model unavailable: %s", exc)
    if esc and escalate_llm is not None:
        # The first pass could not settle it: run the investigation again on the stronger model. Its calls and
        # verdict replace the first pass's; the first verdict is kept in the report.
        first = {k: v.get(k) for k in ("verdict", "confidence", "summary", "checks")}
        store.clear_steps(case_id)
        engine.llm = RecordingLLM(escalate_llm)
        llm = engine.llm
        try:
            v = engine.run(case_id)
            v["escalated"] = {"reason": esc, "model": _escalation_name(cfg), "first_pass": first}
            v["checks"] = [*v["checks"], f"escalated to {_escalation_name(cfg)} ({esc}); first pass said "
                           f"{first['verdict']} at {first['confidence']}"]
            store.bookmark(_ESC_KEY + iso()[:10], str(escalations_today(store) + 1))
        except Exception as exc:
            log.exception("escalation failed for %s", case_id)
            v = {**v, "checks": [*v.get("checks", []), f"escalation failed ({type(exc).__name__})"]}
    check_dismissal = cfg.soc.verify_dismissals and serious and v["verdict"] in ("false_positive", "benign")
    if (cfg.soc.verify and cfg.soc.analysis == "ai" and (v["verdict"] == "true_positive" or check_dismissal)
            and not v.get("unstructured")):
        from .verify import apply as apply_verify
        from .verify import verify
        try:
            v = apply_verify(v, verify(cfg, store, case_id, v, llm=llm, hub=hub, tools=engine.tools()))
        except Exception as exc:        # the second look is extra: its failure must not lose the verdict
            log.exception("second look failed for %s", case_id)
            v["checks"] = [*v["checks"], f"the second look failed ({type(exc).__name__}); not verified"]
            v["confidence"] = min(v["confidence"], 60)
    # Fixed limits, last: nothing above (model, second look, escalation) can overrule them.
    from .floor import apply as apply_floor
    v = apply_floor(cfg, store.alerts(case_id=case_id, limit=100000), v)
    if v.get("floor"):
        v["severity"] = max(int(v.get("severity") or 0), int(case.get("severity") or 0))
    v["model_calls"] = llm.calls[-200:]
    removed = getattr(llm.llm, "secrets_removed", None)
    if removed:
        v["checks"] = [*v["checks"], "secret-shaped values were removed from the prompts before they were sent: "
                       + ", ".join(f"{k} x{n}" for k, n in sorted(removed.items()))]
    usage = llm.usage_summary() if hasattr(llm, "usage_summary") else {}
    usage["seconds"] = round(time.monotonic() - started, 1)
    _account(store, llm)
    from .alerts import severity_label
    status = "triaged"
    if v["verdict"] in ("needs_analyst", "logs_missing") or v["injection"]:
        status = "needs_analyst"
    ver = (v.get("verification") or {}).get("result")
    if serious and v["verdict"] in ("false_positive", "benign") and ver != "confirmed" and not v.get("authorised_test"):
        # A high or critical alert is never quietly dismissed: without an independent confirmation it waits for
        # a person (the verdict stays as the AI's proposal). The case keeps the severity it came in with, so the
        # queue does not show it as low while it waits.
        status = "needs_analyst"
        came = int(case.get("severity") or 0)
        v["checks"] = [*v["checks"], f"the alert came in as {severity_label(came)} (severity {came}): it is not "
                       "dismissed without an independent confirmation; an analyst must decide"]
        if int(v.get("severity") or 0) < came:
            v["checks"] = [*v["checks"], f"the AI rated it {severity_label(int(v.get('severity') or 0))}; "
                           f"the case keeps {severity_label(came)} until an analyst decides"]
            v["severity"] = came
    store.set_case(case_id, status=status, verdict=v["verdict"], confidence=v["confidence"], severity=v["severity"],
                   severity_label=severity_label(v["severity"]), summary=v["summary"], report=v, attack=v["attack"],
                   triaged_at=iso(), usage=usage, title=v["title"] or case["title"])
    store.add_entities(case_id, v["entities"])
    response.propose(cfg, store, case_id, v)
    auto = cfg.soc.auto_close_confidence
    if (auto and status == "triaged" and v["verdict"] in ("false_positive", "benign") and v["confidence"] >= auto
            and not v["injection"] and not manual and not v.get("authorised_test")):
        store.set_case(case_id, status="closed", closed_at=iso(), closed_by="actaeon (auto)")
        store.add_note(case_id, "actaeon", f"Closed automatically: {v['verdict']} at confidence {v['confidence']} "
                       f"(soc.auto_close_confidence {auto}).")
    full = store.get_case(case_id)
    from .outputs import dispatch
    sent = dispatch(cfg, full, hub=hub)
    if sent:
        store.add_note(case_id, "outputs", "; ".join(f"{s['name']}: {'ok' if s['ok'] else 'failed'} {s['detail']}"
                                                     for s in sent)[:2000])
    return store.get_case(case_id)


def budget_reached(cfg, store: SocStore) -> str:
    """Which daily limit on automatic triage is used up ('' = none)."""
    if cfg.soc.max_tokens_per_day and store.usage_today() >= cfg.soc.max_tokens_per_day:
        return "soc.max_tokens_per_day"
    if cfg.soc.max_cases_per_day and store.triaged_today() >= cfg.soc.max_cases_per_day:
        return "soc.max_cases_per_day"
    return ""


def _account(store: SocStore, llm) -> None:
    try:
        usage = llm.usage
        usage = usage() if callable(usage) else usage
        calls = sum(int(u.get("calls", 0)) for u in usage.values())
        store.add_usage(tokens_used(llm), calls)
    except Exception:
        pass


def close_case(store: SocStore, case_id: str, *, user: str, verdict: str, note: str = "") -> dict:
    """The analyst's decision. It can differ from the AI's; both are kept (and feed the metrics)."""
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    case = store.get_case(case_id, full=False)
    if not case:
        raise ValueError("no such case")
    store.set_case(case_id, status="closed", analyst_verdict=verdict, analyst_note=note[:2000], closed_at=iso(),
                   closed_by=user)
    agree = "agrees with" if verdict == case.get("verdict") else "differs from"
    store.add_note(case_id, user, f"Closed as {verdict} ({agree} the AI verdict {case.get('verdict') or 'none'}). "
                   f"{note}".strip())
    return store.get_case(case_id)


def reopen_case(store: SocStore, case_id: str, *, user: str) -> dict:
    store.set_case(case_id, status="triaged" if store.get_case(case_id, full=False).get("verdict") else "new",
                   closed_at=None, closed_by=None)
    store.add_note(case_id, user, "Reopened.")
    return store.get_case(case_id)


def apply_tuning(store: SocStore, case_id: str, *, user: str, days: int = 30, override: dict | None = None) -> int:
    """Turn the verdict's tuning proposal (or the analyst's edit of it) into a suppression."""
    case = store.get_case(case_id, full=False) or {}
    t = dict(((case.get("report") or {}).get("fix") or {}).get("tuning") or {})
    t.update({k: v for k, v in (override or {}).items() if v not in (None, "")})
    rule = str(t.get("rule") or "")
    if not rule:
        alerts = store.alerts(case_id=case_id, limit=1)
        rule = (alerts[0].get("rule_id") or alerts[0].get("rule_name")) if alerts else ""
    sid = store.add_suppression(rule=rule, entity_type=str(t.get("entity_type") or ""),
                                entity_value=str(t.get("entity_value") or ""),
                                reason=str(t.get("reason") or f"from case {case_id}"), created_by=user, days=days,
                                case_id=case_id)
    store.add_note(case_id, user, f"Suppression {sid} added for rule {rule!r}"
                   + (f" on {t.get('entity_type')}={t.get('entity_value')}" if t.get("entity_type") else "")
                   + f" for {days} days.")
    return sid


# ---- background loop ----

class Scheduler:
    """One thread: polls ``soc.intake.sources`` and hands new cases to the job manager for triage."""

    def __init__(self, cfg, jobs, *, tick: float = 5.0, leader=None):
        self.cfg, self.jobs, self.tick = cfg, jobs, tick
        self.leader = leader or (lambda: True)      # with several servers only the scheduling leader polls
        self._stop = threading.Event()
        self._last_poll = 0.0
        self.thread: threading.Thread | None = None
        self.last: dict[str, Any] = {}

    def start(self) -> None:
        if getattr(self.jobs, "mode", "local") == "local":
            store_for(self.cfg).mark_orphans()      # in queue mode a worker may still be on the case
        self.thread = threading.Thread(target=self._loop, name="actaeon-soc-scheduler", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self.leader():
                    self.once()
            except Exception:
                log.exception("scheduler tick failed")
            self._stop.wait(self.tick)

    def once(self, *, force_poll: bool = False) -> dict:
        from ..config import get_config
        try:
            cfg = self.cfg = get_config()       # settings saved in the UI apply without a restart
        except Exception:
            cfg = self.cfg
        store = store_for(cfg)
        out: dict[str, Any] = {"polled": [], "queued": []}
        if cfg.soc.intake.sources and (force_poll or time.monotonic() - self._last_poll >= cfg.soc.intake.poll_interval_sec):
            self._last_poll = time.monotonic()
            from ..connectors import get_hub
            from .intake import poll_source
            for src in cfg.soc.intake.sources:
                try:
                    out["polled"].append({"source": src["name"], **poll_source(cfg, store, get_hub(cfg), src)})
                except Exception as exc:
                    out["polled"].append({"source": src["name"], "error": str(exc)[:300]})
        out["expired_actions"] = store.expire_actions()
        if cfg.soc.auto:
            out["queued"] = queue_new(cfg, self.jobs, store)
        self.last = {"at": iso(), **out}
        return out


def queue_new(cfg, jobs, store: SocStore | None = None) -> list[str]:
    """Submit triage jobs for new cases, up to soc.workers running at once."""
    store = store or store_for(cfg)
    running = len([c for c in store.cases(status="triaging", limit=100)])
    free = max(0, cfg.soc.workers - running)
    queued = []
    for c in store.cases(status="new", limit=50):
        if free <= 0:
            break
        if c.get("severity", 0) < cfg.soc.min_severity:
            continue
        if budget_reached(cfg, store):
            break
        submit_triage(cfg, jobs, c["id"], actor="scheduler")
        queued.append(c["id"])
        free -= 1
    return queued


def submit_triage(cfg, jobs, case_id: str, *, actor: str = "", manual: bool = False) -> str:
    store = store_for(cfg)
    store.set_case(case_id, status="triaging")

    def fn(ctl):
        res = triage_case(cfg, case_id, actor=actor, checkpoint=ctl.checkpoint, manual=manual)
        return {"case_id": case_id, "verdict": res.get("verdict"), "status": res.get("status")}
    job_id = jobs.submit("triage", {"case_id": case_id}, fn, task="triage",
                         params={"case_id": case_id, "actor": actor, "manual": manual})
    store.set_case(case_id, job_id=job_id)
    return job_id
