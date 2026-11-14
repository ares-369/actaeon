"""Scored hunting benchmark.

Runs labelled hypotheses through the real engine and reports whether each verdict
matches the expected outcome, plus threat precision and recall. The built-in
cases use the demo data (actaeon/demo/data.py); a YAML file of your own cases
can be used for real data::

    - id: my-case
      hypothesis: "..."
      expect: [threat]               # outcomes that count as correct

Results depend on the model and on the data. A handful of cases is a smoke
test, not a measure of real-world detection.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

DEMO_CASES = [
    {"id": "office-enc-ps", "expect": ["threat"],
     "hypothesis": "An Office application started PowerShell with an encoded command on any host in the last 7 days."},
    {"id": "c2-beacon", "expect": ["threat"],
     "hypothesis": "A host made regular, repeated connections to one rare external destination in the last 7 days."},
    {"id": "schtask-persist", "expect": ["threat"],
     "hypothesis": "A scheduled task that runs hidden PowerShell was created on any host in the last 7 days."},
    {"id": "password-spray", "expect": ["threat"],
     "hypothesis": "One source failed to sign in to many different accounts within a short window in the last 7 days."},
    {"id": "benign-admin-enc", "expect": ["telemetry_found_benign", "no_results"],
     "hypothesis": "The service account svc.maint ran encoded PowerShell on DEMO-ADM01 in the last 7 days; decide whether "
                   "it is malicious."},
    {"id": "lsass-access", "expect": ["no_results", "logs_missing"],
     "hypothesis": "A process that is not a security tool opened LSASS memory on any host in the last 7 days."},
    {"id": "log-clearing", "expect": ["no_results", "logs_missing"],
     "hypothesis": "A Windows event log was cleared on any host in the last 7 days."},
    {"id": "excel-shell", "expect": ["no_results"],
     "hypothesis": "Excel started cmd.exe, wscript.exe or mshta.exe on any host in the last 7 days."},
]


def cases_label(cases: list[dict]) -> str:
    return "built-in demo cases" if cases and all(c in DEMO_CASES for c in cases) else "custom cases"


def load_cases(path: str | None) -> list[dict]:
    if not path:
        return DEMO_CASES
    cases = yaml.safe_load(Path(path).read_text()) or []
    for c in cases:
        if not c.get("id") or not c.get("hypothesis") or not c.get("expect"):
            raise ValueError("each case needs id, hypothesis and expect")
    return cases


def score(results: list[dict]) -> dict:
    tp = sum(r["outcome"] == "threat" and "threat" in r["expect"] for r in results)
    fp = sum(r["outcome"] == "threat" and "threat" not in r["expect"] for r in results)
    fn = sum(r["outcome"] != "threat" and "threat" in r["expect"] for r in results)
    correct = sum(r["correct"] for r in results)
    return {"cases": len(results), "correct": correct, "accuracy": round(correct / max(1, len(results)), 2),
            "threat_precision": round(tp / (tp + fp), 2) if tp + fp else None,
            "threat_recall": round(tp / (tp + fn), 2) if tp + fn else None,
            "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "tokens_in": sum(r.get("tokens_in") or 0 for r in results),
            "tokens_out": sum(r.get("tokens_out") or 0 for r in results),
            "tokens_cached": sum(r.get("tokens_cached") or 0 for r in results),
            "llm_calls": sum(r.get("llm_calls") or 0 for r in results),
            "seconds": sum(r.get("seconds") or 0 for r in results),
            "infra_errors": sum(1 for r in results if r.get("status") == "error"),
            "reruns": sum((r.get("attempts") or 1) - 1 for r in results)}


_INFRA = __import__("re").compile(r"(?i)429|resource_exhausted|quota|rate.?limit|timed? ?out|timeout|connection|overloaded|unavailable")


def parse_model(spec: str) -> dict:
    """'provider/model' -> {provider, model}. The model part may itself contain '/'."""
    from .config import PROVIDERS
    prov, _, model = str(spec).partition("/")
    if prov not in PROVIDERS or not model:
        raise ValueError(f"model must be provider/model with provider one of {PROVIDERS}, got {spec!r}")
    return {"provider": prov, "model": model}


def with_models(cfg, model: str = "", role_models: list[str] | None = None):
    """A copy of ``cfg`` whose roles use the given models, with no fallbacks (so the score is that model's).

    model: 'provider/model' for every role; role_models: ['analyst=provider/model', ...] for single roles."""
    import copy
    import dataclasses
    if not model and not role_models:
        return cfg
    llm = copy.deepcopy(cfg.llm)
    roles = llm.setdefault("roles", {})
    for r in ("planner", "analyst", "reporter"):
        if model:
            roles[r] = parse_model(model)
    for item in role_models or []:
        role, _, spec = str(item).partition("=")
        if role not in ("planner", "analyst", "reporter"):
            raise ValueError(f"role must be planner, analyst or reporter, got {role!r}")
        roles[role] = parse_model(spec)
    for r in roles.values():
        if isinstance(r, dict):
            r.pop("fallback", None)
    raw = copy.deepcopy(cfg.raw or {})
    raw["llm"] = llm
    return dataclasses.replace(cfg, llm=llm, raw=raw)


def run(cfg, cases: list[dict], *, max_steps: int | None = None, on_case=None, workers: int = 1,
        model: str = "", role_models: list[str] | None = None) -> dict:
    """Run every case as a real hunt and score it. ``workers`` > 1 runs cases in parallel.
    ``model`` / ``role_models``: run with these models instead of the configured ones (see with_models)."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from .hunt.service import run_hunt
    from .providers import LLM
    cfg = with_models(cfg, model, role_models)
    llm = LLM(cfg) if (model or role_models) else None
    lock = threading.Lock()

    def one(c):
        t0 = time.monotonic()
        for attempt in range(3):
            try:
                h = run_hunt(cfg, c["hypothesis"], origin=f"bench:{c['id']}", max_steps=max_steps, llm=llm)
            except Exception as exc:     # one broken case must not end the run (and waste the others)
                h = {"status": "error", "error": f"{type(exc).__name__}: {exc}"[:500], "steps": [], "models": {}}
            # A hunt that died on the model service (rate limit, timeout) says nothing about Actaeon's
            # judgement: run it again instead of scoring it, and record that it happened.
            if h.get("status") != "error" or not _INFRA.search(h.get("error") or ""):
                break
            time.sleep(60 * (attempt + 1))
        v = h.get("verdict") or {}
        r = {"id": c["id"], "expect": c["expect"], "outcome": h.get("outcome"), "status": h.get("status"),
             "correct": h.get("outcome") in c["expect"], "confidence": v.get("confidence"),
             "calls": sum(1 for s in h.get("steps") or [] if s["kind"] == "call"),
             "blocked": sum(1 for s in h.get("steps") or [] if s["kind"] == "blocked"),
             "seconds": round(time.monotonic() - t0), "hunt_id": h.get("id"), "error": h.get("error"),
             "attempts": attempt + 1}
        u = (h.get("models") or {}).get("usage") or {}
        r.update(tokens_in=u.get("tokens_in", 0), tokens_out=u.get("tokens_out", 0),
                 tokens_cached=u.get("tokens_cached", 0), llm_calls=u.get("calls", 0))
        if on_case:
            with lock:
                on_case(r)
        return r

    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(one, cases))
    else:
        results = [one(c) for c in cases]
    models = {r: {"provider": cfg.role_cfg(r).get("provider"), "model": cfg.role_cfg(r).get("model")}
              for r in ("planner", "analyst", "reporter")}
    from . import __version__
    out = {"when": datetime.now(timezone.utc).isoformat(timespec="seconds"), "actaeon": __version__,
           "models": models, "cases_file": cases_label(cases), "score": score(results), "results": results}
    p = cfg.data_dir / f"bench-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
    p.write_text(json.dumps(out, indent=1))
    out["file"] = str(p)
    return out


def markdown_row(out: dict) -> str:
    """One row for the per-model results table in docs/benchmarks.md."""
    s, m = out["score"], out["models"]
    roles = {f"{v.get('provider')}/{v.get('model')}" for v in m.values()}
    who = next(iter(roles)) if len(roles) == 1 else "; ".join(f"{k}: {v.get('provider')}/{v.get('model')}"
                                                             for k, v in m.items())

    def pct(x):
        return "n/a" if x is None else f"{x:.2f}"
    n = max(1, s["cases"])
    cached = s.get("tokens_cached", 0) / max(1, s["tokens_in"])
    return (f"| {who} | {out.get('cases_file', '')} | {s['correct']}/{s['cases']} | {pct(s['threat_precision'])} | "
            f"{pct(s['threat_recall'])} | {s['false_positives']} | {round(s['seconds'] / n)} s | "
            f"{round(s['tokens_in'] / n / 1000)}k ({cached:.0%} cached) | {round(s['tokens_out'] / n / 1000, 1)}k | "
            f"{out['when'][:10]} | {out.get('actaeon', '')} |")
