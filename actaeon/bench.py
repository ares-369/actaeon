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
            "cost_usd": (round(sum(r["cost_usd"] for r in results), 4)
                         if results and all(r.get("cost_usd") is not None for r in results) else None),
            "seconds": sum(r.get("seconds") or 0 for r in results)}


def run(cfg, cases: list[dict], *, max_steps: int | None = None, on_case=None, workers: int = 1) -> dict:
    """Run every case as a real hunt and score it. ``workers`` > 1 runs cases in parallel."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from .hunt.service import run_hunt
    lock = threading.Lock()

    def one(c):
        t0 = time.monotonic()
        h = run_hunt(cfg, c["hypothesis"], origin=f"bench:{c['id']}", max_steps=max_steps)
        v = h.get("verdict") or {}
        r = {"id": c["id"], "expect": c["expect"], "outcome": h.get("outcome"), "status": h.get("status"),
             "correct": h.get("outcome") in c["expect"], "confidence": v.get("confidence"),
             "calls": sum(1 for s in h.get("steps") or [] if s["kind"] == "call"),
             "blocked": sum(1 for s in h.get("steps") or [] if s["kind"] == "blocked"),
             "seconds": round(time.monotonic() - t0), "hunt_id": h.get("id"), "error": h.get("error")}
        u = (h.get("models") or {}).get("usage") or {}
        r.update(tokens_in=u.get("tokens_in", 0), tokens_out=u.get("tokens_out", 0), cost_usd=u.get("cost_usd"))
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
              for r in ("planner", "analyst")}
    out = {"when": datetime.now(timezone.utc).isoformat(timespec="seconds"), "models": models,
           "score": score(results), "results": results}
    p = cfg.data_dir / f"bench-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
    p.write_text(json.dumps(out, indent=1))
    out["file"] = str(p)
    return out
