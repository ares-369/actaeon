"""Verdict limits the model cannot overrule: alerts that are never dismissed, and recorded authorised tests.

``soc.never_dismiss`` lists rules whose alerts cannot be called benign or a false positive (contact with a decoy, a
canary account). It is applied last, after the model, the second look and any escalation::

    soc:
      never_dismiss:
        - {rule: "decoy-*", verdict: true_positive, reason: "nothing legitimate talks to a decoy"}
      authorised_tests: tests.jsonl      # in the data folder

``authorised_tests`` is a file of JSON lines, written BEFORE each test by whoever runs it: name, source, target, started,
finished (the planned end). A case is an authorised test only when EVERY alert in it names that source and that target and
happened inside that window. An address alone is never enough: a compromised test host must not be invisible. Windows over
MAX_WINDOW_H hours are ignored, and an unreadable file authorises nothing.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from datetime import timedelta

from .util import parse_iso

log = logging.getLogger("actaeon.floor")
MAX_WINDOW_H = 6
DISMISS = ("benign", "false_positive")


def validate(items, tests) -> tuple[list[dict], str]:
    out = []
    if not isinstance(items, list):
        raise ValueError("soc.never_dismiss must be a list")
    for i in items:
        if not isinstance(i, dict) or not i.get("rule"):
            raise ValueError("soc.never_dismiss: each entry needs a rule (id or name, * allowed)")
        v = str(i.get("verdict", "needs_analyst"))
        if v not in ("true_positive", "needs_analyst"):
            raise ValueError("soc.never_dismiss: verdict must be true_positive or needs_analyst")
        out.append({"rule": str(i["rule"]), "verdict": v, "reason": str(i.get("reason", ""))[:300]})
    name = str(tests or "")
    if "/" in name or "\\" in name or name.startswith("."):
        raise ValueError("soc.authorised_tests: a file name in the data folder")
    return out, name


def floor_for(cfg, alerts: list[dict]) -> dict | None:
    hits = [f for f in cfg.soc.never_dismiss for a in alerts
            if fnmatch.fnmatchcase(str(a.get("rule_id") or ""), f["rule"])
            or fnmatch.fnmatchcase(str(a.get("rule_name") or "").lower(), f["rule"].lower())]
    return next((f for f in hits if f["verdict"] == "true_positive"), hits[0] if hits else None)


def windows(cfg) -> list[dict]:
    if not cfg.soc.authorised_tests:
        return []
    try:
        lines = (cfg.data_dir / cfg.soc.authorised_tests).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-2000:]:
        try:
            t = json.loads(line)
            a, b = parse_iso(t["started"]), parse_iso(t["finished"])
            if t["source"] and t["target"] and a <= b <= a + timedelta(hours=MAX_WINDOW_H):
                out.append({"name": str(t.get("name") or "test")[:80], "source": str(t["source"]).lower(),
                            "target": str(t["target"]).lower(), "from": a, "to": b})
        except (ValueError, KeyError, TypeError):
            continue
    return out


def test_for(alert: dict, wins: list[dict]) -> str:
    """The authorised test an alert belongs to ('' = none)."""
    try:
        when = parse_iso(alert["ts"])
    except (ValueError, KeyError, TypeError):
        return ""
    vals = {str(e.get("value", "")).lower() for e in alert.get("entities") or []}
    return next((w["name"] for w in wins if w["source"] in vals and w["target"] in vals and w["from"] <= when <= w["to"]), "")


def apply(cfg, alerts: list[dict], v: dict) -> dict:
    """The verdict after the limits. Adds ``authorised_test`` or ``floor`` to it."""
    if not alerts:
        return v
    wins = windows(cfg)
    names = [test_for(a, wins) for a in alerts] if wins else [""]
    if all(names):
        label = ", ".join(sorted(set(names)))
        return {**v, "authorised_test": label, "verdict": "benign", "confidence": 95,
                "summary": f"Authorised test: {label}. " + (v.get("summary") or ""),
                "checks": [*v["checks"], f"all {len(alerts)} alerts match the recorded test (source, target and time); "
                           f"the analysis said {v['verdict']}"]}
    f = floor_for(cfg, alerts)
    if f and v["verdict"] in (*DISMISS, "logs_missing"):
        why = f": {f['reason']}" if f["reason"] else ""
        return {**v, "floor": f["rule"], "verdict": f["verdict"], "confidence": 80 if f["verdict"] == "true_positive" else 0,
                "summary": f"Not dismissed by a fixed rule{why}. The analysis said {v['verdict']}: " + (v.get("summary") or ""),
                "checks": [*v["checks"], f"soc.never_dismiss ({f['rule']}): the analysis said {v['verdict']} at confidence "
                           f"{v['confidence']}; alerts of this rule are never dismissed automatically{why}"]}
    return v
