"""Detection check: which authorised tests did the alert source and Actaeon notice?

Input is a run file: JSON lines (or a JSON list), one test each::

    {"name": "port scan", "target": "192.0.2.10", "source": "192.0.2.50",
     "started": "2026-01-01T10:00:00+00:00", "finished": "2026-01-01T10:02:00+00:00", "status": "ok"}

Nothing is attacked here: the tests were run by something else (by hand, or ``oniops assess --record``). Each test
gets the furthest layer it reached:

* ``case``: an alert of the test is in a case (with that case's verdict)
* ``alert``: Actaeon stored an alert, but it opened no case (suppressed, below the threshold)
* ``source``: the alert source has an alert, Actaeon did not take it in
* ``missed``: nothing
* ``unknown``: the test did not run, or a lookup failed. Never counted as missed or as detected.

An alert belongs to a test when its time is inside the test (plus ``grace`` minutes) and it names the tester's
address; without a ``source`` in the test, the target's. A rule that also fired for the same address in the
equally long window just before the test is background: it is listed, and does not count as a detection.
"""

from __future__ import annotations

import json
from datetime import timedelta

from .alerts import hits_from_result, normalize
from .intake import MAX_POLL_BYTES
from .util import iso, now, parse_iso

LAYERS = ("case", "alert", "source", "missed", "unknown")
PAGE = 500


def load_run(text: str) -> list[dict]:
    text = text.strip()
    items = json.loads(text) if text.startswith("[") else [json.loads(x) for x in text.splitlines() if x.strip()]
    out = []
    for n, t in enumerate(items, 1):
        if not isinstance(t, dict) or not t.get("target") or not t.get("started") or not t.get("finished"):
            raise ValueError(f"test {n}: needs target, started and finished")
        a, b = parse_iso(t["started"]), parse_iso(t["finished"])
        if b < a:
            raise ValueError(f"test {n}: finished is before started")
        out.append({**t, "name": str(t.get("name") or f"test {n}")[:120], "_from": a, "_to": b})
    return out


def _names(alert: dict, address: str) -> bool:
    return any(str(e.get("value", "")).lower() == address.lower() for e in alert.get("entities") or [])


def _split(alerts: list[dict], t: dict, grace: timedelta) -> tuple[list[dict], list[dict]]:
    """(alerts of the test, background alerts) for the test's address."""
    end = t["_to"] + grace
    start0 = t["_from"] - (end - t["_from"])
    addr = str(t.get("source") or t["target"])
    during, before = [], set()
    for a in alerts:
        if not a.get("ts") or not _names(a, addr):
            continue
        try:
            when = parse_iso(a["ts"])
        except ValueError:
            continue
        if t["_from"] <= when <= end:
            during.append(a)
        elif start0 <= when < t["_from"]:
            before.add(a.get("rule_id") or a.get("title"))
    def noisy(a):
        return (a.get("rule_id") or a.get("title")) in before
    return [a for a in during if not noisy(a)], [a for a in during if noisy(a)]


def source_alerts(cfg, hub, src: dict, t: dict, grace: timedelta, query: str | None) -> list[dict]:
    """Alerts of the source over the control window and the test. Raises when the answer is not complete."""
    end = t["_to"] + grace
    args = {**(src.get("arguments") or {}), "time_from": iso(t["_from"] - (end - t["_from"])), "time_to": iso(end),
            "size": PAGE}
    if query:
        args["query"] = query
    res = hub.call(src["connector"], src["tool"], args, actor="detection-check", max_bytes=MAX_POLL_BYTES)
    items = None if res.get("is_error") else hits_from_result(res["content"])
    if items is None or res.get("truncated"):
        raise RuntimeError("the alert source returned an error or a cut result")
    if len(items) >= PAGE:
        raise RuntimeError(f"more than {PAGE} alerts in the window: narrow --query")
    out = []
    for i in items:
        try:
            out.append(normalize(i, source=src["name"], field_map=cfg.soc.intake.field_map,
                                 severity_scale=cfg.soc.intake.severity_scale))
        except (ValueError, TypeError):
            continue
    return out


def _rules(alerts: list[dict]) -> list[str]:
    return sorted({f"{a.get('rule_id') or '-'}: {(a.get('title') or '')[:80]}" for a in alerts})


def check(cfg, store, hub, tests: list[dict], *, grace_min: int = 10, query: str | None = None) -> dict:
    grace = timedelta(minutes=grace_min)
    rows = []
    for t in tests:
        row = {"name": t["name"], "target": t["target"], "source": t.get("source") or "", "started": t["started"],
               "layer": "unknown", "verdict": None, "cases": [], "rules": [], "background": [], "first_min": None, "note": ""}
        rows.append(row)
        if str(t.get("status") or "ok") != "ok":
            row["note"] = f"the test did not complete ({str(t['status'])[:80]})"
            continue
        if t["_to"] + grace > now():
            row["note"] = f"too early: wait until {grace_min} minutes after the test"
            continue
        span = (t["_to"] + grace) - t["_from"]
        mine, noise = _split(store.alerts(since=iso(t["_from"] - span - timedelta(days=1)), limit=20000), t, grace)
        src_hits, src_noise, errors = [], [], []
        for src in cfg.soc.intake.sources:
            try:
                h, n = _split(source_alerts(cfg, hub, src, t, grace, query), t, grace)
                src_hits += h
                src_noise += n
            except Exception as exc:
                errors.append(f"{src['name']}: {str(exc)[:160]}")
        row["rules"], row["background"] = _rules(mine + src_hits), _rules(noise + src_noise)
        row["cases"] = sorted({a["case_id"] for a in mine if a.get("case_id")})
        row["verdict"] = next((c["verdict"] for c in (store.get_case(i, full=False) or {} for i in row["cases"])
                               if c.get("verdict")), None)
        if row["cases"]:
            row["layer"] = "case"
        elif mine:
            row["layer"], row["note"] = "alert", "alert status: " + ", ".join(sorted({a["status"] for a in mine}))
        elif src_hits:
            row["layer"] = "source"
        elif errors or not cfg.soc.intake.sources:
            row["note"] = "; ".join(errors) or "no alert source is configured"
        else:
            row["layer"] = "missed"
        if errors and row["layer"] != "unknown":
            row["note"] = "; ".join(filter(None, [row["note"], *errors]))
        hits = mine + src_hits
        if hits:
            row["first_min"] = round((min(parse_iso(a["ts"]) for a in hits) - t["_from"]).total_seconds() / 60, 1)
    known = [r for r in rows if r["layer"] != "unknown"]
    return {"tests": rows, "counts": {k: sum(r["layer"] == k for r in rows) for k in LAYERS}, "scored": len(known),
            "seen_by_source": sum(r["layer"] != "missed" for r in known),
            "in_a_case": sum(r["layer"] == "case" for r in known), "grace_min": grace_min}


def markdown(res: dict) -> str:
    def e(s):
        return str(s).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")
    out = ["# Detection check", "", f"Alert raised for {res['seen_by_source']} of {res['scored']} scored tests, "
           f"{res['in_a_case']} in an Actaeon case. Not scored: {res['counts']['unknown']}.", "",
           "| Test | Target | Reached | Verdict | First alert | Rules | Note |", "|---|---|---|---|---|---|---|"]
    for r in res["tests"]:
        first = f"{r['first_min']} min" if r["first_min"] is not None else "-"
        out.append(f"| {e(r['name'])} | {e(r['target'])} | {r['layer']} | {r['verdict'] or '-'} | {first} | "
                   f"{e('; '.join(r['rules']) or '-')} | {e(r['note'])} |")
    bg = sorted({b for r in res["tests"] for b in r["background"]})
    if bg:
        out += ["", "Background (also fired just before the test, not counted): " + e("; ".join(bg))]
    return "\n".join(out) + "\n"
