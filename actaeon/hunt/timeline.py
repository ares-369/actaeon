"""Timeline of a hunt: every event in its evidence, in time order, with the entities involved.

Built from the stored results (no model). Field names are matched loosely so it
works across sources: a time field (``@timestamp``, ``timestamp``, ``time``,
``event.created`` ...), host, user, process and network fields. Events with no
readable time are left out and counted.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime

from .triage import classify_event, events_from

_TIME = re.compile(r"(?i)(^|\.)(@timestamp|timestamp|time|_time|event\.created|eventtime|ts|date|created)$")
_HOST = re.compile(r"(?i)(^|\.)(host\.name|hostname|host|computer(name)?|agent\.name|device(name)?|endpoint)$")
_USER = re.compile(r"(?i)(^|\.)(user\.name|username|user|account(name)?|subject(user)?name|upn)$")
_DEST = re.compile(r"(?i)(^|\.)(destination\.(ip|domain)|dst(_ip)?|remote(ip|address)|url|domain)$")
_SRC = re.compile(r"(?i)(^|\.)(source\.ip|src(_ip)?|client\.ip)$")
_PROC = re.compile(r"(?i)(^|\.)(process\.name|image|process|exe|processname)$")
_PARENT = re.compile(r"(?i)(^|\.)(process\.parent\.name|parent(image|process)?(name)?)$")
_CMD = re.compile(r"(?i)(^|\.)(process\.command_line|command_?line|cmdline)$")
_WHAT = re.compile(r"(?i)(^|\.)(event\.(category|action|outcome)|action|outcome|event_?type)$")


def _pick(e: dict[str, str], rx: re.Pattern) -> str:
    for k, v in e.items():
        if rx.search(k) and v not in ("", "None", "null"):
            return v
    return ""


def _when(v: str) -> datetime | None:
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        pass
    if re.fullmatch(r"\d{10}(\.\d+)?", v):
        from datetime import timezone
        return datetime.fromtimestamp(float(v), tz=timezone.utc)
    if re.fullmatch(r"\d{13}", v):
        from datetime import timezone
        return datetime.fromtimestamp(int(v) / 1000, tz=timezone.utc)
    return None


def build(h: dict, limit: int = 500) -> dict:
    rows, seen, no_time = [], set(), 0
    for s in h.get("steps") or []:
        if s["kind"] != "call" or not s["ok"]:
            continue
        for e in events_from(s.get("result") or ""):
            t = _when(_pick(e, _TIME))
            if not t:
                no_time += 1
                continue
            row = {"time": t.isoformat().replace("+00:00", "Z"), "evidence": f"E{s['n']}",
                   "host": _pick(e, _HOST), "user": _pick(e, _USER), "process": _pick(e, _PROC),
                   "parent": _pick(e, _PARENT), "command": _pick(e, _CMD)[:400], "source": _pick(e, _SRC),
                   "destination": _pick(e, _DEST),
                   "what": " ".join(dict.fromkeys(v for k, v in e.items() if _WHAT.search(k)))[:120],
                   "state": classify_event(e)}
            key = (row["time"], row["host"], row["process"], row["destination"], row["command"], row["what"])
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
    rows.sort(key=lambda r: r["time"])
    ents = {k: Counter(r[k] for r in rows if r[k]).most_common(25) for k in ("host", "user", "destination", "process")}
    return {"events": rows[:limit], "total": len(rows), "truncated": len(rows) > limit, "no_time": no_time,
            "first": rows[0]["time"] if rows else None, "last": rows[-1]["time"] if rows else None,
            "entities": {k: [{"value": v, "count": c} for v, c in lst] for k, lst in ents.items()}}


def describe(r: dict) -> str:
    parts = [r["what"]]
    if r["process"]:
        parts.append(f"{r['parent'] + ' -> ' if r['parent'] else ''}{r['process']}")
    if r["command"]:
        parts.append(r["command"][:160])
    if r["source"]:
        parts.append(f"from {r['source']}")
    if r["destination"]:
        parts.append(f"to {r['destination']}")
    return "  ".join(p for p in parts if p)
