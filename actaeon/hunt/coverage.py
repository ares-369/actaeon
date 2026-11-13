"""Coverage: which ATT&CK techniques have been hunted, how recently and with what result,
and which data roles hunts needed that no connector provides."""

from __future__ import annotations

from collections import defaultdict

from .attack_names import _data, current, data_components, name, tactics, version
from .library import starters

_RANK = {"threat": 5, "telemetry_found_benign": 4, "no_results": 3, "inconclusive": 2, "logs_missing": 1}


def build(store, library, hub_specs: dict) -> dict:
    techs: dict[str, dict] = defaultdict(lambda: {"hunts": 0, "last": "", "outcomes": defaultdict(int),
                                                  "saved": 0, "scheduled": 0, "starter": False})
    missing_roles: dict[str, int] = defaultdict(int)
    for h in store.list(limit=5000):
        ids = {current(t) for t in ((h.get("plan") or {}).get("attack") or []) + ((h.get("verdict") or {}).get("attack") or [])}
        for r in (h.get("plan") or {}).get("missing_roles") or []:
            missing_roles[r] += 1
        for t in ids:
            d = techs[t]
            d["hunts"] += 1
            d["last"] = max(d["last"], h["created"])
            d["outcomes"][h.get("outcome") or "none"] += 1
    for s in library.list():
        for t in {current(x) for x in s["attack"]}:
            techs[t]["saved"] += 1
            techs[t]["scheduled"] += int(s["enabled"] and s["interval_minutes"] > 0)
    for s in starters():
        for t in s["attack"]:
            techs[t]["starter"] = True
    rows = []
    for t, d in techs.items():
        outcomes = dict(d["outcomes"])
        best = max(outcomes, key=lambda o: _RANK.get(o, 0)) if outcomes else ""
        state = ("not hunted" if not d["hunts"] else "data missing" if set(outcomes) <= {"logs_missing", "none"}
                 else "hunted")
        rows.append({"technique": t, "name": name(t), "tactics": tactics(t), "data": data_components(t),
                     "hunts": d["hunts"], "last": d["last"], "outcomes": outcomes,
                     "worst": best, "saved": d["saved"], "scheduled": d["scheduled"], "starter": d["starter"],
                     "state": state})
    rows.sort(key=lambda r: r["technique"])
    roles_with = sorted({r for s in hub_specs.values() if s.enabled for r in s.roles})
    starter_roles = sorted({r for s in starters() for r in s.get("roles") or []})
    # Breadth against the whole matrix, per tactic (parent techniques and sub-techniques both count).
    all_t = _data()["techniques"]
    by_tactic: dict[str, dict] = defaultdict(lambda: {"total": 0, "hunted": 0, "seen": 0})
    state_of = {r["technique"]: r["state"] for r in rows}
    for tid, info in all_t.items():
        for ta in info.get("t") or []:
            b = by_tactic[ta]
            b["total"] += 1
            if tid in state_of:
                b["seen"] += 1
                b["hunted"] += state_of[tid] == "hunted"
    # Log sources that would unlock techniques you have not been able to hunt yet.
    need: dict[str, int] = defaultdict(int)
    for r in rows:
        if r["state"] != "hunted":
            for comp in r["data"]:
                need[comp] += 1
    return {"techniques": rows, "attack_version": version(),
            "tactics": dict(sorted(by_tactic.items())),
            "log_sources_needed": sorted(need.items(), key=lambda kv: (-kv[1], kv[0]))[:12],
            "summary": {"techniques": len(rows), "hunted": sum(r["state"] == "hunted" for r in rows),
                        "data_missing": sum(r["state"] == "data missing" for r in rows),
                        "not_hunted": sum(r["state"] == "not hunted" for r in rows),
                        "scheduled": sum(r["scheduled"] > 0 for r in rows)},
            "roles": {"connected": roles_with, "needed_by_starters": starter_roles,
                      "missing": sorted(set(starter_roles) - set(roles_with)),
                      "missing_in_hunts": dict(missing_roles)}}
