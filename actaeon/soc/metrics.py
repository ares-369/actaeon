"""SOC metrics for the dashboard: volume, verdicts, speed, agreement, noisy rules, tokens. No model."""

from __future__ import annotations

from collections import Counter, defaultdict
from statistics import median

from .store import SocStore
from .util import ago, loads, parse_iso


def _minutes(a: str | None, b: str | None) -> float | None:
    if not a or not b:
        return None
    try:
        return max(0.0, (parse_iso(b) - parse_iso(a)).total_seconds() / 60.0)
    except ValueError:
        return None


def metrics(store: SocStore, days: int = 14) -> dict:
    since = ago(days=days)
    rows = store.stats_rows(since)
    by_day: dict[str, Counter] = defaultdict(Counter)
    ai = Counter()
    final = Counter()
    agree = disagree = 0
    ttt, ttc, tokens = [], [], []
    rules: dict[str, Counter] = defaultdict(Counter)
    confusion: Counter = Counter()
    for r in rows:
        day = (r.get("created") or "")[:10]
        v = r.get("verdict") or "untriaged"
        by_day[day][v] += 1
        ai[v] += 1
        fv = r.get("analyst_verdict") or (r.get("verdict") if r.get("status") == "closed" else None)
        if fv:
            final[fv] += 1
        if r.get("analyst_verdict") and r.get("verdict"):
            confusion[(r["verdict"], r["analyst_verdict"])] += 1
            if r["analyst_verdict"] == r["verdict"]:
                agree += 1
            else:
                disagree += 1
        m = _minutes(r.get("created"), r.get("triaged_at"))
        if m is not None:
            ttt.append(m)
        m = _minutes(r.get("created"), r.get("closed_at"))
        if m is not None:
            ttc.append(m)
        u = loads(r.get("usage"), {}) or {}
        if u.get("tokens_in") is not None:
            tokens.append(int(u.get("tokens_in", 0)) + int(u.get("tokens_out", 0)))
        rule = r.get("rule") or "(no rule)"
        rules[rule][fv or v] += 1
    days_list = sorted(by_day)
    noisy = []
    for rule, c in rules.items():
        total = sum(c.values())
        noise = c["false_positive"] + c["benign"]
        noisy.append({"rule": rule, "cases": total, "true_positive": c["true_positive"], "noise": noise,
                      "noise_rate": round(noise / total, 2) if total else 0})
    noisy.sort(key=lambda x: (x["noise"], x["cases"]), reverse=True)
    counts = store.counts()
    return {
        "days": days,
        "cases": len(rows),
        "alerts": counts["alerts"],
        "open": sum(n for s, n in counts["status"].items() if s != "closed"),
        "status": counts["status"],
        "pending_actions": counts["pending_actions"],
        "ai_verdicts": dict(ai),
        "final_verdicts": dict(final),
        "agreement": {"agree": agree, "disagree": disagree,
                      "rate": round(agree / (agree + disagree), 2) if agree + disagree else None,
                      "matrix": [{"ai": a, "analyst": b, "count": n} for (a, b), n in confusion.items()]},
        "minutes_to_triage": {"median": round(median(ttt), 1) if ttt else None, "n": len(ttt)},
        "minutes_to_close": {"median": round(median(ttc), 1) if ttc else None, "n": len(ttc)},
        "tokens_per_case": {"median": int(median(tokens)) if tokens else None, "n": len(tokens)},
        "per_day": [{"day": d, **dict(by_day[d])} for d in days_list],
        "tokens_per_day": store.usage_days(days),
        "noisy_rules": noisy[:15],
        "alert_rules": store.rule_counts(since)[:15],
        "suppressions": len(store.suppressions()),
        # suppressions that hid high or critical alerts: worth a second look by a person
        "suppression_warnings": [{k: x.get(k) for k in ("id", "rule", "entity_type", "entity_value", "hits",
                                                        "high_hits", "last_hit", "expires")}
                                 for x in store.suppressions() if x.get("high_hits")],
    }
