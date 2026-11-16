"""What the analyst sees on a case: the entity graph, the timeline and the ATT&CK chain.

All three are built from stored data (alerts, the checked verdict, actions, notes). No model is used.
"""

from __future__ import annotations

from ..hunt.attack_names import name as tname
from ..hunt.attack_names import tactics as ttactics

TACTIC_ORDER = ("reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
                "collection", "command-and-control", "exfiltration", "impact")
MAX_NODES = 150


def _key(kind: str, value: str) -> str:
    return f"{kind}:{value.lower()}"


def graph(case: dict) -> dict:
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    by_value: dict[str, str] = {}

    def node(kind: str, value: str, **extra) -> str | None:
        k = _key(kind, value)
        if k not in nodes:
            if len(nodes) >= MAX_NODES:
                return None
            nodes[k] = {"id": k, "type": kind, "label": value[:80], "value": value, "alerts": 0, **extra}
        else:
            for kk, vv in extra.items():
                if vv and not nodes[k].get(kk):
                    nodes[k][kk] = vv
        by_value.setdefault(value.lower(), k)
        return k

    def edge(a: str | None, b: str | None, kind: str, ts: str = "") -> None:
        if not a or not b or a == b:
            return
        e = edges.setdefault((a, b, kind), {"source": a, "target": b, "type": kind, "count": 0, "first": ts, "last": ts})
        e["count"] += 1
        if ts:
            e["first"] = min(e["first"] or ts, ts)
            e["last"] = max(e["last"] or ts, ts)

    report = case.get("report") or {}
    roles = {str(e.get("value", "")).lower(): e.get("role") for e in report.get("entities") or []}
    for a in case.get("alerts") or []:
        an = node("alert", a["id"], label=(a.get("title") or "alert")[:60], severity=a.get("severity"), ts=a.get("ts"))
        if an is None:
            break
        nodes[an]["label"] = (a.get("title") or "alert")[:60]
        for e in a.get("entities") or []:
            en = node(e["type"], e["value"], role=roles.get(e["value"].lower()), internal=e.get("internal"))
            if en:
                nodes[en]["alerts"] += 1
                nodes[en].setdefault("first", a.get("ts"))
                nodes[en]["first"] = min(nodes[en]["first"] or a.get("ts"), a.get("ts") or "")
                nodes[en]["last"] = max(nodes[en].get("last") or "", a.get("ts") or "")
                edge(an, en, "in alert", a.get("ts") or "")
    for e in report.get("entities") or []:
        node(e["type"], e["value"], role=e.get("role"))
    for r in report.get("relations") or []:
        a = by_value.get(str(r["from"]).lower()) or node("entity", str(r["from"]))
        b = by_value.get(str(r["to"]).lower()) or node("entity", str(r["to"]))
        edge(a, b, r.get("type") or "related")
    return {"nodes": list(nodes.values()), "edges": list(edges.values()),
            "truncated": len(nodes) >= MAX_NODES}


def timeline(case: dict) -> list[dict]:
    items = []
    for a in case.get("alerts") or []:
        items.append({"time": a.get("ts"), "kind": "alert", "text": a.get("title"), "severity": a.get("severity"),
                      "ref": a["id"]})
    report = case.get("report") or {}
    for t in report.get("timeline") or []:
        items.append({"time": t.get("time") or "", "kind": "finding", "text": t.get("event") or t.get("text") or "",
                      "evidence": t.get("evidence") or []})
    for x in case.get("actions") or []:
        items.append({"time": x.get("decided_at") or x.get("proposed_at"), "kind": "action",
                      "text": f"{x['name']} on {x['target']}: {x['status']}"})
    for n in case.get("notes") or []:
        items.append({"time": n.get("ts"), "kind": "note", "text": f"{n.get('author')}: {n.get('text')}"})
    if case.get("triaged_at"):
        items.append({"time": case["triaged_at"], "kind": "verdict",
                      "text": f"AI verdict: {case.get('verdict')} ({case.get('confidence')})"})
    if case.get("closed_at"):
        items.append({"time": case["closed_at"], "kind": "closed",
                      "text": f"Closed by {case.get('closed_by')}: {case.get('analyst_verdict') or case.get('verdict')}"})
    return sorted(items, key=lambda i: str(i.get("time") or ""))


def attack_chain(case: dict) -> list[dict]:
    techs = list(dict.fromkeys([*(case.get("attack") or []),
                                *[t for a in case.get("alerts") or [] for t in a.get("attack") or []]]))
    by: dict[str, list[dict]] = {}
    for t in techs:
        tac = ttactics(t) or ["unknown"]
        for ta in tac:
            by.setdefault(ta, [])
            if t not in [x["id"] for x in by[ta]]:
                by[ta].append({"id": t, "name": tname(t)})
    order = {t: i for i, t in enumerate(TACTIC_ORDER)}
    return [{"tactic": k, "techniques": v} for k, v in sorted(by.items(), key=lambda kv: order.get(kv[0], 99))]
