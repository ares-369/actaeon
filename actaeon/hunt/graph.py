"""Investigation graph of a hunt: who did what where, and what it talked to, from the stored results.

Nodes are users, hosts, parent processes, processes, destinations and intel matches; an edge says two of
them appeared together in an event (user on host, host ran process, parent started process, process or
host reached destination, destination matched intel). Every node and edge lists the evidence ids it came
from, and is marked when a finding cites that evidence. Built from the same reading of results as the
timeline, with no model. Large hunts are cut to the most frequent nodes per column.
"""

from __future__ import annotations

import re

from .timeline import build as timeline

COLUMNS = ("user", "host", "parent", "process", "destination", "intel")
PER_COLUMN = 15
_FOUND = re.compile(r'"found"\s*:\s*true', re.I)


def build(h: dict) -> dict:
    v = h.get("verdict") or {}
    cited = {e for f in v.get("findings") or [] if isinstance(f, dict) for e in f.get("evidence") or []}
    tl = timeline(h, limit=5000)
    nodes: dict[tuple[str, str], dict] = {}
    edges: dict[tuple[tuple[str, str], tuple[str, str]], dict] = {}

    def seen(item: dict, t: str | None) -> None:
        if t:
            item["first"] = min(item["first"], t) if item["first"] else t
            item["last"] = max(item["last"], t) if item["last"] else t

    def node(kind: str, label: str, ev: str, t: str | None = None) -> tuple[str, str] | None:
        label = str(label or "").strip()
        if not label or label.lower() in ("none", "null", "-"):
            return None
        k = (kind, label)
        n = nodes.setdefault(k, {"id": f"{kind}:{label}", "kind": kind, "label": label[:120], "count": 0,
                                 "evidence": set(), "cited": False, "first": None, "last": None})
        n["count"] += 1
        seen(n, t)
        n["evidence"].add(ev)
        n["cited"] = n["cited"] or ev in cited
        return k

    def edge(a, b, ev: str, t: str | None = None) -> None:
        if not a or not b or a == b:
            return
        e = edges.setdefault((a, b), {"from": f"{a[0]}:{a[1]}", "to": f"{b[0]}:{b[1]}", "count": 0,
                                      "evidence": set(), "cited": False, "first": None, "last": None})
        e["count"] += 1
        seen(e, t)
        e["evidence"].add(ev)
        e["cited"] = e["cited"] or ev in cited

    for r in tl["events"]:
        ev, t = r["evidence"], r.get("time")
        u, ho = node("user", r["user"], ev, t), node("host", r["host"], ev, t)
        pa, pr = node("parent", r["parent"], ev, t), node("process", r["process"], ev, t)
        de = node("destination", r["destination"], ev, t)
        edge(u, ho, ev, t)
        edge(ho, pa or pr, ev, t)
        edge(pa, pr, ev, t)
        edge(pr or ho, de, ev, t)
    # intel lookups that found the value: link the looked-up destination to an intel node
    for s in h.get("steps") or []:
        if s.get("kind") != "call" or not s.get("ok") or s.get("tool") not in ("lookup", "find_indicator"):
            continue
        if not _FOUND.search(s.get("result") or ""):
            continue
        val = str((s.get("arguments") or {}).get("value") or (s.get("arguments") or {}).get("indicator") or "")
        ev = f"E{s['n']}"
        i = node("intel", f"intel match: {val}", ev)
        d = ("destination", val) if ("destination", val) in nodes else node("destination", val, ev)
        edge(d, i, ev)

    keep: set[tuple[str, str]] = set()
    for col in COLUMNS:
        ranked = sorted((k for k in nodes if k[0] == col), key=lambda k: (-int(nodes[k]["cited"]), -nodes[k]["count"]))
        keep.update(ranked[:PER_COLUMN])
    out_nodes = [{**n, "evidence": sorted(n["evidence"], key=_evkey)} for k, n in nodes.items() if k in keep]
    out_edges = [{**e, "evidence": sorted(e["evidence"], key=_evkey)} for (a, b), e in edges.items()
                 if a in keep and b in keep]
    return {"columns": list(COLUMNS), "nodes": out_nodes, "edges": out_edges,
            "dropped": len(nodes) - len(keep), "events": tl["total"], "no_time": tl["no_time"]}


def _evkey(e: str) -> int:
    try:
        return int(str(e)[1:])
    except ValueError:
        return 0

