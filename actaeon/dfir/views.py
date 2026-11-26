"""Views built from the stored events with no model: the process tree around an event."""

from __future__ import annotations

from typing import Any

SYSMON = "microsoft-windows-sysmon/operational"


def _pid(v: Any) -> int | None:
    s = str(v or "").strip().lower()
    if not s or s in ("-", "?"):
        return None
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except ValueError:
        return None


def _node(e: dict) -> dict:
    d = e["data"]
    sysmon = str(d.get("Channel", "")).lower() == SYSMON
    if sysmon:
        pid, ppid = _pid(d.get("ProcessId")), _pid(d.get("ParentProcessId"))
        guid, pguid = str(d.get("ProcessGuid") or ""), str(d.get("ParentProcessGuid") or "")
        image, parent = d.get("Image", ""), d.get("ParentImage", "")
        user = d.get("User", "")
    else:                                             # Security 4688: NewProcessId, and ProcessId is the creator
        pid, ppid = _pid(d.get("NewProcessId")), _pid(d.get("ProcessId"))
        guid = pguid = ""
        image, parent = d.get("NewProcessName", "") or d.get("Image", ""), d.get("ParentProcessName", "")
        user = d.get("SubjectUserName", "")
    return {"seq": e["seq"], "ts": e["ts"], "pid": pid, "ppid": ppid, "guid": guid, "pguid": pguid,
            "image": str(image), "parent_image": str(parent), "command": str(d.get("CommandLine", ""))[:2000],
            "user": str(user), "level": e.get("level") or 0}


def _is_proc(e: dict) -> bool:
    ch = str(e["data"].get("Channel", "")).lower()
    return (ch == SYSMON and e["event_id"] == "1") or (ch == "security" and e["event_id"] == "4688")


class Tree:
    def __init__(self, events: list[dict]):
        self.nodes = [_node(e) for e in events if _is_proc(e)]
        self.nodes.sort(key=lambda n: (n["ts"] or "", n["seq"]))
        self.by_guid = {n["guid"]: n for n in self.nodes if n["guid"]}
        self.by_pid: dict[int, list[dict]] = {}
        for n in self.nodes:
            if n["pid"] is not None:
                self.by_pid.setdefault(n["pid"], []).append(n)
        self.kids: dict[int, list[dict]] = {}
        for n in self.nodes:
            p = self.parent(n)
            if p:
                self.kids.setdefault(p["seq"], []).append(n)

    def parent(self, n: dict) -> dict | None:
        if n["pguid"] and n["pguid"] in self.by_guid:
            return self.by_guid[n["pguid"]]
        if n["ppid"] is None:
            return None
        best = None
        for c in self.by_pid.get(n["ppid"], []):            # the latest start of that pid before the child
            if (c["ts"] or "") <= (n["ts"] or "") and c["seq"] != n["seq"]:
                best = c
        return best

    def find(self, e: dict) -> dict | None:
        """The process node for any event: the event itself, or the process named by its GUID or pid."""
        for n in self.nodes:
            if n["seq"] == e["seq"]:
                return n
        d = e["data"]
        for k in ("ProcessGuid", "SourceProcessGuid"):
            if d.get(k) and str(d[k]) in self.by_guid:
                return self.by_guid[str(d[k])]
        pid = _pid(d.get("ProcessId") or d.get("SourceProcessId"))
        if pid is not None:
            cands = [c for c in self.by_pid.get(pid, []) if (c["ts"] or "") <= (e["ts"] or "")]
            if cands:
                return cands[-1]
        return None

    def around(self, n: dict, *, max_nodes: int = 300, max_depth: int = 8) -> dict:
        ancestors, cur, seen = [], self.parent(n), {n["seq"]}
        while cur and len(ancestors) < 15 and cur["seq"] not in seen:
            seen.add(cur["seq"])
            ancestors.append(cur)
            cur = self.parent(cur)
        count = [0]

        def down(x: dict, depth: int) -> dict:
            count[0] += 1
            kids = [] if depth >= max_depth else self.kids.get(x["seq"], [])
            out = {**x, "children": []}
            for k in kids:
                if count[0] >= max_nodes or k["seq"] in seen:
                    out["truncated"] = True
                    break
                seen.add(k["seq"])
                out["children"].append(down(k, depth + 1))
            return out
        return {"ancestors": list(reversed(ancestors)), "focus": down(n, 0), "nodes": count[0]}


def process_tree(store, cid: str, seq: int) -> dict:
    e = store.event(cid, seq)
    if not e:
        raise KeyError(seq)
    events = store.host_events(cid, e["host"], ("1", "4688"))
    t = Tree(events)
    n = t.find(e)
    if not n:
        return {"host": e["host"], "found": False,
                "note": "no process-creation event (Sysmon 1 or Security 4688) for this process on this host"}
    return {"host": e["host"], "found": True, **t.around(n)}
