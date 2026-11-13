"""A short read-only tool loop shared by chat and verification.

The model replies with one JSON object per turn: a call
({"action": "call", "connector", "tool", "arguments"}) or a final object whose
action is ``final_action``. Every call goes through the tool policy, the
validator, the field guard and the hub, and is stored on the hunt as new
evidence E<n>. Returns the final object (or None) and the evidence ids made.
"""

from __future__ import annotations

import json

from ..connectors import ROLES
from ..connectors.hub import ToolCallError
from .engine import _fields_from, query_fields, resolve_tool
from .jsonparse import action_object
from .validator import ValidationError, validate_call


def available_tools(hub) -> list[dict]:
    tools, seen = [], set()
    for role in ROLES:
        for t in hub.tools_for_role(role):
            key = (t["connector"], t["name"])
            if key not in seen:
                seen.add(key)
                tools.append({**t, "role": role})
    return tools


def run_loop(*, llm, hub, store, hid: str, system: str, user: str, final_action: str, max_calls: int,
             max_results: int, actor: str, why_prefix: str) -> tuple[dict | None, list[str], int]:
    tools = available_tools(hub)
    index = {(t["connector"], t["name"]): t for t in tools}
    h = store.get(hid) or {}
    n = max([s["n"] for s in h.get("steps") or []] + [0])
    transcript: list[dict] = []
    made: list[str] = []
    calls = 0
    for _ in range(max_calls + 3):
        last = calls >= max_calls
        if last:
            transcript.append({"role": "user", "content": f"No more calls. Reply with the {final_action} now."})
        res = llm.for_role("analyst").chat([{"role": "system", "content": system}, {"role": "user", "content": user}, *transcript], max_tokens=1500)
        if res.error:
            return {"action": final_action, "error": res.error[:300]}, made, calls
        act = action_object(res.text) or {}
        if act.get("action") == final_action or last or act.get("action") != "call":
            if act.get("action") != final_action:
                act = {"action": final_action, "text": res.text[:4000], "unstructured": True}
            return act, made, calls
        transcript.append({"role": "assistant", "content": json.dumps(act)[:3000]})
        calls += 1
        conn, tool = resolve_tool(index, act)
        meta = index.get((conn, tool))
        if not meta:
            transcript.append({"role": "user", "content": f"{conn}.{tool} is not an available tool."})
            continue
        try:
            args, _ = validate_call(meta, act.get("arguments"), max_results=max_results)
        except ValidationError as exc:
            transcript.append({"role": "user", "content": f"Refused by the validator: {exc}"})
            continue
        if isinstance(args.get("query"), str) and (conn, "get_fields") in index:
            try:
                fo = hub.call(conn, "get_fields", {"index": args["index"]} if args.get("index") else {},
                              actor=actor, hunt_id=hid)
                fields = _fields_from(fo["content"])
                bad = [f for f in query_fields(args["query"]) if fields and f not in fields]
                if bad:
                    transcript.append({"role": "user", "content": f"Refused: unknown field(s) {bad}. "
                                       f"Known fields include: {', '.join(sorted(fields)[:60])}"})
                    continue
            except ToolCallError:
                pass
        n += 1
        try:
            out = hub.call(conn, tool, args, actor=actor, hunt_id=hid)
            ok, content = not out.get("is_error"), out["content"]
        except ToolCallError as exc:
            ok, content = False, f"call failed: {exc}"
        store.add_step(hid, n, "call", connector=conn, tool=tool, role=meta["role"], arguments=args,
                       why=f"{why_prefix}: {str(act.get('thought', ''))[:200]}", ok=ok, result=content,
                       note=f"from {why_prefix}")
        if ok:
            made.append(f"E{n}")
        transcript.append({"role": "user", "content": f"E{n} result of {conn}.{tool}:\n{content[:12000]}"})
    return None, made, calls
