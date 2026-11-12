"""The hunt loop.

1. Plan (planner role): ATT&CK techniques and steps per data role.
2. Investigate (analyst role): one JSON action per turn; each tool call is
   validated, run through the connector hub, stored as evidence E<n> and fed
   back as untrusted data. Repeated calls are not re-run.
3. Verdict: the model's verdict is checked against the record. Citations must
   point at successful calls; a 'threat' with no cited evidence is downgraded;
   'no_results' needs at least one successful data search, otherwise it is
   reported as 'logs_missing'.
Stops on the step limit, the time limit, or a stop request; pause is honoured
between steps.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..connectors import ROLES
from ..connectors.hub import ToolCallError
from .jsonparse import first_object
from .prompts import ANALYST_SYSTEM, PLANNER_SYSTEM, analyst_user, planner_user
from .store import OUTCOMES, HuntStore
from .validator import ValidationError, validate_call

TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
DATA_ROLES = tuple(r for r in ROLES if r != "intel")
KEEP_FULL = 4          # newest results kept in full in the prompt
TRIM_TO = 1500


@dataclass
class HuntLimits:
    max_steps: int = 25
    max_runtime_sec: int = 900
    max_results: int = 200
    max_parse_failures: int = 3


class Stopped(Exception):
    pass


def _clip(x: Any, n: int = 300) -> str:
    s = x if isinstance(x, str) else json.dumps(x, default=str)
    return s if len(s) <= n else s[:n] + "..."


class HuntEngine:
    def __init__(self, llm, hub, store: HuntStore, limits: HuntLimits | None = None, *,
                 checkpoint: Callable[[], bool] | None = None, on_event: Callable[[dict], None] | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.llm, self.hub, self.store = llm, hub, store
        self.limits = limits or HuntLimits()
        self._checkpoint = checkpoint or (lambda: True)
        self._emit = on_event or (lambda e: None)
        self._clock = clock

    # ---- helpers ----
    def _tools(self) -> list[dict]:
        seen: dict[tuple[str, str], dict] = {}
        for role in ROLES:
            for t in self.hub.tools_for_role(role):
                key = (t["connector"], t["name"])
                if key in seen:
                    seen[key]["role"] += f",{role}"
                else:
                    seen[key] = {**t, "role": role}
        return list(seen.values())

    def _roles(self, tools: list[dict]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for t in tools:
            for r in t["role"].split(","):
                out.setdefault(r, [])
                if t["connector"] not in out[r]:
                    out[r].append(t["connector"])
        return out

    def _ask(self, role: str, messages: list[dict], max_tokens: int = 1200) -> str:
        bound = self.llm.for_role(role)
        res = bound.chat(messages, max_tokens=max_tokens)
        if res.error:
            raise RuntimeError(res.error)
        return res.text or ""

    def _gate(self) -> None:
        if not self._checkpoint():
            raise Stopped("stopped")
        if self._clock() - self._t0 > self.limits.max_runtime_sec:
            raise Stopped("time limit reached")

    # ---- main ----
    def run(self, hypothesis: str, *, hunt_id: str | None = None, origin: str = "manual", actor: str = "",
            context: str = "") -> dict:
        hypothesis = hypothesis.strip()
        if not hypothesis:
            raise ValueError("a hypothesis is required")
        hid = hunt_id or self.store.create(hypothesis, origin=origin, actor=actor)
        self._t0 = self._clock()
        try:
            models = {r: {"provider": b.provider.name, "model": b.model}
                      for r in ("planner", "analyst") for b in [self.llm.for_role(r)]}
        except Exception:
            models = None
        self.store.update(hid, status="running", models=models)
        self.n = 0
        self.evidence: dict[str, dict] = {}
        self.data_ok = 0          # successful calls to non-intel roles
        self.data_attempted = 0
        try:
            tools = self._tools()
            roles = self._roles(tools)
            plan = self._plan(hid, hypothesis, roles, context)
            verdict = self._investigate(hid, hypothesis, plan, tools, context, actor)
            status = "done"
            err = None
        except Stopped as exc:
            verdict = self._finalize({"outcome": "inconclusive", "summary": f"Hunt {exc} before a verdict."}, None)
            status, err = "stopped", str(exc)
        except Exception as exc:
            verdict = self._finalize({"outcome": "inconclusive", "summary": "The hunt failed before a verdict."}, None)
            status, err = "error", f"{type(exc).__name__}: {exc}"[:1000]
        self.store.add_step(hid, self._next(), "verdict", note=json.dumps(verdict))
        self.store.update(hid, status=status, outcome=verdict["outcome"], verdict=verdict, error=err,
                          steps_used=sum(1 for e in self.evidence.values()),
                          finished=time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()))
        self._emit({"type": "verdict", "hunt_id": hid, "verdict": verdict, "status": status})
        return self.store.get(hid) or {}

    def _next(self) -> int:
        self.n += 1
        return self.n

    def _plan(self, hid: str, hypothesis: str, roles: dict, context: str) -> dict | None:
        self._gate()
        try:
            text = self._ask("planner", [{"role": "system", "content": PLANNER_SYSTEM},
                                         {"role": "user", "content": planner_user(hypothesis, roles, context)}], 900)
        except Exception as exc:
            self.store.add_step(hid, self._next(), "plan", ok=False, note=f"planner failed: {exc}")
            return None
        plan = first_object(text)
        if not plan:
            self.store.add_step(hid, self._next(), "plan", ok=False, note="planner reply was not JSON", result=text[:2000])
            return None
        plan = {"summary": _clip(plan.get("summary", ""), 400),
                "attack": [t for t in plan.get("attack") or [] if isinstance(t, str) and TECHNIQUE.match(t)][:20],
                "steps": [{"role": str(s.get("role", "")), "goal": _clip(s.get("goal", ""), 300)}
                          for s in plan.get("steps") or [] if isinstance(s, dict)][:10],
                "data_needed": [r for r in plan.get("data_needed") or [] if r in ROLES]}
        plan["missing_roles"] = sorted({s["role"] for s in plan["steps"] if s["role"] in ROLES} - set(roles)
                                       | set(plan["data_needed"]) - set(roles))
        self.store.update(hid, plan=plan)
        self.store.add_step(hid, self._next(), "plan", ok=True, note=json.dumps(plan))
        self._emit({"type": "plan", "hunt_id": hid, "plan": plan})
        return plan

    def _messages(self, base: list[dict], transcript: list[dict]) -> list[dict]:
        msgs = list(base)
        results = [i for i, m in enumerate(transcript) if m.get("_result")]
        old = set(results[:-KEEP_FULL])
        for i, m in enumerate(transcript):
            content = m["content"]
            if i in old and len(content) > TRIM_TO:
                content = content[:TRIM_TO] + "\n[older result trimmed; re-read the evidence id if needed]"
            msgs.append({"role": m["role"], "content": content})
        return msgs

    def _investigate(self, hid, hypothesis, plan, tools, context, actor) -> dict:
        index = {(t["connector"], t["name"]): t for t in tools}
        base = [{"role": "system", "content": ANALYST_SYSTEM},
                {"role": "user", "content": analyst_user(hypothesis, plan, tools, context, self.limits.max_steps)}]
        transcript: list[dict] = []
        done_calls: dict[str, str] = {}
        calls = parse_fail = 0
        while True:
            self._gate()
            last = calls >= self.limits.max_steps
            if last:
                transcript.append({"role": "user", "content": "Tool budget used up. Give the verdict now."})
            text = self._ask("analyst", self._messages(base, transcript))
            action = first_object(text)
            if not action or action.get("action") not in ("call", "verdict"):
                parse_fail += 1
                self.store.add_step(hid, self._next(), "note", ok=False, note="reply was not a valid action",
                                    result=text[:1500])
                if parse_fail >= self.limits.max_parse_failures:
                    return self._finalize({"outcome": "inconclusive",
                                           "summary": "The model did not return valid actions."}, tools)
                transcript.append({"role": "assistant", "content": text[:2000]})
                transcript.append({"role": "user", "content": "Reply with ONE JSON object: a call or a verdict."})
                continue
            parse_fail = 0
            if action["action"] == "verdict" or last:
                if action["action"] != "verdict":
                    return self._finalize({"outcome": "inconclusive",
                                           "summary": "Step limit reached without a verdict."}, tools)
                return self._finalize(action, tools)

            transcript.append({"role": "assistant", "content": json.dumps(action)[:3000]})
            connector, tool = str(action.get("connector", "")), str(action.get("tool", ""))
            if "." in tool and not connector:
                connector, tool = tool.split(".", 1)
            meta = index.get((connector, tool))
            if not meta:
                self.store.add_step(hid, self._next(), "blocked", connector=connector, tool=tool,
                                    arguments=action.get("arguments"), note="unknown or not allowed tool")
                transcript.append({"role": "user", "content": f"{connector}.{tool} is not an available tool. "
                                                              "Use one from the list."})
                continue
            try:
                args, notes = validate_call(meta, action.get("arguments"), max_results=self.limits.max_results)
            except ValidationError as exc:
                self.store.add_step(hid, self._next(), "blocked", connector=connector, tool=tool, role=meta["role"],
                                    arguments=action.get("arguments"), why=str(action.get("thought", "")),
                                    note=f"validator: {exc}")
                transcript.append({"role": "user", "content": f"Call refused by the validator: {exc}"})
                continue
            key = json.dumps([connector, tool, args], sort_keys=True, default=str)
            if key in done_calls:
                transcript.append({"role": "user", "content": f"You already made that call; see {done_calls[key]}."})
                calls += 1   # repeats still use budget so a stuck model ends
                continue
            calls += 1
            n = self._next()
            eid = f"E{n}"
            is_data = any(r in DATA_ROLES for r in meta["role"].split(","))
            self.data_attempted += is_data
            t0 = time.monotonic()
            try:
                out = self.hub.call(connector, tool, args, actor=actor, hunt_id=hid)
                ok = not out.get("is_error")
                content = out["content"]
            except ToolCallError as exc:
                ok, content = False, f"call failed: {exc}"
            ms = int((time.monotonic() - t0) * 1000)
            self.data_ok += ok and is_data
            done_calls[key] = eid
            self.evidence[eid] = {"ok": ok, "connector": connector, "tool": tool, "role": meta["role"], "args": args}
            self.store.add_step(hid, n, "call", connector=connector, tool=tool, role=meta["role"], arguments=args,
                                why=str(action.get("thought", "")), ok=ok, ms=ms, result=content,
                                note="; ".join(notes))
            self._emit({"type": "step", "hunt_id": hid, "n": n, "tool": f"{connector}.{tool}", "ok": ok})
            head = f"{eid} result of {connector}.{tool}" + (f" ({'; '.join(notes)})" if notes else "") + ":\n"
            transcript.append({"role": "user", "content": head + content, "_result": True})

    def _finalize(self, v: dict, tools: Any) -> dict:
        notes: list[str] = []
        outcome = v.get("outcome") if v.get("outcome") in OUTCOMES else "inconclusive"
        if v.get("outcome") and v.get("outcome") not in OUTCOMES:
            notes.append(f"unknown outcome {v.get('outcome')!r} replaced with inconclusive")
        good = {e for e, d in getattr(self, "evidence", {}).items() if d["ok"]}
        findings, unsupported = [], []
        for f in v.get("findings") or []:
            if not isinstance(f, dict) or not f.get("claim"):
                continue
            cited = [e for e in f.get("evidence") or [] if isinstance(e, str)]
            valid = [e for e in cited if e in good]
            item = {"claim": _clip(f["claim"], 600), "evidence": valid}
            (findings if valid else unsupported).append(item)
            if len(valid) < len(cited):
                notes.append(f"dropped citation(s) {sorted(set(cited) - set(valid))} that are not successful results")
        data_ok = getattr(self, "data_ok", 0)
        if outcome == "threat" and not findings:
            outcome = "inconclusive"
            notes.append("'threat' had no claim backed by evidence; downgraded to inconclusive")
        if outcome == "telemetry_found_benign" and not findings:
            outcome = "inconclusive" if data_ok else "logs_missing"
            notes.append("'benign' had no cited evidence")
        if outcome == "no_results" and data_ok == 0:
            outcome = "logs_missing"
            notes.append("no data search succeeded, so 'no results' cannot be claimed")
        try:
            conf = max(0, min(100, int(v.get("confidence", 0))))
        except (TypeError, ValueError):
            conf = 0
        if outcome != v.get("outcome"):
            conf = min(conf, 40)
        return {
            "outcome": outcome,
            "confidence": conf,
            "summary": _clip(v.get("summary", ""), 1500),
            "findings": findings,
            "unsupported_claims": unsupported,
            "attack": [t for t in v.get("attack") or [] if isinstance(t, str) and TECHNIQUE.match(t)][:30],
            "gaps": [_clip(g, 300) for g in v.get("gaps") or [] if isinstance(g, str)][:10],
            "next_steps": [_clip(g, 300) for g in v.get("next_steps") or [] if isinstance(g, str)][:10],
            "checks": notes,
            "evidence_ok": sorted(good, key=lambda e: int(e[1:])),
            "data_searches": {"succeeded": data_ok, "attempted": getattr(self, "data_attempted", 0)},
        }
