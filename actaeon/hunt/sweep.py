"""Intel sweeps: search the logs for indicators from the intel store, without a model.

Only indicators added or changed since the last sweep are searched (the IOC
ledger), so a scheduled sweep does not repeat old work. Values are searched in
batches; when a batch matches, each value in it is searched on its own so the
match can be attributed. Each sweep is recorded as a hunt (origin ``sweep``).

Targets come from ``intel.sweep.targets``. Each target names a connector and a
tool, plus an argument template where ``{values}`` becomes the batch query::

    intel:
      sweep:
        interval_minutes: 360
        lookback: now-7d
        min_confidence: 50
        targets:
          - connector: logs
            tool: search
            arguments: {index: "events-*", query: "{values}", time_from: "{lookback}", size: 20}

With no targets, every connector that runs the built-in search-index bridge is
used, with its allowed index patterns and a quoted free-text match.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..connectors.hub import ToolCallError
from ..intel.store import IntelStore
from .signals import hits
from .store import HuntStore
from .validator import ValidationError, validate_call

SEARCHABLE = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def auto_targets(specs: dict) -> list[dict]:
    out = []
    for s in specs.values():
        if s.enabled and s.command == "actaeon" and s.args[:2] == ["bridge", "search-index"]:
            idx = [s.args[i + 1] for i, a in enumerate(s.args[:-1]) if a == "--index"] or ["*"]
            out.append({"connector": s.name, "tool": "search",
                        "arguments": {"index": ",".join(idx), "query": "{values}", "time_from": "{lookback}",
                                      "size": 20}})
        elif s.enabled and s.command == "actaeon" and s.args[:2] == ["bridge", "demo"]:
            out.append({"connector": s.name, "tool": "search",
                        "arguments": {"index": "demo-events", "query": "{values}", "time_from": "{lookback}",
                                      "size": 20}})
    return out


def _fill(template: Any, values_q: str, lookback: str) -> Any:
    if isinstance(template, str):
        return template.replace("{values}", values_q).replace("{lookback}", lookback)
    if isinstance(template, dict):
        return {k: _fill(v, values_q, lookback) for k, v in template.items()}
    if isinstance(template, list):
        return [_fill(v, values_q, lookback) for v in template]
    return template


def _quote(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Sweep:
    def __init__(self, hub, intel: IntelStore, store: HuntStore, settings: dict | None = None, *,
                 max_results: int = 200, llm=None):
        self.hub, self.intel, self.store = hub, intel, store
        self.llm = llm
        s = settings or {}
        self.lookback = str(s.get("lookback", "now-7d"))
        self.min_conf = int(s.get("min_confidence", 50))
        self.batch = max(1, min(int(s.get("batch", 20)), 100))
        self.max_values = int(s.get("max_values", 2000))
        self.max_attrib = int(s.get("max_attribution_calls", 50))
        self.triage = str(s.get("triage", "rules"))           # rules | model | off
        self.targets = list(s.get("targets") or []) or auto_targets(getattr(hub, "specs", {}))
        self.max_results = max_results
        with self.intel._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS sweep_state (k TEXT PRIMARY KEY, v TEXT)")

    def _last(self) -> str | None:
        with self.intel._conn() as c:
            r = c.execute("SELECT v FROM sweep_state WHERE k='last_sweep'").fetchone()
        return r[0] if r else None

    def _set_last(self, ts: str) -> None:
        with self.intel._conn() as c:
            c.execute("INSERT INTO sweep_state (k, v) VALUES ('last_sweep', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                      (ts,))

    def run(self, *, full: bool = False, actor: str = "scheduler", tag: str | None = None,
            origin: str = "sweep") -> dict:
        """Sweep new/changed indicators (or, with ``tag``, every indicator carrying that tag)."""
        since = None if (full or tag) else self._last()
        inds = [i for i in self.intel.list(min_confidence=0 if tag else self.min_conf, changed_after=since,
                                           tag=tag, limit=self.max_values)
                if i["type"] in SEARCHABLE]
        newest = max((i["updated"] for i in inds), default=since) if not tag else None
        # a single-value batch never goes through attribution, so keep its content too

        what = f"tagged {tag}" if tag else ("(all)" if since is None else "changed since " + since)
        hid = self.store.create(f"Intel sweep: {len(inds)} indicator(s) {what}", origin=origin, actor=actor)
        self.store.update(hid, status="running")
        tools = {(t["connector"], t["name"]): t for t in self._all_tools()}
        n = 0
        matched: dict[str, list[str]] = {}
        ok_calls = failed = attrib = 0
        gaps = []
        if not self.targets:
            gaps.append("no sweep targets: add intel.sweep.targets or a search-index bridge connector")
        if not inds:
            gaps.append("no new or changed indicators to sweep")

        contents: dict[str, list[str]] = {}

        def search(target: dict, values: list[str]) -> tuple[int | None, int]:
            nonlocal n, ok_calls, failed
            n += 1
            meta = tools.get((target["connector"], target["tool"]))
            q = " OR ".join(_quote(v) for v in values)
            args = _fill(target.get("arguments") or {}, q, self.lookback)
            if not meta:
                self.store.add_step(hid, n, "blocked", connector=target["connector"], tool=target["tool"],
                                    arguments=args, note="sweep target tool is not available or allowed")
                failed += 1
                return None, n
            try:
                args, _ = validate_call(meta, args, max_results=self.max_results)
            except ValidationError as exc:
                self.store.add_step(hid, n, "blocked", connector=target["connector"], tool=target["tool"],
                                    arguments=args, note=f"validator: {exc}")
                failed += 1
                return None, n
            try:
                out = self.hub.call(target["connector"], target["tool"], args, actor=actor, hunt_id=hid)
                ok, content = not out.get("is_error"), out["content"]
            except ToolCallError as exc:
                ok, content = False, f"call failed: {exc}"
            h = hits(content) if ok else None
            ok_calls += ok
            failed += not ok
            self.store.add_step(hid, n, "call", connector=target["connector"], tool=target["tool"],
                                role=meta.get("role", ""), arguments=args, why=f"sweep of {len(values)} value(s)",
                                ok=ok, result=content, note=f"hits={h}")
            if ok and h and len(values) == 1:
                contents.setdefault(values[0], []).append(content)
            return h, n

        values = [i["value"] for i in inds]
        for target in self.targets:
            for b in range(0, len(values), self.batch):
                chunk = values[b:b + self.batch]
                h, _ = search(target, chunk)
                if not h:
                    continue
                if len(chunk) == 1:
                    matched.setdefault(chunk[0], []).append(f"E{n}")
                    continue
                for v in chunk:
                    if attrib >= self.max_attrib:
                        gaps.append("attribution limit reached; some batch matches were not split per value")
                        break
                    attrib += 1
                    hv, nn = search(target, [v])
                    if hv:
                        matched.setdefault(v, []).append(f"E{nn}")
        by_value = {i["value"]: i for i in inds}
        from .triage import classify, events_from, model_classify
        states: dict[str, dict] = {}
        for v in matched:
            evs = [e for c in contents.get(v, []) for e in events_from(c)]
            st = classify(evs) if self.triage != "off" else {"state": "unknown", "counts": {}}
            if st["state"] == "unknown" and self.triage == "model" and self.llm is not None and evs:
                m = model_classify(self.llm, v, evs)
                if m:
                    st = {**st, **m, "by": "model"}
            states[v] = {"by": "rules", **st} if self.triage != "off" else st
        label = {"executed": "was USED (executed)", "blocked": "was seen but BLOCKED",
                 "passive": "was only MENTIONED (passive)", "unknown": "matched; state UNKNOWN"}
        findings = [{"claim": f"{by_value[v]['type']} {v} (confidence {by_value[v]['confidence']}, "
                              f"source {by_value[v]['source']}) {label[states[v]['state']]}"
                              + (f": {states[v]['reason']}" if states[v].get("reason") else ""),
                     "evidence": ev, "state": states[v]["state"]}
                    for v, ev in matched.items()]
        n_exec = sum(st["state"] == "executed" for st in states.values())
        n_unknown = sum(st["state"] == "unknown" for st in states.values())
        if findings and n_exec:
            outcome = "threat"
            summary = (f"{n_exec} indicator(s) from intel were used in this environment (executed); "
                       f"{len(findings) - n_exec} other match(es) were blocked, passive or unclear. Confirm before acting.")
        elif findings and n_unknown:
            outcome = "inconclusive"
            summary = f"{len(findings)} indicator match(es); {n_unknown} could not be classified. Review them."
        elif findings:
            outcome = "telemetry_found_benign"
            summary = (f"{len(findings)} indicator match(es), all blocked or passive (mentions, drops, quarantines). "
                       "No sign they were used.")
        elif ok_calls:
            outcome, summary = "no_results", f"No match for {len(values)} indicator(s)."
        else:
            outcome = "logs_missing" if values and self.targets else "inconclusive"
            summary = "Nothing was searched." if not values else "No sweep search succeeded."
        verdict = {"outcome": outcome, "confidence": max([by_value[v]["confidence"] for v in matched] or [50]),
                   "summary": summary, "findings": findings, "unsupported_claims": [], "attack": [], "gaps": gaps,
                   "next_steps": ["Open each match and check whether it is malicious"] if findings else [],
                   "checks": ["automatic indicator sweep; each match triaged as executed / blocked / passive / "
                              "unknown" + (" by rules then model" if self.triage == "model" else " by rules")
                              + "; a match is not proof of compromise"],
                   "needs_review": bool(findings) and outcome != "telemetry_found_benign",
                   "sweep": {"indicators": len(values), "matched": len(matched), "failed_calls": failed,
                             "triage": {v: st["state"] for v, st in states.items()}}}
        self.store.add_step(hid, n + 1, "verdict", note=json.dumps(verdict))
        self.store.update(hid, status="done", outcome=outcome, verdict=verdict, steps_used=n, finished=_now())
        if newest and (not inds or (ok_calls and not failed)):
            self._set_last(newest)
        return self.store.get(hid) or {}

    def _all_tools(self) -> list[dict]:
        out = []
        for role in ("log_search", "endpoint", "network", "identity", "email", "cloud", "asset"):
            out += [{**t, "role": role} for t in self.hub.tools_for_role(role)]
        return out
