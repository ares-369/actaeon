"""Run a rule's sample-event tests with the local matcher, and decide whether it may be marked ready."""

from __future__ import annotations

import json
from typing import Any

from ..soc.util import iso
from .config import of
from .sigma_eval import Unsupported, compile_rule


def events_from_result(content: str, limit: int = 50) -> list[dict]:
    """Events (flat dicts) inside a stored tool result: search hits, compacted hits, or a JSON list."""
    from ..hunt.signals import payload
    try:
        data = json.loads(payload(content or "").strip())
    except ValueError:
        return []
    out: list[dict] = []

    def take(rows: Any, common: dict | None = None) -> None:
        for r in rows if isinstance(rows, list) else []:
            if isinstance(r, dict) and len(out) < limit:
                src = r.get("_source") if isinstance(r.get("_source"), dict) else r
                out.append({**(common or {}), **{k: v for k, v in src.items() if k not in ("_id", "_index")}})
    if isinstance(data, list):
        take(data)
    elif isinstance(data, dict):
        common = data.get("common") if isinstance(data.get("common"), dict) else None
        for k in ("hits", "events", "results", "items", "matches", "rows"):
            v = data.get(k)
            if isinstance(v, dict) and isinstance(v.get("hits"), list):
                v = v["hits"]
            if isinstance(v, list):
                take(v, common)
                break
    return out


def run(rule: dict, tests: list[dict], field_map: dict[str, list[str]] | None = None) -> dict:
    res: dict[str, Any] = {"rule_id": rule["id"], "version": rule["version"], "ts": iso(), "results": [],
                           "passed": 0, "failed": 0, "total": len(tests), "unsupported": None}
    try:
        compiled = compile_rule(rule["sigma"])
    except Unsupported as exc:
        res["unsupported"] = str(exc)
        res["ok"] = False
        return res
    for t in tests:
        try:
            hit, used = compiled.match(t["event"], field_map)
            err = ""
        except Exception as exc:                       # a malformed event must not stop the run
            hit, used, err = False, {}, f"{type(exc).__name__}: {exc}"[:200]
        ok = (hit == (t["expect"] == "match")) and not err
        res["results"].append({"test_id": t["id"], "name": t["name"], "expect": t["expect"], "origin": t["origin"],
                               "matched": hit, "ok": ok, "fields": used, "error": err})
        res["passed" if ok else "failed"] += 1
    res["ok"] = res["failed"] == 0 and res["total"] > 0
    return res


def ready_problems(cfg, rule: dict, tests: list[dict], last: dict | None, lint: list[dict], actor: str) -> list[str]:
    """What still stops this rule from being marked ready (empty list: it may be)."""
    rc = of(cfg)
    out = []
    if rule["status"] != "testing":
        out.append("only a rule in testing can be marked ready (submit it for testing first)")
    out += [f"lint: {x['text']}" for x in lint if x["level"] == "error"]
    real = sum(1 for t in tests if t["expect"] == "match" and t["origin"] == "real")
    neg = sum(1 for t in tests if t["expect"] == "no_match")
    if real < rc.min_real_tests:
        out.append(f"needs {rc.min_real_tests} real event(s) the rule must catch (has {real}); events written by a "
                   "model do not count")
    if neg < rc.min_no_match_tests:
        out.append(f"needs {rc.min_no_match_tests} event(s) the rule must not catch (has {neg})")
    if not last:
        out.append("the tests have not been run")
    elif last.get("version") != rule["version"]:
        out.append("the last test run was for an older version; run the tests again")
    elif last.get("unsupported"):
        out.append(f"the local matcher cannot evaluate this rule: {last['unsupported']}")
    elif last.get("total") != len(tests):
        out.append("tests were added or removed since the last run; run them again")
    elif not last.get("ok"):
        out.append(f"{last.get('failed', 0)} test(s) fail")
    if not rc.allow_self_approval and actor and actor == rule.get("updated_by"):
        out.append("the last editor cannot also approve (rules.allow_self_approval)")
    return out
