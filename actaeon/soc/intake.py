"""Alert intake: normalise, suppress, de-duplicate and group into cases. No model is used here.

Alerts arrive three ways:
  * POST /api/alerts (another system pushes them; optional bearer token)
  * polling: ``soc.intake.sources`` names a connector tool that returns alerts
  * ``actaeon alerts import FILE`` (a JSON list or JSON lines)

Grouping: an alert joins an open case when it has the same fingerprint (same
rule on the same host/user/IP), or shares a host, user, external IP, domain
or hash with a case that has not been triaged yet, within
``soc.intake.group_window_min``. Otherwise it opens a new case. Shared infrastructure
that every alert touches (a sign-in server, a proxy) can be left out of grouping
with ``soc.intake.no_group``.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from datetime import timedelta
from typing import Any

from .alerts import hits_from_result, normalize
from .store import SocStore
from .util import iso, now, parse_iso

log = logging.getLogger("actaeon.intake")
MAX_BATCH = 1000
MAX_POLL_BYTES = 8_000_000
HIGH = 65        # severity from which a suppressed alert counts as a warning on its suppression


def suppression_for(store: SocStore, alert: dict, rules: list[dict] | None = None) -> dict | None:
    """The first active suppression that matches the alert's rule (and entity, if the suppression names one)."""
    for s in rules if rules is not None else store.suppressions():
        rule = s["rule"]
        if not (fnmatch.fnmatchcase(alert.get("rule_id") or "", rule)
                or fnmatch.fnmatchcase((alert.get("rule_name") or "").lower(), rule.lower())):
            continue
        if s.get("entity_type") and not any(
                e["type"] == s["entity_type"] and fnmatch.fnmatchcase(e["value"].lower(), (s["entity_value"] or "").lower())
                for e in alert.get("entities") or []):
            continue
        return s
    return None


def ingest(cfg, store: SocStore, raw_alerts: list[dict], *, source: str = "webhook") -> dict:
    """Store a batch of raw alerts. Returns counts and the cases that were opened or grew."""
    if not isinstance(raw_alerts, list):
        raise ValueError("send a JSON object or a list of objects")
    if len(raw_alerts) > MAX_BATCH:
        raise ValueError(f"at most {MAX_BATCH} alerts per request")
    window = timedelta(minutes=cfg.soc.intake.group_window_min)
    rules = store.suppressions()
    out: dict[str, Any] = {"received": len(raw_alerts), "new": 0, "duplicates": 0, "suppressed": 0,
                           "below_threshold": 0, "invalid": 0, "cases_opened": [], "cases_updated": []}
    def _time(raw):          # oldest first, so a case grows forward in time whatever order the source returns
        for k in ("@timestamp", "timestamp", "ts", "time", "created"):
            if isinstance(raw, dict) and isinstance(raw.get(k), str):
                return raw[k]
        return ""
    for raw in sorted(raw_alerts, key=_time):
        try:
            a = normalize(raw, source=source, field_map=cfg.soc.intake.field_map, severity_scale=cfg.soc.intake.severity_scale)
        except (ValueError, TypeError):
            out["invalid"] += 1
            continue
        sup = suppression_for(store, a, rules)
        if sup:
            _id, is_new = store.add_alert(a, status="suppressed")
            if is_new:
                store.hit_suppression(sup["id"], high=a["severity"] >= HIGH)
            out["suppressed"] += 1
            continue
        if a["severity"] < cfg.soc.intake.min_severity:
            _id, is_new = store.add_alert(a, status="below_threshold")
            out["below_threshold"] += int(is_new)
            continue
        _id, is_new = store.add_alert(a)
        if not is_new:
            out["duplicates"] += 1
            continue
        out["new"] += 1
        when = parse_iso(a["ts"]) if a["ts"] else now()
        since, until = iso(when - window), iso(when + window)
        group_on = [e for e in a["entities"]
                    if not any(fnmatch.fnmatchcase(e["value"].lower(), p.lower()) for p in cfg.soc.intake.no_group)]
        cid = store.open_case_for(fingerprint=a["fingerprint"], entities=group_on, since=since, until=until)
        if cid:
            store.attach(cid, a)
            if cid not in out["cases_opened"] and cid not in out["cases_updated"]:
                out["cases_updated"].append(cid)
            case = store.get_case(cid, full=False) or {}
            if case.get("status") in ("triaged", "needs_analyst"):
                store.add_note(cid, "actaeon", f"New alert after triage: {a['title'][:200]} ({a['id'][:80]})")
        else:
            cid = store.new_case(a["title"], a["severity"], a["severity_label"], a["ts"])
            store.attach(cid, a)
            out["cases_opened"].append(cid)
    return out


def poll_source(cfg, store: SocStore, hub, src: dict) -> dict:
    """Run one ``soc.intake.sources`` entry: call the tool from the last bookmark and ingest what it returns."""
    key = f"intake:{src['name']}"
    last = store.bookmark(key)
    args = dict(src.get("arguments") or {})
    time_key = next((k for k in ("time_from", "since", "from", "start") if k in args or k == "time_from"), "time_from")
    args[time_key] = last or src.get("lookback") or "now-15m"
    started = iso()
    # No model reads this result, so it is not cut to the size used for prompts.
    res = hub.call(src["connector"], src["tool"], args, actor="intake", max_bytes=MAX_POLL_BYTES)
    if res.get("is_error"):
        raise RuntimeError(f"{src['name']}: the tool returned an error")
    if res.get("truncated"):
        raise RuntimeError(f"{src['name']}: the result is larger than {MAX_POLL_BYTES // 1_000_000} MB; "
                           "ask for fewer alerts per poll (a smaller size, or a narrower query)")
    items = hits_from_result(res["content"])
    if items is None:
        raise RuntimeError(f"{src['name']}: the result is not JSON with a list of alerts")
    out = ingest(cfg, store, items[:MAX_BATCH], source=src["name"])
    asked = next((args[k] for k in ("size", "limit", "max_results") if isinstance(args.get(k), int)), None)
    if asked and len(items) >= asked:
        out["page_full"] = True     # there may be more alerts in this window than one poll returns
    store.bookmark(key, started)
    return out


def load_file(text: str) -> list[dict]:
    """A JSON list, one JSON object, or JSON lines."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except ValueError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
