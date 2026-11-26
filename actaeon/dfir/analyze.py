"""Analyzers that run over a whole case, with no model:

* ``sigma``: rules from the rule library (by status), Actaeon's built-in checks and any ``dfir.rule_dirs`` folder,
  run over every event. A rule's logsource decides which events it is tried on (``process_creation`` only on
  Sysmon 1 and Security 4688, ``service: security`` only on the Security log, and so on).
* ``imported``: detections already present in the evidence (Hayabusa results carry ``RuleTitle`` and ``Level``).
* ``logons``: logons per account and source, and failed logons followed by a success from the same source.
* ``stacking``: the least frequent processes, parent-child pairs, services, tasks and logon sources.
* ``metrics``: events per host, log and event id, and per day.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from ..rules.sigma_eval import Unsupported, compile_rule

BUILTIN = Path(__file__).with_name("builtin_rules")
SYSMON = "microsoft-windows-sysmon/operational"
SERVICES = {
    "security": ["security"], "system": ["system"], "application": ["application"], "sysmon": [SYSMON],
    "powershell": ["microsoft-windows-powershell/operational"], "powershell-classic": ["windows powershell"],
    "taskscheduler": ["microsoft-windows-taskscheduler/operational"],
    "wmi": ["microsoft-windows-wmi-activity/operational"],
    "windefend": ["microsoft-windows-windows defender/operational"],
    "terminalservices-localsessionmanager": ["microsoft-windows-terminalservices-localsessionmanager/operational"],
    "bits-client": ["microsoft-windows-bits-client/operational"],
    "codeintegrity-operational": ["microsoft-windows-codeintegrity/operational"],
    "firewall-as": ["microsoft-windows-windows firewall with advanced security/firewall"],
    "dns-server": ["dns server"], "msexchange-management": ["msexchange management"],
    "ntlm": ["microsoft-windows-ntlm/operational"], "applocker": ["microsoft-windows-applocker/exe and dll",
                                                                 "microsoft-windows-applocker/msi and script"],
}
_S = {"process_creation": [(SYSMON, "1"), ("security", "4688")], "network_connection": [(SYSMON, "3")],
      "process_termination": [(SYSMON, "5")], "driver_load": [(SYSMON, "6")], "image_load": [(SYSMON, "7")],
      "create_remote_thread": [(SYSMON, "8")], "raw_access_thread": [(SYSMON, "9")], "process_access": [(SYSMON, "10")],
      "file_event": [(SYSMON, "11")], "registry_add": [(SYSMON, "12")], "registry_delete": [(SYSMON, "12")],
      "registry_set": [(SYSMON, "13")], "registry_rename": [(SYSMON, "14")],
      "registry_event": [(SYSMON, "12"), (SYSMON, "13"), (SYSMON, "14")], "create_stream_hash": [(SYSMON, "15")],
      "pipe_created": [(SYSMON, "17"), (SYSMON, "18")], "wmi_event": [(SYSMON, "19"), (SYSMON, "20"), (SYSMON, "21")],
      "dns_query": [(SYSMON, "22")], "file_delete": [(SYSMON, "23"), (SYSMON, "26")],
      "process_tampering": [(SYSMON, "25")], "file_block_executable": [(SYSMON, "27")],
      "ps_script": [("microsoft-windows-powershell/operational", "4104")],
      "ps_module": [("microsoft-windows-powershell/operational", "4103")],
      "ps_classic_start": [("windows powershell", "400")]}
LEVEL_RANK = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


class Rule:
    def __init__(self, key: str, doc: dict, origin: str):
        self.key, self.origin = key, origin
        self.title = str(doc.get("title") or key)[:300]
        lv = str(doc.get("level") or "medium").lower()
        self.level = lv if lv in LEVEL_RANK else "medium"
        self.attack = [t[7:].upper() for t in doc.get("tags") or [] if isinstance(t, str)
                       and t.lower().startswith("attack.t")]
        ls = doc.get("logsource") or {}
        self.product = str(ls.get("product") or "").lower()
        self.pairs: list[tuple[str, str]] | None = None
        self.channels: list[str] | None = None
        cat, svc = str(ls.get("category") or "").lower(), str(ls.get("service") or "").lower()
        if cat in _S:
            self.pairs = _S[cat]
        if svc in SERVICES:
            self.channels = SERVICES[svc]
        self.compiled = compile_rule(doc)

    def applies(self, ev: dict) -> bool:
        ch = str(ev["data"].get("Channel", "")).lower()
        if ch:                                    # a Windows event
            if self.product and self.product != "windows":
                return False
            if self.channels is not None and ch not in self.channels:
                return False
            return not (self.pairs is not None and (ch, str(ev["event_id"])) not in self.pairs)
        return self.product != "windows"


def load_rules(cfg, dcfg) -> tuple[list[Rule], list[str]]:
    rules, skipped = [], []

    def add(key: str, text: str, origin: str) -> None:
        try:
            docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except yaml.YAMLError:
            skipped.append(f"{key}: not valid YAML")
            return
        for d in docs[:1]:
            try:
                rules.append(Rule(key, d, origin))
            except Unsupported as exc:
                skipped.append(f"{key}: {exc}"[:200])
    if dcfg.library_rules:
        from ..rules.config import of as rules_of
        if rules_of(cfg).enabled:
            from ..rules.service import store_for, visible
            for r in store_for(cfg).all_full():
                if r["status"] in dcfg.library_rules and visible(r):
                    add(f"library:{r['id']}", r["sigma"], "library")
    if dcfg.builtin_rules:
        for f in sorted(BUILTIN.glob("*.yml")):
            add(f"builtin:{f.stem}", f.read_text(encoding="utf-8"), "builtin")
    for folder in dcfg.rule_dirs:
        p = Path(folder).expanduser()
        for f in sorted(p.rglob("*.yml")) if p.is_dir() else []:
            add(f"dir:{f.relative_to(p)}", f.read_text(encoding="utf-8", errors="replace"), "folder")
    return rules, skipped


_HAYA_LEVEL = {"crit": "critical", "critical": "critical", "high": "high", "med": "medium", "medium": "medium",
               "low": "low", "info": "informational", "informational": "informational"}


def run_sigma(store, cid: str, rules: list[Rule], *, max_hits: int) -> dict:
    hits: Counter = Counter()
    errors: Counter = Counter()
    batch: list = []
    imported = 0
    cache: dict[tuple[str, str], list[Rule]] = {}
    for ev in store.iter_events(cid):
        d = ev["data"]
        if d.get("RuleTitle") and d.get("Level"):                # detections already in the evidence
            lv = _HAYA_LEVEL.get(str(d["Level"]).lower(), "medium")
            batch.append((ev["seq"], f"imported:{str(d['RuleTitle'])[:200]}", str(d["RuleTitle"]), lv, "imported", []))
            imported += 1
        ck = (str(d.get("Channel", "")).lower(), str(ev["event_id"]))
        cand = cache.get(ck)
        if cand is None:                      # which rules apply depends only on the log and the event id
            cand = cache[ck] = [r for r in rules if r.applies(ev)]
        for r in cand:
            if hits[r.key] >= max_hits:
                continue
            try:
                ok = r.compiled.match(d)[0]
            except Exception:
                errors[r.key] += 1
                continue
            if ok:
                hits[r.key] += 1
                batch.append((ev["seq"], r.key, r.title, r.level, r.origin, r.attack))
        if len(batch) >= 2000:
            store.add_detections(cid, batch)
            batch = []
    store.add_detections(cid, batch)
    capped = [k for k, n in hits.items() if n >= max_hits]
    return {"rules": len(rules), "matched_rules": len(hits), "hits": sum(hits.values()), "imported": imported,
            "capped": capped, "errors": dict(errors)}


# ---------------------------------------------------------------- logons, stacking, metrics

def _src(d: dict) -> str:
    for k in ("IpAddress", "src_ip", "WorkstationName", "SourceNetworkAddress"):
        v = d.get(k)
        if v not in (None, "", "-", "::1", "127.0.0.1"):
            return str(v)
    return ""


def run_profile(store, cid: str, *, burst: int = 10, window_min: int = 30) -> tuple[dict, list]:
    """Logons, stacking and metrics in one pass. Returns (results, detections for brute-force successes)."""
    from datetime import datetime
    logons: dict[tuple[str, str], dict] = {}
    accounts: dict[str, dict] = {}
    fails: dict[tuple[str, str], list] = defaultdict(list)
    procs: Counter = Counter()
    pairs: Counter = Counter()
    services: Counter = Counter()
    tasks: Counter = Counter()
    sources: Counter = Counter()
    sample: dict[str, int] = {}
    hosts: Counter = Counter()
    logs: Counter = Counter()
    eids: Counter = Counter()
    days: Counter = Counter()
    dets: list = []

    def t(ts: str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None
    for ev in store.iter_events(cid):
        d, eid, ch = ev["data"], ev["event_id"], str(ev["data"].get("Channel", "")).lower()
        hosts[ev["host"] or "(none)"] += 1
        logs[ev["channel"] or "(none)"] += 1
        if eid:
            eids[f"{ev['channel']}/{eid}"] += 1
        if ev["ts"]:
            days[ev["ts"][:10]] += 1
        ok = (eid == "4624" and ch == "security") or d.get("action") == "ssh_accepted"
        bad = (eid == "4625" and ch == "security") or d.get("action") in ("ssh_failed", "ssh_invalid_user")
        if ok or bad:
            user = str(d.get("TargetUserName") or d.get("user") or "")
            dom = str(d.get("TargetDomainName") or "")
            acct = f"{dom}\\{user}" if dom and dom != "-" else user
            src = _src(d)
            key = (acct, src)
            x = logons.setdefault(key, {"account": acct, "source": src, "ok": 0, "failed": 0, "types": Counter(),
                                        "first": ev["ts"], "last": ev["ts"], "hosts": set()})
            x["ok" if ok else "failed"] += 1
            a = accounts.setdefault(acct, {"account": acct, "ok": 0, "failed": 0, "first": ev["ts"], "last": ev["ts"],
                                           "hosts": {}, "sources": {}, "types": Counter()})
            a["ok" if ok else "failed"] += 1
            if ev["ts"]:
                a["first"] = min(a["first"] or ev["ts"], ev["ts"])
                a["last"] = max(a["last"] or "", ev["ts"])
            if ev["host"]:
                a["hosts"].setdefault(ev["host"], ev["ts"])
            if src and ok:
                a["sources"].setdefault(src, ev["ts"])
            if d.get("LogonType"):
                a["types"][str(d["LogonType"])] += 1
            x["last"] = ev["ts"] or x["last"]
            x["hosts"].add(ev["host"])
            if d.get("LogonType"):
                x["types"][str(d["LogonType"])] += 1
            if bad and src:
                fails[src].append(ev["ts"])
            if ok and src and len(fails.get(src, [])) >= burst and ev["ts"]:
                now = t(ev["ts"])
                recent = [f for f in fails[src] if f and now and 0 <= (now - t(f)).total_seconds() <= window_min * 60] \
                    if now else []
                if len(recent) >= burst:
                    dets.append((ev["seq"], "analyzer:bruteforce_success", f"Logon after {len(recent)} failed attempts "
                                 f"from {src} within {window_min} min", "high", "analyzer", ["T1110"]))
                    fails[src] = []
            if src and ok:
                sources[src] += 1
                sample.setdefault("src:" + src, ev["seq"])
        is_proc = (ch == "microsoft-windows-sysmon/operational" and eid == "1") or (ch == "security" and eid == "4688")
        if is_proc:
            img = str(d.get("Image") or "").lower()
            par = str(d.get("ParentImage") or "").lower()
            if img:
                procs[img] += 1
                sample.setdefault("p:" + img, ev["seq"])
            if img and par:
                pr = f"{par.rsplit(chr(92), 1)[-1]} -> {img.rsplit(chr(92), 1)[-1]}"
                pairs[pr] += 1
                sample.setdefault("pp:" + pr, ev["seq"])
        if eid in ("7045", "4697"):
            s = f"{d.get('ServiceName', '')}: {d.get('ImagePath') or d.get('ServiceFileName') or ''}"
            services[s] += 1
            sample.setdefault("s:" + s, ev["seq"])
        if eid in ("4698", "106"):
            s = str(d.get("TaskName") or "")
            tasks[s] += 1
            sample.setdefault("t:" + s, ev["seq"])

    def rare(c: Counter, prefix: str, n: int = 25) -> list[dict]:
        return [{"value": k, "count": v, "sample": sample.get(prefix + k)} for k, v in
                sorted(c.items(), key=lambda kv: (kv[1], kv[0]))[:n]]
    lg = sorted(logons.values(), key=lambda x: (-x["failed"], -x["ok"]))[:300]
    for x in lg:
        x["types"] = dict(x["types"])
        x["hosts"] = sorted(h for h in x["hosts"] if h)[:20]
    acc = []
    for a in accounts.values():
        start = t(a["first"]) if a["first"] else None
        late = []
        for kind in ("sources", "hosts"):
            for v, first in a[kind].items():
                ft = t(first) if first else None
                if start and ft and (ft - start).total_seconds() > 86400:
                    late.append({"kind": kind[:-1], "value": v, "first": first})
        acc.append({"account": a["account"], "ok": a["ok"], "failed": a["failed"], "first": a["first"],
                    "last": a["last"], "hosts": sorted(a["hosts"])[:30], "sources": sorted(a["sources"])[:30],
                    "types": dict(a["types"]), "new_later": sorted(late, key=lambda x: x["first"])[:20]})
    acc.sort(key=lambda a: (-len(a["new_later"]), -a["failed"], -a["ok"]))
    return {
        "accounts": acc[:500],
        "logons": lg,
        "stacking": {"processes": rare(procs, "p:"), "parent_child": rare(pairs, "pp:"),
                     "services": rare(services, "s:"), "tasks": rare(tasks, "t:"),
                     "logon_sources": rare(sources, "src:")},
        "metrics": {"hosts": hosts.most_common(50), "logs": logs.most_common(50), "event_ids": eids.most_common(50),
                    "per_day": sorted(days.items())},
    }, dets


def run_all(cfg, dcfg, store, cid: str) -> dict[str, Any]:
    store.clear_detections(cid, ("library", "builtin", "folder", "imported", "analyzer"))
    rules, skipped = load_rules(cfg, dcfg)
    sig = run_sigma(store, cid, rules, max_hits=dcfg.max_rule_hits)
    sig["skipped"] = skipped[:200]
    sig["skipped_count"] = len(skipped)
    prof, dets = run_profile(store, cid)
    store.add_detections(cid, dets)
    store.refresh_levels(cid)
    store.save_analysis(cid, "sigma", sig)
    for k, v in prof.items():
        store.save_analysis(cid, k, v)
    return {"sigma": sig, "bruteforce_hits": len(dets)}


def attack_of(store, cid: str) -> list[str]:
    seen: list[str] = []
    for r in store.detection_summary(cid):
        for t in r["attack"]:
            if re.match(r"^T\d{4}(\.\d{3})?$", t) and t not in seen:
                seen.append(t)
    return seen
