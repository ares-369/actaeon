"""Create a demo home: sample connector, sample advisory and a sample memory note."""

from __future__ import annotations

import secrets
from pathlib import Path

import yaml

from ..paths import PKG_DIR, REPO_ROOT
from .data import ADMIN, ADVISORY_TEXT, ADVISORY_TITLE


def _example() -> dict:
    for p in (REPO_ROOT / "config.example.yaml", PKG_DIR / "config.example.yaml"):
        if p.is_file():
            return yaml.safe_load(p.read_text())
    raise FileNotFoundError("config.example.yaml is missing")


def init_demo(home: Path, *, offline: bool = False, port: int = 8611) -> dict:
    home = Path(home).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    cfg = _example()
    cfg["actaeon"].update(instance_name="Actaeon demo", demo=True, bind_port=port, data_dir="")
    cfg["connectors"] = [{
        "name": "demo-logs", "roles": ["log_search", "endpoint", "network", "identity", "alerts"], "transport": "stdio",
        "command": "actaeon", "args": ["bridge", "demo"], "dialect": "query_string subset (field:value, AND/OR/NOT)",
        "description": "SAMPLE DATA - synthetic events for the demo", "rate_per_min": 600,
        "query_notes": ("Index: demo-events. Time field @timestamp. Fields: process.name, process.parent.name, "
                        "process.command_line, host.name, user.name, destination.ip, destination.domain, "
                        "destination.port, source.ip, event.category (process|network|authentication), "
                        "event.action, event.outcome (success|failure). Use field:value; * is a wildcard; "
                        "combine with AND / OR / NOT and parentheses. Use top_values to stack a field."),
        "query_examples": [
            {"goal": "PowerShell started by Word", "query": "process.parent.name:winword.exe AND process.name:powershell.exe"},
            {"goal": "connections to one destination", "query": "event.category:network AND destination.ip:198.51.100.10"},
            {"goal": "failed sign-ins", "query": "event.category:authentication AND event.outcome:failure"}]}]
    # Alert triage: the demo connector also raises sample alerts, and a pretend response connector lets the
    # approval flow be tried (it only changes a dictionary in memory).
    cfg["connectors"].append({
        "name": "demo-response", "roles": ["response"], "transport": "stdio", "command": "actaeon",
        "args": ["bridge", "demo-response"], "description": "SAMPLE - pretend containment, changes nothing real",
        "rate_per_min": 600})
    rev = {"kind": "reversible"}
    cfg["soc"] = {
        "auto": True, "workers": 2,
        "intake": {"sources": [{"connector": "demo-logs", "tool": "list_alerts", "arguments": {},
                                "lookback": "now-7d"}], "no_group": ["DEMO-DC01"], "poll_interval_sec": 3600,
                   "severity_scale": "15"},
        "response": {"enabled": True, "dry_run": False, "two_person": False, "actions": [
            {"name": "isolate_host", "description": "Cut the host off the network (demo)",
             "connector": "demo-response", "tool": "isolate_host", "entity": "host",
             "arguments": {"hostname": "{target}"},
             "undo": {"tool": "release_host", "arguments": {"hostname": "{target}"}, **rev}},
            {"name": "disable_user", "description": "Disable the account (demo)",
             "connector": "demo-response", "tool": "disable_user", "entity": "user",
             "arguments": {"username": "{target}"},
             "undo": {"tool": "enable_user", "arguments": {"username": "{target}"}, "kind": "compensating"}},
            {"name": "block_ip", "description": "Block the address at the edge (demo)",
             "connector": "demo-response", "tool": "block_ip", "entity": "ip", "arguments": {"ip": "{target}"},
             "undo": {"tool": "unblock_ip", "arguments": {"ip": "{target}"}, **rev}}]}}
    cfg["environment"] = {"summary": "SAMPLE environment: Windows endpoints named DEMO-WS01..12, one admin "
                                     "host DEMO-ADM01.", "platforms": ["windows"], "not_present": ["macOS", "Linux"]}
    if offline:
        for role in ("planner", "analyst", "reporter"):
            cfg["llm"]["roles"][role] = {"provider": "demo", "model": ""}
    (home / "config.yaml").write_text("# Actaeon DEMO config: sample data only.\n" + yaml.safe_dump(cfg, sort_keys=False))
    env = home / ".env"
    if not env.exists():
        env.write_text(f"ACTAEON_SECRET_KEY={secrets.token_hex(32)}\n")
        env.chmod(0o600)
    from ..intel import IntelStore
    store = IntelStore(home / "data" / "intel.sqlite")
    if not store.advisories():
        store.add_advisory(ADVISORY_TITLE, ADVISORY_TEXT, source="demo", confidence=80, tags=["sample"])
    from ..hunt.memory import HuntMemory
    mem = HuntMemory(home / "data" / "hunts.sqlite")
    if not mem.notes():
        mem.add_note(f"SAMPLE: svc.maint on DEMO-ADM01 runs a nightly encoded PowerShell log clean-up ({ADMIN}); "
                     "known and benign.", author="demo", tags=["benign", "sample"])
    return {"home": str(home), "offline": offline, "port": port}


DEMO_HYPOTHESIS = ("An Office application started PowerShell with an encoded command on any host in the last 7 days "
                   "(sample data).")
