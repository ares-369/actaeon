"""The ``soc:`` section of config.yaml: alert triage limits, intake and response."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IntakeConfig:
    poll_interval_sec: int = 60
    sources: list[dict] = field(default_factory=list)   # [{connector, tool, arguments, lookback}]
    group_window_min: int = 120      # alerts that share an entity within this window join one case
    webhook_token_env: str = ""      # bearer token for POST /api/alerts from other systems
    field_map: dict[str, list[str]] = field(default_factory=dict)   # extra source keys per normal field
    no_group: list[str] = field(default_factory=list)   # entity values (globs) never used to group alerts
    severity_scale: str = "auto"     # numeric alert severity: auto | 4 | 10 | 15 | 100
    min_severity: int = 0            # alerts below this (0-100) are stored but open no case


@dataclass
class ResponseConfig:
    enabled: bool = False            # off: actions are only recommended, never run
    dry_run: bool = True             # on: approved actions are recorded but not sent
    two_person: bool = False         # an action needs two different approvers
    proposal_hours: int = 24         # a proposal not decided within this lapses (0 = never)
    allow_self_approval: bool = False   # a person may approve an action they proposed (one-person teams)
    actions: list[dict] = field(default_factory=list)


@dataclass
class SocConfig:
    auto: bool = True                # triage new cases without being asked
    first_look: bool = True          # the planner role reads the alerts first and plans the investigation
    verify: bool = True              # second look on true positives: tries to prove each one wrong
    verify_dismissals: bool = True   # also on false_positive/benign verdicts for high and critical cases
    workers: int = 2                 # cases triaged at the same time
    max_steps: int = 15              # tool calls per case
    max_runtime_sec: int = 600
    max_results: int = 100
    max_tokens: int = 0              # model tokens per case before a verdict is forced (0 = no cap)
    max_tokens_per_day: int = 0      # all automatic triage together; 0 = no cap. Manual runs ignore it.
    max_cases_per_day: int = 0       # automatic triage: cases per day; 0 = no cap
    min_severity: int = 0            # cases below this severity wait for a person
    auto_close_confidence: int = 0   # close false_positive/benign verdicts at or above this confidence; 0 = never
    playbook_dirs: list[str] = field(default_factory=list)
    intake: IntakeConfig = field(default_factory=IntakeConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)


def _int(d: dict, key: str, default: int, lo: int = 0, hi: int = 10**9) -> int:
    try:
        return max(lo, min(hi, int(d.get(key, default) or 0)))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"soc.{key} must be a number") from exc


def parse(raw: Any, connector_names: set[str]) -> SocConfig:
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ValueError("soc: must be a mapping")
    known = set(SocConfig.__dataclass_fields__)
    extra = sorted(set(raw) - known)
    if extra:
        raise ValueError(f"soc: unknown setting(s) {extra}; known: {sorted(known)}")
    dirs = [str(x) for x in raw.get("playbook_dirs") or []]
    from .playbooks import load as load_playbooks
    load_playbooks(dirs)                                   # fail fast on a bad playbook
    return SocConfig(
        auto=bool(raw.get("auto", True)), first_look=bool(raw.get("first_look", True)),
        verify=bool(raw.get("verify", True)), verify_dismissals=bool(raw.get("verify_dismissals", True)),
        workers=_int(raw, "workers", 2, 1, 16), max_steps=_int(raw, "max_steps", 15, 1, 200),
        max_runtime_sec=_int(raw, "max_runtime_sec", 600, 10), max_results=_int(raw, "max_results", 100, 1),
        max_tokens=_int(raw, "max_tokens", 0), max_tokens_per_day=_int(raw, "max_tokens_per_day", 0),
        max_cases_per_day=_int(raw, "max_cases_per_day", 0),
        min_severity=_int(raw, "min_severity", 0, 0, 100),
        auto_close_confidence=_int(raw, "auto_close_confidence", 0, 0, 100),
        playbook_dirs=dirs,
        intake=_intake(raw.get("intake") or {}, connector_names),
        response=_response(raw.get("response") or {}, connector_names),
    )


def _intake(i: dict, connector_names: set[str]) -> IntakeConfig:
    if not isinstance(i, dict):
        raise ValueError("soc.intake must be a mapping")
    sources = []
    for s in i.get("sources") or []:
        if not isinstance(s, dict) or not s.get("connector") or not s.get("tool"):
            raise ValueError("soc.intake.sources: each source needs connector and tool")
        if str(s["connector"]) not in connector_names:
            raise ValueError(f"soc.intake.sources: unknown connector {s['connector']!r}")
        if not isinstance(s.get("arguments") or {}, dict):
            raise ValueError("soc.intake.sources: arguments must be a mapping")
        sources.append({"connector": str(s["connector"]), "tool": str(s["tool"]),
                        "arguments": dict(s.get("arguments") or {}), "lookback": str(s.get("lookback", "now-15m")),
                        "name": str(s.get("name") or f"{s['connector']}/{s['tool']}")})
    fm = i.get("field_map") or {}
    if not isinstance(fm, dict):
        raise ValueError("soc.intake.field_map must map a field (host, user, ...) to a list of source keys")
    scale = str(i.get("severity_scale", "auto")).strip().lower()
    if scale not in ("auto", "4", "10", "15", "100"):
        raise ValueError("soc.intake.severity_scale must be auto, 4, 10, 15 or 100")
    return IntakeConfig(
        poll_interval_sec=max(10, int(i.get("poll_interval_sec", 60))),
        sources=sources,
        group_window_min=max(1, int(i.get("group_window_min", 120))),
        webhook_token_env=str(i.get("webhook_token_env", "") or ""),
        field_map={str(k): [str(x) for x in (v if isinstance(v, list) else [v])] for k, v in fm.items()},
        no_group=[str(x) for x in i.get("no_group") or []],
        severity_scale=scale,
        min_severity=max(0, min(100, int(i.get("min_severity", 0) or 0))),
    )


def _response(r: dict, connector_names: set[str]) -> ResponseConfig:
    if not isinstance(r, dict):
        raise ValueError("soc.response must be a mapping")
    from .response import validate_actions
    actions = list(r.get("actions") or [])
    validate_actions(actions, connector_names)
    return ResponseConfig(enabled=bool(r.get("enabled", False)), dry_run=bool(r.get("dry_run", True)),
                          two_person=bool(r.get("two_person", False)),
                          proposal_hours=max(0, min(24 * 30, int(r.get("proposal_hours", 24) or 0))),
                          allow_self_approval=bool(r.get("allow_self_approval", False)), actions=actions)
