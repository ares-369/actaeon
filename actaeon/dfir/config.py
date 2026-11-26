"""The ``dfir:`` section of config.yaml: offline investigations. Off unless ``enabled: true``."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

RULE_STATUSES = ("draft", "testing", "ready")


@dataclass
class DfirConfig:
    enabled: bool = False
    max_events_per_case: int = 2_000_000
    max_upload_mb: int = 1024
    library_rules: list[str] = field(default_factory=lambda: ["ready", "testing"])   # rule library statuses run
    rule_dirs: list[str] = field(default_factory=list)   # extra folders of Sigma rules (e.g. a SigmaHQ checkout)
    builtin_rules: bool = True       # Actaeon's small set of high-value Windows checks
    max_rule_hits: int = 5_000       # per rule and case: a noisy rule stops tagging after this many events
    story_events: int = 250          # events given to the model for the story (detections and starred first)
    evtx_dump: str = ""              # optional path to the evtx_dump tool (much faster than python-evtx)
    yara_dirs: list[str] = field(default_factory=list)   # YARA rule folders: evidence files are scanned at import
    yara_max_mb: int = 512           # files (and zip members) larger than this are not scanned


def parse(raw: Any) -> DfirConfig:
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ValueError("dfir: must be a mapping")
    known = set(DfirConfig.__dataclass_fields__)
    extra = sorted(set(raw) - known)
    if extra:
        raise ValueError(f"dfir: unknown setting(s) {extra}; known: {sorted(known)}")
    lib = [str(x) for x in raw.get("library_rules", ["ready", "testing"]) or []]
    bad = [x for x in lib if x not in RULE_STATUSES]
    if bad:
        raise ValueError(f"dfir.library_rules: {bad} are not rule statuses {RULE_STATUSES}")

    def num(k: str, d: int, lo: int, hi: int) -> int:
        try:
            return max(lo, min(hi, int(raw[k]) if raw.get(k) is not None else d))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"dfir.{k} must be a number") from exc
    return DfirConfig(enabled=bool(raw.get("enabled", False)),
                      max_events_per_case=num("max_events_per_case", 2_000_000, 1000, 100_000_000),
                      max_upload_mb=num("max_upload_mb", 1024, 1, 100_000), library_rules=lib,
                      rule_dirs=[str(x) for x in raw.get("rule_dirs") or []],
                      builtin_rules=bool(raw.get("builtin_rules", True)),
                      max_rule_hits=num("max_rule_hits", 5000, 10, 1_000_000),
                      story_events=num("story_events", 250, 20, 5000),
                      evtx_dump=str(raw.get("evtx_dump") or ""),
                      yara_dirs=[str(x) for x in raw.get("yara_dirs") or []],
                      yara_max_mb=num("yara_max_mb", 512, 1, 100_000))


def of(cfg) -> DfirConfig:
    return getattr(cfg, "dfir", None) or DfirConfig()
