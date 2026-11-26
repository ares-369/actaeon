"""The ``rules:`` section of config.yaml: the detection rule library. Off unless ``enabled: true``."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@dataclass
class RulesConfig:
    enabled: bool = False
    min_real_tests: int = 1          # real events a rule must catch before it can be marked ready
    min_no_match_tests: int = 1      # events it must NOT catch (real or written by hand/model)
    allow_self_approval: bool = False   # the last editor of a rule may also mark it ready (one-person teams)
    field_map: dict[str, list[str]] = field(default_factory=dict)   # Sigma field -> your event field names
    priorities: list[str] = field(default_factory=list)   # ATT&CK techniques you want rules for
    max_tests: int = 200             # sample events per rule
    draft_samples: bool = True       # the model also writes sample events for a draft (marked "synthetic")


def parse(raw: Any) -> RulesConfig:
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ValueError("rules: must be a mapping")
    known = set(RulesConfig.__dataclass_fields__)
    extra = sorted(set(raw) - known)
    if extra:
        raise ValueError(f"rules: unknown setting(s) {extra}; known: {sorted(known)}")
    fm = raw.get("field_map") or {}
    if not isinstance(fm, dict):
        raise ValueError("rules.field_map must map a Sigma field name to a name or a list of names")
    field_map = {str(k): ([str(v)] if isinstance(v, str) else [str(x) for x in v or []]) for k, v in fm.items()}
    pri = [str(x).strip().upper() for x in raw.get("priorities") or []]
    bad = [p for p in pri if not TECHNIQUE.match(p)]
    if bad:
        raise ValueError(f"rules.priorities: not ATT&CK technique ids: {bad}")

    def num(k: str, d: int, lo: int, hi: int) -> int:
        try:
            return max(lo, min(hi, int(raw.get(k, d) if raw.get(k) is not None else d)))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"rules.{k} must be a number") from exc
    return RulesConfig(enabled=bool(raw.get("enabled", False)), min_real_tests=num("min_real_tests", 1, 0, 50),
                       min_no_match_tests=num("min_no_match_tests", 1, 0, 50),
                       allow_self_approval=bool(raw.get("allow_self_approval", False)), field_map=field_map,
                       priorities=pri, max_tests=num("max_tests", 200, 1, 5000),
                       draft_samples=bool(raw.get("draft_samples", True)))


def of(cfg) -> RulesConfig:
    """The rules settings of a config (defaults when the config was built without them)."""
    return getattr(cfg, "rules", None) or RulesConfig()
