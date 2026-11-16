"""Playbooks: investigation guidance per kind of alert.

A playbook is a YAML file::

    title: Brute force and password spraying
    match:
      keywords: ["failed sign", "spray"]       # any of these in the alert title, rule or description
      attack: ["T1110*"]                        # or any matching ATT&CK technique on the alerts
      rules: ["R-100*"]                         # or a matching rule id
    steps:
      - Count failures from the source and how many accounts it tried.
      - Check for a successful sign-in after the failures.

The built-in playbooks ship in actaeon/soc/playbooks/. Add your own folders with ``soc.playbook_dirs``;
a file with the same name replaces the built-in one. Matching playbooks are given to the investigator
as guidance; the model still decides what to run.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import yaml

BUILTIN = Path(__file__).resolve().parent / "playbooks"


def load(dirs: list[str] | None = None) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for d in [BUILTIN, *[Path(x).expanduser() for x in dirs or []]]:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.yaml")):
            data = yaml.safe_load(f.read_text()) or {}
            validate(f.stem, data)
            out[f.stem] = {"name": f.stem, **data}
    return out


def validate(name: str, data: dict) -> None:
    if not isinstance(data, dict) or not data.get("title") or not isinstance(data.get("steps"), list):
        raise ValueError(f"playbook {name}: needs a title and a list of steps")
    m = data.get("match") or {}
    if not any(m.get(k) for k in ("keywords", "attack", "rules")):
        raise ValueError(f"playbook {name}: match needs keywords, attack or rules")


def matching(alerts: list[dict], books: dict[str, dict], limit: int = 2) -> list[dict]:
    text = " ".join(f"{a.get('title', '')} {a.get('rule_name', '')} {a.get('description', '')} "
                    f"{a.get('command_line', '')}" for a in alerts).lower()
    techs = {t for a in alerts for t in a.get("attack") or []}
    rules = {a.get("rule_id") or "" for a in alerts}
    scored = []
    for b in books.values():
        m = b.get("match") or {}
        score = sum(2 for k in m.get("keywords") or [] if re.search(r"(?<!\w)" + re.escape(str(k).lower()), text))
        score += sum(3 for p in m.get("attack") or [] for t in techs if fnmatch.fnmatchcase(t, str(p)))
        score += sum(5 for p in m.get("rules") or [] for r in rules if r and fnmatch.fnmatchcase(r, str(p)))
        if score:
            scored.append((score, b))
    scored.sort(key=lambda x: -x[0])
    return [b for _, b in scored[:limit]]


def prompt_text(books: list[dict]) -> str:
    if not books:
        return ""
    parts = ["Playbook guidance for this kind of alert (follow where it fits; skip steps your tools cannot do):"]
    for b in books:
        parts.append(f"[{b['title']}]")
        parts += [f"  {i}. {s}" for i, s in enumerate(b["steps"][:10], 1)]
    return "\n".join(parts)
