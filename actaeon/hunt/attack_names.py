"""ATT&CK Enterprise lookups from the bundled dataset (hunt/attack_data.json).

Built by scripts/build_attack_data.py from MITRE's STIX bundle. ATT&CK is a
trademark of The MITRE Corporation and is used under MITRE's terms of use.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@lru_cache(maxsize=1)
def _data() -> dict:
    p = Path(__file__).with_name("attack_data.json")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": "", "techniques": {}, "retired": {}}


def version() -> str:
    return str(_data().get("version", ""))


def info(tid: str) -> dict:
    """{'n': name, 't': tactics, 'd': data components, 'p': platforms} or {}."""
    return _data()["techniques"].get(tid, {})


def current(tid: str) -> str:
    """The current ID for a technique (follows a revoked ID to its replacement)."""
    r = _data()["retired"].get(tid)
    return (r or {}).get("by") or tid if isinstance(r, dict) else tid


def name(tid: str) -> str:
    t = info(tid) or info(current(tid))
    if t:
        return t["n"]
    parent = info(tid.split(".")[0])
    return parent.get("n", "")


def tactics(tid: str) -> list[str]:
    return list(info(tid).get("t") or info(tid.split(".")[0]).get("t") or [])


def data_components(tid: str) -> list[str]:
    return list(info(tid).get("d") or [])


def check(ids) -> tuple[list[str], list[str]]:
    """Split IDs into (valid current techniques, notes about the rest)."""
    good, notes = [], []
    for t in ids or []:
        if not isinstance(t, str):
            continue
        t = t.strip().upper()
        if not TECHNIQUE.match(t):
            notes.append(f"{t!r} is not an ATT&CK technique ID")
        elif t in _data()["techniques"]:
            if t not in good:
                good.append(t)
        elif t in _data()["retired"]:
            new = (_data()["retired"][t] or {}).get("by", "") if isinstance(_data()["retired"][t], dict) else ""
            if new and new in _data()["techniques"]:
                notes.append(f"{t} was replaced by {new} ({name(new)}) in ATT&CK {version()}")
                if new not in good:
                    good.append(new)
            else:
                notes.append(f"{t} is deprecated in ATT&CK {version()}")
        else:
            notes.append(f"{t} does not exist in ATT&CK {version()}")
    return good, notes
