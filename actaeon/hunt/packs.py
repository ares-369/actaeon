"""Hunt packs: threat-hunting hypotheses as one YAML file per hunt.

The built-in pack is ``actaeon/hunts/<tactic>/<id>.yaml``. Organisations can add
their own folders with ``hunt.library_dirs``. A hunt file::

    id: encoded-powershell-from-office        # lowercase, digits, '-'; same as the file name
    name: Encoded PowerShell from Office
    hypothesis: "An Office application started PowerShell with an encoded command in the last 7 days."
    attack: [T1059.001, T1204.002]            # current ATT&CK Enterprise technique IDs
    roles: [endpoint, log_search]             # connector roles the hunt needs
    author: Your name                         # optional from here on
    platforms: [windows]                      # windows | linux | macos | cloud | network | identity | saas
    references: ["https://..."]               # https links only
    notes: "What normal looks like, common false positives"

Hunts carry no queries and no product names: the model writes the queries for
your data, through your connectors. ``actaeon library validate`` checks files.
"""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path

import yaml

from ..connectors.spec import ROLES
from .attack_names import check as attack_check

REQUIRED = ("id", "name", "hypothesis", "attack", "roles")
OPTIONAL = ("author", "platforms", "references", "notes")
PLATFORMS = ("windows", "linux", "macos", "cloud", "network", "identity", "saas", "containers")
_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,79}")


class PackError(ValueError):
    pass


def validate(doc, *, filename: str = "") -> dict:
    """Return the hunt as a dict, or raise PackError with every problem found."""
    where = filename or "hunt"
    if not isinstance(doc, dict):
        raise PackError(f"{where}: must be a mapping")
    errs = []
    unknown = sorted(set(doc) - set(REQUIRED) - set(OPTIONAL))
    if unknown:
        errs.append(f"unknown keys {unknown}")
    for k in REQUIRED:
        if not doc.get(k):
            errs.append(f"{k} is required")
    hid = str(doc.get("id", ""))
    if hid and not _ID.fullmatch(hid):
        errs.append("id must be 3-80 lowercase letters, digits or '-'")
    if filename and hid and Path(filename).stem != hid:
        errs.append(f"id {hid!r} must match the file name")
    for k in ("name", "hypothesis", "author", "notes"):
        if k in doc and not isinstance(doc[k], str):
            errs.append(f"{k} must be text")
    if isinstance(doc.get("hypothesis"), str) and not 20 <= len(doc["hypothesis"]) <= 1000:
        errs.append("hypothesis must be 20-1000 characters")
    for k in ("attack", "roles", "platforms", "references"):
        if k in doc and not isinstance(doc[k], list):
            errs.append(f"{k} must be a list")
    if isinstance(doc.get("attack"), list) and doc["attack"]:
        _good, notes = attack_check([str(t) for t in doc["attack"]])
        errs += [f"attack: {n}" for n in notes]
    if isinstance(doc.get("roles"), list):
        bad = [r for r in doc["roles"] if r not in ROLES]
        if bad:
            errs.append(f"unknown roles {bad}; use {list(ROLES)}")
    if isinstance(doc.get("platforms"), list):
        bad = [p for p in doc["platforms"] if p not in PLATFORMS]
        if bad:
            errs.append(f"unknown platforms {bad}; use {list(PLATFORMS)}")
    if isinstance(doc.get("references"), list):
        bad = [r for r in doc["references"] if not str(r).startswith("https://")]
        if bad:
            errs.append("references must be https:// links")
    if errs:
        raise PackError(f"{where}: " + "; ".join(errs))
    return dict(doc)


def load_dir(path, *, strict: bool = True) -> list[dict]:
    """Every *.yaml / *.yml under ``path``. strict: raise on the first bad file; else skip bad files."""
    out, ids = [], set()
    for p in sorted(Path(path).rglob("*.y*ml")):
        try:
            h = validate(yaml.safe_load(p.read_text(encoding="utf-8")), filename=p.name)
            if h["id"] in ids:
                raise PackError(f"{p.name}: duplicate id {h['id']!r}")
        except (PackError, yaml.YAMLError) as exc:
            if strict:
                raise PackError(str(exc)) from None
            continue
        ids.add(h["id"])
        out.append({**h, "pack": str(p.parent.name)})
    return out


def builtin_dir() -> Path:
    return Path(str(resources.files("actaeon").joinpath("hunts")))


def load_all(cfg=None) -> list[dict]:
    """The built-in pack, then any ``hunt.library_dirs`` (later ids replace earlier ones)."""
    hunts = {h["id"]: h for h in load_dir(builtin_dir())}
    dirs = (((getattr(cfg, "raw", None) or {}).get("hunt") or {}).get("library_dirs") or []) if cfg else []
    for d in dirs if isinstance(dirs, list) else [dirs]:
        if Path(str(d)).is_dir():
            hunts.update({h["id"]: h for h in load_dir(d, strict=False)})
    return list(hunts.values())
