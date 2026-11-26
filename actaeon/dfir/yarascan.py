"""YARA scanning of evidence files at import (``dfir.yara_dirs``; needs ``pip install 'actaeon[yara]'``).

Every file, and every member of a zip, is scanned with the rules in those folders (``*.yar``, ``*.yara``). A match
becomes an event in the case (log ``yara``) with a detection; its level comes from the rule's ``severity``,
``level`` or ``score`` metadata (high when it has none). A rule file that does not compile is skipped and
reported, so one bad file does not stop the others.
"""

from __future__ import annotations

import threading
import zipfile
from pathlib import Path
from typing import Any

_cache: dict[tuple, Any] = {}
_lock = threading.Lock()
LEVELS = ("informational", "low", "medium", "high", "critical")


def _files(dirs: list[str]) -> list[Path]:
    out = []
    for d in dirs:
        p = Path(d).expanduser()
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out += sorted(x for x in p.rglob("*") if x.suffix.lower() in (".yar", ".yara"))
    return out


def rules_for(dirs: list[str]) -> tuple[Any, list[str]]:
    """(compiled rules or None, problems). Compiled once per set of files and their change times."""
    try:
        import yara  # type: ignore[import-not-found]
    except ImportError:
        return None, ["YARA scanning needs: pip install 'actaeon[yara]' (yara-python)"]
    files = _files(dirs)
    key = tuple((str(f), f.stat().st_mtime) for f in files)
    with _lock:
        if key in _cache:
            return _cache[key]
        good, problems = {}, []
        for f in files:
            ns = f.stem[:60]
            try:
                yara.compile(filepath=str(f))
                good[f"{ns}_{len(good)}" if ns in good else ns] = str(f)
            except yara.Error as exc:
                problems.append(f"{f.name}: {exc}"[:300])
        compiled = yara.compile(filepaths=good) if good else None
        _cache.clear()
        _cache[key] = (compiled, problems)
        return compiled, problems


def _level(meta: dict) -> str:
    for k in ("severity", "level"):
        v = str(meta.get(k, "")).lower()
        if v in LEVELS:
            return v
        if v in ("crit",):
            return "critical"
    try:
        score = int(meta.get("score"))
        return "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low"
    except (TypeError, ValueError):
        return "high"


def _rows(matches, name: str, member: str = "") -> list[dict]:
    out = []
    for m in matches:
        strings = []
        for s in getattr(m, "strings", [])[:5]:
            inst = getattr(s, "instances", None)
            off = inst[0].offset if inst else None
            strings.append({"id": getattr(s, "identifier", str(s)), "offset": off})
        meta = dict(getattr(m, "meta", {}) or {})
        out.append({"rule": m.rule, "namespace": m.namespace, "tags": list(m.tags), "meta": {k: str(v)[:300] for k, v in meta.items()},
                    "file": name, "member": member, "strings": strings, "level": _level(meta)})
    return out


def scan(dirs: list[str], path: Path, name: str, *, max_mb: int = 512) -> tuple[list[dict], list[str]]:
    rules, problems = rules_for(dirs)
    if rules is None:
        return [], problems
    limit = max_mb << 20
    out: list[dict] = []
    p = Path(path)
    is_zip = zipfile.is_zipfile(p)
    if not is_zip:                    # a zip is scanned member by member (its own bytes would repeat the matches)
        if p.stat().st_size <= limit:
            out += _rows(rules.match(str(p), timeout=120), name)
        else:
            problems.append(f"{name}: larger than dfir.yara_max_mb, not scanned")
    if is_zip:
        with zipfile.ZipFile(p) as z:
            for info in z.infolist()[:5000]:
                if info.is_dir() or info.file_size > limit:
                    continue
                with z.open(info) as fh:
                    out += _rows(rules.match(data=fh.read(), timeout=120), name, info.filename)
    return out, problems
