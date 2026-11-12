"""Import intel from files or URL feeds.

Formats:
  text  one indicator per line (``#`` comments ignored); or free text if ``extract: true``
  csv   picks the column named by ``value_field`` (default: first column)
  stix  a STIX 2.x bundle; indicators' patterns are parsed for values
  json  a JSON document; ``list_key`` (dot path) selects the list, ``value_field`` the value

Example config::

    intel:
      feeds:
        - name: kev
          url: "https://example.org/known_exploited.json"
          format: json
          list_key: vulnerabilities
          value_field: cveID
          type: cve
          confidence: 90
          tags: [exploited]
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from pathlib import Path
from typing import Any

import requests

from .extract import extract, guess_type
from .store import IntelStore

FORMATS = ("text", "csv", "stix", "json")
_STIX_VAL = re.compile(r"(?:value|hashes\.'?[A-Za-z0-9-]+'?)\s*=\s*'([^']+)'")


def _dig(obj: Any, path: str) -> Any:
    for part in [p for p in (path or "").split(".") if p]:
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def parse(content: str, fmt: str, *, value_field: str = "", list_key: str = "",
          extract_text: bool = False) -> list[str]:
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {FORMATS}")
    if fmt == "text":
        if extract_text:
            return [v for vals in extract(content).values() for v in vals]
        return [ln.strip().split()[0] for ln in content.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if fmt == "csv":
        rows = list(csv.reader(io.StringIO(content)))
        if not rows:
            return []
        head = [h.strip() for h in rows[0]]
        if value_field and value_field in head:
            i = head.index(value_field)
            body = rows[1:]
        else:
            i = 0
            body = rows[1:] if guess_type(rows[0][0] if rows[0] else "") is None else rows
        return [r[i].strip() for r in body if len(r) > i and r[i].strip()]
    data = json.loads(content)
    if fmt == "stix":
        out = []
        for o in data.get("objects") or []:
            if o.get("type") == "indicator":
                out += _STIX_VAL.findall(str(o.get("pattern", "")))
        return out
    items = _dig(data, list_key) if list_key else data
    if not isinstance(items, list):
        raise ValueError("list_key does not point at a JSON list")
    vals = []
    for it in items:
        v = _dig(it, value_field) if value_field and isinstance(it, dict) else it
        if isinstance(v, (str, int)):
            vals.append(str(v))
    return vals


def import_values(store: IntelStore, values: list[str], *, kind: str | None = None, source: str,
                  confidence: int = 50, tags: list[str] | None = None, ttl_days: int | None = None) -> dict:
    new = updated = skipped = 0
    for v in values:
        try:
            r = store.add(v, kind, source=source, confidence=confidence, tags=tags, ttl_days=ttl_days)
        except ValueError:
            skipped += 1
            continue
        new += r["status"] == "new"
        updated += r["status"] == "updated"
    return {"source": source, "read": len(values), "new": new, "updated": updated, "skipped": skipped}


def import_file(store: IntelStore, path: str, fmt: str = "text", **kw) -> dict:
    text = Path(path).expanduser().read_text(errors="replace")
    vals = parse(text, fmt, value_field=kw.pop("value_field", ""), list_key=kw.pop("list_key", ""),
                 extract_text=kw.pop("extract", False))
    kw.setdefault("source", f"file:{Path(path).name}")
    return import_values(store, vals, **kw)


def validate_feed(f: dict) -> dict:
    name = str(f.get("name", ""))
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", name):
        raise ValueError(f"intel feed name {name!r} must be lowercase letters, digits, _ or -")
    if not str(f.get("url", "")).startswith(("https://", "http://")):
        raise ValueError(f"intel feed {name}: url must be http(s)")
    if f.get("format", "text") not in FORMATS:
        raise ValueError(f"intel feed {name}: format must be one of {FORMATS}")
    return f


def pull_feed(store: IntelStore, f: dict, session=None) -> dict:
    f = validate_feed(f)
    headers = {"User-Agent": "actaeon"}
    if f.get("token_env"):
        headers["Authorization"] = f"Bearer {os.getenv(str(f['token_env']), '')}"
    r = (session or requests).get(f["url"], headers=headers, timeout=60, verify=bool(f.get("verify_tls", True)))
    r.raise_for_status()
    vals = parse(r.text, f.get("format", "text"), value_field=str(f.get("value_field", "")),
                 list_key=str(f.get("list_key", "")), extract_text=bool(f.get("extract", False)))
    max_items = int(f.get("max_items", 50_000))
    return import_values(store, vals[:max_items], kind=f.get("type"), source=f"feed:{f['name']}",
                         confidence=int(f.get("confidence", 50)), tags=list(f.get("tags") or []),
                         ttl_days=f.get("ttl_days"))
