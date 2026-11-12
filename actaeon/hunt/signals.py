"""Read a hit count out of a tool result without a model.

Looks at the JSON inside the untrusted-data block for the usual keys
(total, count, returned, found, matches, hits, results). Returns None when it
cannot tell; callers then fall back to comparing content fingerprints.
"""

from __future__ import annotations

import hashlib
import json
import re

_BLOCK = re.compile(r"<<UNTRUSTED-DATA [^>]*>>\n?(.*?)\n?<<END-UNTRUSTED-DATA [^>]*>>", re.S)


def payload(content: str) -> str:
    m = _BLOCK.search(content or "")
    return m.group(1) if m else (content or "")


def hits(content: str) -> int | None:
    text = payload(content).strip()
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return _count(data)


def _count(d) -> int | None:
    if isinstance(d, list):
        return len(d)
    if not isinstance(d, dict):
        return None
    for k in ("total", "count", "hits_total", "total_hits"):
        v = d.get(k)
        if isinstance(v, dict) and isinstance(v.get("value"), int):
            return v["value"]
        if isinstance(v, int) and not isinstance(v, bool):
            return v
    if isinstance(d.get("found"), bool):
        return int(d["found"])
    for k in ("matches", "hits", "results", "events", "items", "buckets", "objects", "indicators"):
        v = d.get(k)
        if isinstance(v, list):
            return len(v)
        if isinstance(v, dict):
            n = _count(v)
            if n is not None:
                return n
    return None


def fingerprint(content: str) -> str:
    return hashlib.sha256(payload(content).encode()).hexdigest()[:16]
