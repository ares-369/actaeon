"""Small shared helpers."""

from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

_BLOCK = re.compile(r"<<UNTRUSTED-DATA [^>]*>>\n?(.*?)\n?<<END-UNTRUSTED-DATA [^>]*>>", re.S)


def payload(content: str) -> str:
    """The text inside an UNTRUSTED-DATA block (or the text itself)."""
    m = _BLOCK.search(content or "")
    return m.group(1) if m else (content or "")


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(d: datetime | None = None) -> str:
    return (d or now()).isoformat(timespec="seconds")


def parse_iso(s: str) -> datetime:
    d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def ago(**kw) -> str:
    return iso(now() - timedelta(**kw))


def new_id() -> str:
    return secrets.token_hex(6)


def dumps(x: Any) -> str:
    return json.dumps(x, default=str, sort_keys=True)


def loads(s: str | None, default: Any = None) -> Any:
    if not s:
        return default
    try:
        return json.loads(s)
    except ValueError:
        return default


def clip(x: Any, n: int = 300) -> str:
    s = x if isinstance(x, str) else json.dumps(x, default=str)
    return s if len(s) <= n else s[:n] + "..."
