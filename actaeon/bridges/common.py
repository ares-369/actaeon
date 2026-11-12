"""Shared helpers for bridges: HTTP session with auth from env, time ranges, caps."""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone

import requests

from .server import ToolInputError

_REL = re.compile(r"^now-(\d{1,5})([mhdw])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def session_from_env(prefix: str = "BRIDGE", verify_tls: bool = True, ca_bundle: str = "") -> requests.Session:
    """Auth comes only from environment variables (set by the connector's env:).

    ``<P>_TOKEN`` -> Bearer; ``<P>_API_KEY`` + optional ``<P>_API_KEY_HEADER``
    (default ``Authorization``); ``<P>_USERNAME``/``<P>_PASSWORD`` -> Basic.
    """
    s = requests.Session()
    s.verify = ca_bundle or verify_tls
    tok = os.getenv(f"{prefix}_TOKEN", "")
    key = os.getenv(f"{prefix}_API_KEY", "")
    user, pw = os.getenv(f"{prefix}_USERNAME", ""), os.getenv(f"{prefix}_PASSWORD", "")
    if tok:
        s.headers["Authorization"] = f"Bearer {tok}"
    elif key:
        s.headers[os.getenv(f"{prefix}_API_KEY_HEADER", "Authorization")] = os.getenv(f"{prefix}_API_KEY_PREFIX", "") + key
    elif user:
        s.auth = (user, pw)
    s.headers["User-Agent"] = "actaeon-bridge"
    return s


def parse_time(value: str, *, default: str) -> datetime:
    """Accept ISO-8601 or relative ``now-24h`` / ``now-7d`` / ``now``."""
    v = (value or default).strip()
    now = datetime.now(timezone.utc)
    if v == "now":
        return now
    m = _REL.match(v)
    if m:
        return now - timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ToolInputError(f"time {v!r} must be ISO-8601 or like now-24h") from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def time_window(args: dict, max_days: int) -> tuple[datetime, datetime]:
    start = parse_time(str(args.get("time_from", "")), default="now-24h")
    end = parse_time(str(args.get("time_to", "")), default="now")
    if end <= start:
        raise ToolInputError("time_to must be after time_from")
    if end - start > timedelta(days=max_days):
        raise ToolInputError(f"time window is longer than the {max_days}-day limit; narrow it")
    return start, end


def cap(value, default: int, maximum: int) -> int:
    try:
        n = int(value if value is not None else default)
    except (TypeError, ValueError) as exc:
        raise ToolInputError("size must be an integer") from exc
    return max(1, min(n, maximum))


def check_status(r: requests.Response) -> None:
    if r.status_code in (401, 403):
        raise PermissionError(f"HTTP {r.status_code}: the source refused the bridge's credentials")
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
