"""Connector definitions from config.yaml ``connectors:``.

Example::

    connectors:
      - name: logs
        roles: [log_search]
        transport: http            # http | stdio
        url: https://mcp.example.internal/mcp
        auth: {type: bearer, token_env: LOGS_MCP_TOKEN}
        dialect: "lucene"          # free text hint for the planner
        tools: {allow: [], deny: []}
        allow_write: false
        rate_per_min: 60
        timeout_sec: 30
      - name: intel
        roles: [intel]
        transport: stdio
        command: python
        args: ["-m", "some_mcp_server"]
        env: {API_KEY: "${INTEL_API_KEY}"}

Secrets are never written in config.yaml: use ``*_env`` keys or ``${VAR}``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

ROLES = ("log_search", "endpoint", "identity", "email", "asset", "network", "cloud", "intel", "analysis")
DATA_ROLES = ("log_search", "endpoint", "identity", "email", "asset", "network", "cloud")
AUTH_TYPES = ("none", "api_key", "bearer", "oauth_client_credentials")
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
_VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand_env(value: str) -> str:
    """Replace ``${VAR}`` with the environment value (empty if unset)."""
    return _VAR_RE.sub(lambda m: os.getenv(m.group(1), ""), str(value))


@dataclass
class ConnectorSpec:
    name: str
    roles: list[str]
    transport: str
    url: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    auth: dict[str, Any] = field(default_factory=dict)
    dialect: str = ""
    description: str = ""
    query_notes: str = ""                     # how to write queries for this source (from config or a file)
    query_examples: list[dict] = field(default_factory=list)   # [{goal, query}]
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    allow_write: bool = False
    rate_per_min: int = 60
    timeout_sec: float = 30.0
    enabled: bool = True
    verify_tls: bool = True

    def public(self) -> dict[str, Any]:
        """Safe view for the UI/API (no secrets, no env values)."""
        return {
            "name": self.name, "roles": self.roles, "transport": self.transport,
            "url": self.url, "command": self.command, "dialect": self.dialect,
            "description": self.description, "auth_type": self.auth.get("type", "none"),
            "allow": self.allow, "deny": self.deny, "allow_write": self.allow_write,
            "rate_per_min": self.rate_per_min, "enabled": self.enabled,
            "query_notes": bool(self.query_notes), "query_examples": len(self.query_examples),
        }


def _notes(name: str, raw: dict[str, Any]) -> str:
    text = str(raw.get("query_notes", "") or "")
    path = raw.get("query_notes_file")
    if path:
        from pathlib import Path
        p = Path(str(path)).expanduser()
        if not p.is_file():
            raise ValueError(f"connector {name}: query_notes_file {p} does not exist")
        text = (text + "\n" + p.read_text(errors="replace")).strip()
    return text[:6000]


def _spec(raw: dict[str, Any]) -> ConnectorSpec:
    name = str(raw.get("name", "")).strip()
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"connector name {name!r} must be lowercase letters, digits, _ or - (max 40)")
    roles = [str(r) for r in (raw.get("roles") or [])]
    if not roles:
        raise ValueError(f"connector {name}: at least one role is required ({', '.join(ROLES)})")
    bad = [r for r in roles if r not in ROLES]
    if bad:
        raise ValueError(f"connector {name}: unknown role(s) {bad}; expected {ROLES}")
    transport = str(raw.get("transport", "")).strip()
    if transport not in ("stdio", "http"):
        raise ValueError(f"connector {name}: transport must be 'stdio' or 'http'")
    if transport == "http" and not str(raw.get("url", "")).startswith(("http://", "https://")):
        raise ValueError(f"connector {name}: http transport needs an http(s) url")
    if transport == "stdio" and not raw.get("command"):
        raise ValueError(f"connector {name}: stdio transport needs a command")
    auth = dict(raw.get("auth") or {})
    auth.setdefault("type", "none")
    if auth["type"] not in AUTH_TYPES:
        raise ValueError(f"connector {name}: auth.type must be one of {AUTH_TYPES}")
    for k in ("token", "api_key", "client_secret"):
        if auth.get(k) and not _VAR_RE.fullmatch(str(auth[k])):
            raise ValueError(f"connector {name}: put auth.{k} in .env and reference it as {k}_env or ${{VAR}}")
    tools = raw.get("tools") or {}
    return ConnectorSpec(
        name=name, roles=roles, transport=transport,
        url=str(raw.get("url", "")), command=str(raw.get("command", "")),
        args=[str(a) for a in raw.get("args") or []],
        env={str(k): str(v) for k, v in (raw.get("env") or {}).items()},
        headers={str(k): str(v) for k, v in (raw.get("headers") or {}).items()},
        auth=auth, dialect=str(raw.get("dialect", "")), description=str(raw.get("description", "")),
        query_notes=_notes(name, raw),
        query_examples=[{"goal": str(e.get("goal", ""))[:200], "query": str(e.get("query", ""))[:1000]}
                        for e in (raw.get("query_examples") or []) if isinstance(e, dict) and e.get("query")][:20],
        allow=[str(t) for t in tools.get("allow") or []],
        deny=[str(t) for t in tools.get("deny") or []],
        allow_write=bool(raw.get("allow_write", False)),
        rate_per_min=max(1, int(raw.get("rate_per_min", 60))),
        timeout_sec=float(raw.get("timeout_sec", 30)),
        enabled=bool(raw.get("enabled", True)),
        verify_tls=bool(raw.get("verify_tls", True)),
    )


def parse_connectors(items: list[dict[str, Any]]) -> list[ConnectorSpec]:
    specs = [_spec(i) for i in items or []]
    names = [s.name for s in specs]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ValueError(f"duplicate connector names: {sorted(dupes)}")
    return specs
