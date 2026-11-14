"""The connector hub: one place the hunt engine asks for tools by ROLE.

The engine never names a product. It asks ``hub.tools_for_role("log_search")``
and gets the allowed tools of every enabled connector with that role.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from .audit import AuditLog
from .client import McpClient, McpError
from .policy import decide
from .ratelimit import Pacer
from .spec import ConnectorSpec, parse_connectors
from .untrusted import wrap

RETRIES = 2            # extra attempts after the first
BACKOFF_SEC = 1.0      # 1s, then 2s


LOCAL_INTEL = "local-intel"
PROBE_TOOLS = ("list_indices", "list_collections", "intel_stats", "list_hunts")


def local_intel_connector(data_dir) -> dict:
    """The built-in connector for Actaeon's own intel store (read-only bridge)."""
    from .. import db
    # The bridge runs with a minimal environment: hand it the database settings so that with PostgreSQL
    # it reads the same intel store as the server.
    env = db.child_env()
    return {"name": LOCAL_INTEL, "roles": ["intel"], "transport": "stdio", "command": "actaeon",
            "args": ["bridge", "local-intel", "--db", str(data_dir / "intel.sqlite")], "env": env,
            "description": "Indicators and advisories added in Actaeon", "rate_per_min": 600, "timeout_sec": 15}


LOCAL_TOOLS = "local-tools"


def local_tools_connector() -> dict:
    return {"name": LOCAL_TOOLS, "roles": ["analysis"], "transport": "stdio", "command": "actaeon",
            "args": ["bridge", "local-tools"], "description": "Offline analysis helpers (decoder)",
            "rate_per_min": 600, "timeout_sec": 15}


WEB = "web"


def web_connector(cfg) -> dict | None:
    """Built-in public-web lookups when ``intel.web.tools: true``. Internal terms come from privacy.terms."""
    web = ((getattr(cfg, "intel", {}) or {}).get("web") or {})
    if not web.get("tools"):
        return None
    args = ["bridge", "web"]
    if web.get("search_url"):
        args += ["--search-url", str(web["search_url"])]
    priv = (cfg.raw or {}).get("privacy") or {}
    for t in priv.get("terms") or []:
        args += ["--block-term", str(t)]
    for p in priv.get("patterns") or []:
        args += ["--block-pattern", str(p)]
    return {"name": WEB, "roles": ["intel"], "transport": "stdio", "command": "actaeon", "args": args,
            "description": "Public web lookups (pages and optional search)", "rate_per_min": 30, "timeout_sec": 45}


class ToolCallError(RuntimeError):
    pass


def _result_text(res: dict[str, Any]) -> str:
    parts: list[str] = []
    for item in res.get("content") or []:
        if item.get("type") == "text":
            parts.append(str(item.get("text", "")))
        elif item.get("type") == "resource":
            r = item.get("resource") or {}
            parts.append(str(r.get("text", "")) or f"[resource {r.get('uri', '')}]")
        else:
            parts.append(f"[{item.get('type', 'content')} omitted]")
    if res.get("structuredContent") is not None and not parts:
        parts.append(json.dumps(res["structuredContent"]))
    return "\n".join(parts)


class ConnectorHub:
    def __init__(self, specs: list[ConnectorSpec], audit: AuditLog, *, max_result_bytes: int = 8_000,
                 pacer: Pacer | None = None, sleep=time.sleep, client_factory=McpClient,
                 max_query_sec: float = 0):
        self.specs = {s.name: s for s in specs}
        self.audit = audit
        self.max_result_bytes = max_result_bytes
        self.max_query_sec = float(max_query_sec or 0)   # all attempts of one call together; 0 = no cap
        self.pacer = pacer or Pacer()
        self._sleep = sleep
        self._factory = client_factory
        self._clients: dict[str, McpClient] = {}
        self._tools: dict[str, list[dict]] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, cfg) -> ConnectorHub:
        items = list(cfg.connectors)
        if (getattr(cfg, "intel", {}) or {}).get("local", True):
            items.append(local_intel_connector(cfg.data_dir))
        items.append(local_tools_connector())
        w = web_connector(cfg)
        if w:
            items.append(w)
        return cls(parse_connectors(items), AuditLog(cfg.data_dir / "audit.sqlite"),
                   max_result_bytes=cfg.hunt.max_result_bytes,
                   max_query_sec=getattr(cfg.hunt, "max_query_sec", 0))

    # ---- discovery ----
    def _client(self, name: str) -> McpClient:
        with self._lock:
            if name not in self._clients:
                self._clients[name] = self._factory(self.specs[name])
            return self._clients[name]

    def tools(self, name: str, refresh: bool = False) -> list[dict]:
        """All tools a connector offers, each with ``allowed`` and ``reason``."""
        spec = self.specs[name]
        if refresh or name not in self._tools:
            raw = self._client(name).list_tools()
            out = []
            for t in raw:
                ok, why = decide(spec, t)
                out.append({"name": t.get("name", ""), "description": str(t.get("description", ""))[:500],
                            "inputSchema": t.get("inputSchema") or {}, "annotations": t.get("annotations") or {},
                            "allowed": ok, "reason": why})
            self._tools[name] = out
        return self._tools[name]

    def connectors_for_role(self, role: str) -> list[ConnectorSpec]:
        """Enabled connectors with this role that the current caller may use (see actaeon/access.py)."""
        from ..access import can_use
        return [s for s in self.specs.values() if s.enabled and role in s.roles and can_use(s.name)]

    def tools_for_role(self, role: str) -> list[dict]:
        out = []
        for s in self.connectors_for_role(role):
            try:
                tools = self.tools(s.name)
            except Exception:
                continue  # an unreachable connector just offers nothing
            out.extend({**t, "connector": s.name, "dialect": s.dialect} for t in tools if t["allowed"])
        return out

    def test(self, name: str) -> dict:
        """Connect, list tools, report. Used by the UI and ``actaeon connectors test``."""
        start = time.monotonic()
        try:
            info = self._client(name).connect()
            tools = self.tools(name, refresh=True)
        except Exception as exc:
            self._drop(name)
            return {"ok": False, "error": str(exc)[:300]}
        out = {"ok": True, "server": (info.get("serverInfo") or {}), "tools": len(tools),
               "allowed": sum(t["allowed"] for t in tools)}
        # listing tools does not touch the source; if there is an argument-free read tool, try it
        probe = next((t for t in tools if t["allowed"] and t["name"] in PROBE_TOOLS
                      and not (t.get("inputSchema") or {}).get("required")), None)
        if probe:
            try:
                res = self._client(name).call_tool(probe["name"], {})
                text = _result_text(res)
                out["probe"] = probe["name"]
                if res.get("isError"):
                    out.update(ok=False, error=f"{probe['name']} failed: {text[:300]}")
            except Exception as exc:
                self._drop(name)
                out.update(ok=False, probe=probe["name"], error=f"{probe['name']} failed: {str(exc)[:300]}")
        out["ms"] = int((time.monotonic() - start) * 1000)
        return out

    # ---- calls ----
    def call(self, name: str, tool: str, arguments: dict[str, Any], *, actor: str = "", hunt_id: str = "",
             deadline: float | None = None) -> dict:
        """Call one tool. Returns the output wrapped as untrusted data.

        Time: every attempt (retries included) must finish within ``hunt.max_query_sec`` of the first,
        and before ``deadline`` (a time.monotonic() value, e.g. the end of the hunt's runtime)."""
        if name not in self.specs or not self.specs[name].enabled:
            raise ToolCallError(f"unknown or disabled connector {name!r}")
        spec = self.specs[name]
        from ..access import can_use, current
        who = current()
        if who is not None and who.user and who.user not in actor:
            actor = f"{actor} (as {who.user})" if actor else who.user   # the identity the call ran as
        if not can_use(name):
            self.audit.record(connector=name, tool=tool, arguments=arguments, decision="caller may not use this "
                              "connector (access)", status="blocked", actor=actor, hunt_id=hunt_id)
            raise ToolCallError(f"{name}: you are not allowed to use this connector")
        known = {t["name"]: t for t in self.tools(name)}
        meta = known.get(tool)
        if meta is None:
            self.audit.record(connector=name, tool=tool, arguments=arguments, decision="unknown tool",
                              status="blocked", actor=actor, hunt_id=hunt_id)
            raise ToolCallError(f"{name} has no tool {tool!r}")
        ok, why = decide(spec, meta)
        if not ok:
            self.audit.record(connector=name, tool=tool, arguments=arguments, decision=why,
                              status="blocked", actor=actor, hunt_id=hunt_id)
            raise ToolCallError(f"{name}/{tool} blocked: {why}")

        start = time.monotonic()
        ends = [t for t in (deadline, start + self.max_query_sec if self.max_query_sec else None) if t]
        end = min(ends) if ends else None
        last_err = ""
        attempts = 0
        for attempt in range(1, RETRIES + 2):
            self.pacer.acquire(name, spec.rate_per_min)
            left = None if end is None else end - time.monotonic()
            if left is not None and left < 1:
                last_err = last_err or "no time left for this query (hunt.max_query_sec or the hunt's time limit)"
                break
            attempts = attempt
            try:
                client = self._client(name)
                res = (client.call_tool(tool, arguments) if left is None
                       else client.call_tool(tool, arguments, timeout=left))
                text = _result_text(res)
                status = "tool_error" if res.get("isError") else "ok"
                out = wrap(name, tool, text, self.max_result_bytes)
                out["is_error"] = bool(res.get("isError"))
                if spec.access and hunt_id:
                    self._mark_restricted(hunt_id, name)
                self.audit.record(connector=name, tool=tool, arguments=arguments, decision=why, status=status,
                                  actor=actor, hunt_id=hunt_id, attempts=attempt,
                                  duration_ms=int((time.monotonic() - start) * 1000),
                                  result_bytes=len(text.encode()))
                return out
            except (McpError, OSError, ValueError) as exc:
                last_err = str(exc)
                self._drop(name)
                if attempt <= RETRIES:
                    self._sleep(BACKOFF_SEC * (2 ** (attempt - 1)))
        self.audit.record(connector=name, tool=tool, arguments=arguments, decision=why, status="error",
                          actor=actor, hunt_id=hunt_id, attempts=attempts,
                          duration_ms=int((time.monotonic() - start) * 1000), error=last_err)
        raise ToolCallError(f"{name}/{tool} failed after {attempts} attempt{'' if attempts == 1 else 's'}: {last_err}")

    def _mark_restricted(self, hunt_id: str, name: str) -> None:
        """A hunt that read a restricted connector is visible only to people who may use it."""
        from ..hunt.store import HuntStore
        try:
            HuntStore(self.audit.path.parent / "hunts.sqlite").add_restricted(hunt_id, name)
        except Exception:
            pass

    def _drop(self, name: str) -> None:
        with self._lock:
            c = self._clients.pop(name, None)
        if c:
            try:
                c.close()
            except Exception:
                pass

    def close(self) -> None:
        for n in list(self._clients):
            self._drop(n)


_HUB: ConnectorHub | None = None


def get_hub(cfg=None, reload: bool = False) -> ConnectorHub:
    global _HUB
    if _HUB is None or reload:
        if _HUB:
            _HUB.close()
        from ..config import get_config
        _HUB = ConnectorHub.from_config(cfg or get_config())
    return _HUB
