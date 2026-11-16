"""Demo response connector: pretend containment tools over in-memory state. SAMPLE only.

Lets the approval flow be tried end to end. Nothing here touches a real system: isolating a host
or disabling a user only changes a dictionary in this process.
"""

from __future__ import annotations

import argparse

from ..demo.data import LABEL
from .server import McpServer, Tool, ToolInputError

WRITE = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}


class DemoResponse:
    def __init__(self):
        self.isolated: set[str] = set()
        self.disabled: set[str] = set()
        self.blocked: set[str] = set()

    def _flip(self, bucket: set, key: str, value, on: bool, what: str) -> dict:
        v = str(value or "").strip()
        if not v:
            raise ToolInputError(f"{key} is required")
        (bucket.add if on else bucket.discard)(v)
        return {"ok": True, "demo": LABEL, "done": f"{what} {v} (demo only, nothing real changed)"}

    def build(self) -> McpServer:
        srv = McpServer("actaeon-demo-response", instructions=f"DEMO response tools ({LABEL}). Nothing real changes.")
        host = {"type": "object", "properties": {"hostname": {"type": "string"}}, "required": ["hostname"]}
        user = {"type": "object", "properties": {"username": {"type": "string"}}, "required": ["username"]}
        ip = {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}
        for name, schema, bucket, key, on, what in (
                ("isolate_host", host, self.isolated, "hostname", True, "isolated"),
                ("release_host", host, self.isolated, "hostname", False, "released"),
                ("disable_user", user, self.disabled, "username", True, "disabled"),
                ("enable_user", user, self.disabled, "username", False, "enabled"),
                ("block_ip", ip, self.blocked, "ip", True, "blocked"),
                ("unblock_ip", ip, self.blocked, "ip", False, "unblocked")):
            srv.add(Tool(name, f"DEMO: {name.replace('_', ' ')} (changes nothing real).", schema,
                         lambda a, b=bucket, k=key, o=on, w=what: self._flip(b, k, a.get(k), o, w), WRITE))
        srv.tool("response_state", "DEMO: what is isolated, disabled or blocked now.",
                 {"type": "object", "properties": {}})(
            lambda a: {"isolated": sorted(self.isolated), "disabled": sorted(self.disabled),
                       "blocked": sorted(self.blocked), "demo": LABEL})
        return srv


def add_args(p: argparse.ArgumentParser) -> None:
    pass


def run(a: argparse.Namespace) -> None:
    DemoResponse().build().serve()
