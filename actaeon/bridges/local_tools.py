"""Local analysis tools served over MCP (role ``analysis``). No network, nothing executed."""

from __future__ import annotations

import argparse

from ..decode import decode
from .server import McpServer, ToolInputError


def build() -> McpServer:
    srv = McpServer("actaeon-local-tools", instructions="Offline helpers for analysing what a hunt finds.")

    def decode_command(a):
        text = str(a.get("text", ""))
        if not text.strip():
            raise ToolInputError("text is required")
        return decode(text)

    srv.tool("decode_command", "Decode an obfuscated command line or script (base64/-EncodedCommand, gzip, hex, "
             "char codes, URL encoding, concatenation, escapes). Does not run anything.",
             {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]})(decode_command)
    return srv


def add_args(p: argparse.ArgumentParser) -> None:
    pass


def run(a: argparse.Namespace) -> None:
    build().serve()
