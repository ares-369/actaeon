"""Which tools the hunt engine may call.

Order of checks for a tool on a connector:
  1. ``deny`` list match -> blocked (always wins)
  2. ``allow`` list set and no match -> blocked
  3. tool is a response action (isolate, quarantine, kill, delete, disable,
     revoke, ...) or the server marks it destructive -> ALWAYS blocked. No
     setting enables these: Actaeon hunts, it never responds.
  4. tool looks like it changes state -> blocked unless ``allow_write: true``
     AND the tool is named in ``allow`` explicitly.
"Looks like it changes state" uses the MCP ``readOnlyHint``/``destructiveHint``
annotations when the server sends them, otherwise the tool name. Hints come
from the server and are not proof, so a write-like NAME is blocked even if the
server says it is read-only.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

_WRITE_WORDS = (
    "delete", "remove", "create", "update", "write", "set", "add", "put", "post", "patch",
    "isolate", "contain", "quarantine", "block", "unblock", "kill", "stop", "start", "restart",
    "disable", "enable", "reset", "revoke", "send", "execute", "exec", "run", "install",
    "uninstall", "upload", "modify", "edit", "approve", "close", "assign", "ban", "purge",
)
# Response actions and destructive operations. Blocked whatever the config says.
_NEVER_WORDS = (
    "isolate", "unisolate", "contain", "quarantine", "kill", "terminate", "delete", "remove", "purge",
    "wipe", "erase", "destroy", "drop", "truncate", "disable", "revoke", "ban", "block", "unblock",
    "uninstall", "shutdown", "reboot", "restart", "suspend", "lock", "unlock", "reset", "rollback",
    "remediate",
)
_WORD_RE = re.compile(r"[a-z]+")


def _words(name: str) -> list[str]:
    # split camelCase, snake_case, kebab-case
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    return _WORD_RE.findall(spaced.lower())


def looks_write(tool: dict[str, Any]) -> bool:
    if any(w in _WRITE_WORDS for w in _words(str(tool.get("name", "")))):
        return True
    ann = tool.get("annotations") or {}
    if ann.get("destructiveHint") is True:
        return True
    return ann.get("readOnlyHint") is False


def is_never(tool: dict[str, Any]) -> bool:
    """A response or destructive action that no configuration may allow."""
    if any(w in _NEVER_WORDS for w in _words(str(tool.get("name", "")))):
        return True
    return (tool.get("annotations") or {}).get("destructiveHint") is True


def _match(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def decide(spec, tool: dict[str, Any]) -> tuple[bool, str]:
    """Return (allowed, reason)."""
    name = str(tool.get("name", ""))
    if _match(name, spec.deny):
        return False, "denied by the connector's deny list"
    if spec.allow and not _match(name, spec.allow):
        return False, "not on the connector's allow list"
    if is_never(tool):
        return False, "response or destructive action; Actaeon never allows these, whatever the config says"
    if looks_write(tool):
        if not spec.allow_write:
            return False, "may change state; connectors are read-only unless allow_write is set"
        if name not in spec.allow:
            return False, "may change state; write tools must be named exactly in the allow list"
    return True, "allowed"
