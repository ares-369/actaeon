"""Mask personal data before prompts go to a cloud model, and restore it in replies.

Each hunt gets its own mapping: the same real value always becomes the same
placeholder (EMAIL_1, IP_2, USER_3, TERM_1, ...), so the model can still reason
and pivot on it. The model's replies are unmasked before Actaeon acts on them,
so tool calls use the real values; the data never leaves in clear text in a
prompt to a masked provider.

Pattern-based, so it can miss values (for example a username in free text with
no ``user`` label). Add your own terms and patterns for anything that must
never leave.

Config::

    privacy:
      mask_for: [anthropic, gemini, openai, azure_openai, openai_compatible]   # default; [] = off
      types: [email, ipv4, ipv6, user]      # default
      terms: ["example-corp", "corp.example"]   # always masked
      patterns: ['\\bWS-\\d{4,}\\b']         # extra regexes (e.g. hostnames)
      keep_public_ips: false
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

CLOUD = ("anthropic", "gemini", "openai", "azure_openai", "openai_compatible", "cli")
DEFAULT_TYPES = ("email", "ipv4", "ipv6", "user")

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_IPV6 = re.compile(r"(?<![:\w.])(?=[0-9a-fA-F:]*:[0-9a-fA-F]*:)[0-9a-fA-F:]{2,39}(?![:\w])")
# "user": "alice", user=alice, UserName: alice, account_name 'bob'
_USER = re.compile(r"""(?ix)(\b(?:user(?:_?name)?|account(?:_?name)?|subject_?user(?:_?name)?|target_?user(?:_?name)?|
                     src_?user|dst_?user|logon_?user|owner|upn|sam_?account_?name)\b["']?\s*[:=]\s*["']?)
                     ([^\s"',;}{\]\[]{2,128})""")
_PLACEHOLDER = re.compile(r"\b(?:EMAIL|IP|USER|TERM|CUSTOM)_\d+\b")
_NOT_USERS = {"null", "none", "true", "false", "n/a", "-", "system", "local", "unknown"}


@dataclass
class Masker:
    types: tuple = DEFAULT_TYPES
    terms: list[str] = field(default_factory=list)
    patterns: list[str] = field(default_factory=list)
    keep_public_ips: bool = False
    forward: dict[str, str] = field(default_factory=dict)
    back: dict[str, str] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)

    def __post_init__(self):
        self._custom = [re.compile(p) for p in self.patterns]
        self._terms = [re.compile(re.escape(t), re.I) for t in sorted(self.terms, key=len, reverse=True) if t]

    def _ph(self, kind: str, value: str) -> str:
        key = value.lower() if kind in ("EMAIL", "TERM", "USER") else value
        if key not in self.forward:
            self.counts[kind] = self.counts.get(kind, 0) + 1
            ph = f"{kind}_{self.counts[kind]}"
            self.forward[key] = ph
            self.back[ph] = value
        return self.forward[key]

    def _ip_ok(self, v: str) -> bool:
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return False
        if ip.is_unspecified or ip.is_loopback:
            return False
        return not (self.keep_public_ips and ip.is_global)

    def mask(self, text: str) -> str:
        if not text:
            return text
        t = text
        for rx in self._terms:
            t = rx.sub(lambda m: self._ph("TERM", m.group(0)), t)
        for rx in self._custom:
            t = rx.sub(lambda m: self._ph("CUSTOM", m.group(0)), t)
        if "email" in self.types:
            t = _EMAIL.sub(lambda m: self._ph("EMAIL", m.group(0)), t)
        if "user" in self.types:
            def u(m):
                v = m.group(2)
                if v.lower() in _NOT_USERS or _PLACEHOLDER.fullmatch(v) or v.endswith("$"):
                    return m.group(0)
                return m.group(1) + self._ph("USER", v)
            t = _USER.sub(u, t)
        if "ipv4" in self.types:
            t = _IPV4.sub(lambda m: self._ph("IP", m.group(0)) if self._ip_ok(m.group(0)) else m.group(0), t)
        if "ipv6" in self.types:
            t = _IPV6.sub(lambda m: self._ph("IP", m.group(0)) if self._ip_ok(m.group(0)) else m.group(0), t)
        return t

    def unmask(self, text: str) -> str:
        if not text or not self.back:
            return text
        return _PLACEHOLDER.sub(lambda m: self.back.get(m.group(0), m.group(0)), text)


class _MaskedBound:
    def __init__(self, bound, masker: Masker):
        self._b, self._m = bound, masker
        self.provider, self.model = bound.provider, bound.model

    def chat(self, messages, **kw):
        masked = [{**m, "content": self._m.mask(m.get("content", ""))} for m in messages]
        res = self._b.chat(masked, **kw)
        if res.text:
            res.text = self._m.unmask(res.text)
        return res


class PrivacyLLM:
    """Wraps an LLM (``for_role``) so prompts to the listed providers are masked."""

    def __init__(self, llm, settings: dict | None = None):
        s = settings or {}
        self.llm = llm
        self._usage: dict[str, dict] = {}   # per-wrapper meter: one wrapper per hunt
        self.mask_for = tuple(s.get("mask_for", CLOUD))
        self.masker = Masker(types=tuple(s.get("types", DEFAULT_TYPES)), terms=list(s.get("terms") or []),
                             patterns=list(s.get("patterns") or []),
                             keep_public_ips=bool(s.get("keep_public_ips", False)))

    def for_role(self, role: str):
        b = self.llm.for_role(role)
        if hasattr(b, "meter"):
            b.meter = self._usage          # count this wrapper's (one hunt's) calls only
        return _MaskedBound(b, self.masker) if getattr(b.provider, "name", "") in self.mask_for else b

    @property
    def usage(self) -> dict:
        return self._usage

    def usage_summary(self) -> dict:
        return self.llm.usage_summary(self._usage) if hasattr(self.llm, "usage_summary") else {}

    def summary(self) -> dict[str, Any]:
        return {"masked_values": len(self.back_map()), "by_type": dict(self.masker.counts)}

    def back_map(self) -> dict[str, str]:
        return self.masker.back


def validate(settings: dict) -> None:
    for p in (settings or {}).get("patterns") or []:
        re.compile(p)
    bad = set((settings or {}).get("types") or []) - set(DEFAULT_TYPES)
    if bad:
        raise ValueError(f"privacy.types has unknown entries {sorted(bad)}; use {DEFAULT_TYPES}")
