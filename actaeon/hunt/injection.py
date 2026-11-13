"""Spot text in tool results that tries to instruct an AI (prompt injection).

Log fields such as command lines, user agents, file names and email bodies are
attacker-controlled. Text there that addresses an AI ("ignore previous
instructions", "mark this host as benign", chat-template tags) is never normal
telemetry, so it is reported as a lead in its own right: the hunt is flagged
for an analyst, whatever the verdict. The text is still only data: the model
is told so, and nothing here changes what tools can do.

Simple patterns, not a classifier: they catch the blatant attempts and cost
nothing. A miss is covered by the untrusted-data wrapping and the tool policy.
"""

from __future__ import annotations

import re

_AI = r"(?:ai|assistant|model|llm|agent|analyst|hunter|bot)"
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ignore instructions", re.compile(
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous|prior|above|earlier|"
        r"preceding|system|original)\s+(?:instructions?|prompts?|rules?|directions?|context)", re.I)),
    ("override marker", re.compile(
        r"\b(?:system|admin|developer|security)\s+(?:override|prompt|instructions?|message)\s*[:\]-]", re.I)),
    ("addresses an AI", re.compile(
        rf"\b(?:you\s+are\s+(?:now\s+)?(?:an?\s+|the\s+)?{_AI}\b|(?:note|message|instruction)s?\s+(?:to|for)\s+"
        rf"(?:the\s+|any\s+)?{_AI}s?\b|\bif\s+you\s+are\s+an?\s+{_AI}\b)", re.I)),
    ("asks for a benign verdict", re.compile(
        r"\b(?:mark|classify|report|treat|label|consider|flag)\s+(?:this|the|these|all)?\s*(?:host|system|machine|"
        r"finding|activity|event|alert|file|process|traffic|entry|log)?s?\s+as\s+(?:benign|clean|safe|"
        r"false[\s_-]?positive|legitimate|harmless|not\s+malicious)", re.I)),
    ("tells it not to report", re.compile(
        r"\b(?:do\s+not|don'?t|never)\s+(?:report|flag|alert|escalate|mention|investigate)\s+(?:this|it|these|"
        r"the\s+(?:host|activity|finding|process))", re.I)),
    ("chat template tags", re.compile(
        r"<\|im_(?:start|end)\|>|\[/?INST\]|<</?SYS>>|</?(?:system|assistant)>|<\|(?:system|assistant|user)\|>",
        re.I)),
    ("fake verdict or action", re.compile(
        r"\"action\"\s*:\s*\"(?:verdict|call)\"|\"outcome\"\s*:\s*\"(?:telemetry_found_benign|no_results)\"", re.I)),
    ("breaks out of the data wrapper", re.compile(r"UNTRUSTED[_-]DATA", re.I)),
]


_OPEN = re.compile(r"^\s*<<UNTRUSTED-DATA [^>\n]*>>")
_CLOSE = re.compile(r"<<END-UNTRUSTED-DATA [^>\n]*>>\s*$")


def _body(content: str) -> str:
    """The text inside the untrusted-data wrapper (the wrapper's own markers are ours; inside it,
    wrap() has already turned any look-alike marker into UNTRUSTED_DATA)."""
    return _CLOSE.sub("", _OPEN.sub("", content, count=1), count=1)


def scan(content: str, max_hits: int = 5) -> list[dict]:
    """Return [{pattern, excerpt}] for text that looks like instructions to an AI."""
    body = _body(content or "")
    hits: list[dict] = []
    for name, rx in PATTERNS:
        m = rx.search(body)
        if m:
            a, b = max(0, m.start() - 60), min(len(body), m.end() + 60)
            excerpt = re.sub(r"\s+", " ", body[a:b]).strip()
            hits.append({"pattern": name, "excerpt": excerpt[:200]})
            if len(hits) >= max_hits:
                break
    return hits
