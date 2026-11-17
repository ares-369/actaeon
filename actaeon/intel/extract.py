"""Pull indicators and ATT&CK technique IDs out of free text (advisories, emails, notes).

Handles common defanging: hxxp, [.], (.), {.}, [:], [at]. Pattern-based, so it
can miss indicators or pick up false ones; review before trusting.
"""

from __future__ import annotations

import ipaddress
import re

TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "cve", "technique")

_FILE_EXT = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "zip", "rar", "7z", "gz", "tar", "iso", "img",
    "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "rtf", "txt", "log", "csv", "json", "xml", "html",
    "htm", "php", "asp", "aspx", "jsp", "png", "jpg", "jpeg", "gif", "svg", "lnk", "msi", "hta", "py", "sh", "bin",
    "dat", "tmp", "ini", "cfg", "conf", "yaml", "yml", "md", "so", "elf", "apk", "dmg", "pkg", "one", "local",
}

_RE = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`)\]]+", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"),
    "ipv4": re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d|\.\d)"),
    "ipv6": re.compile(r"(?<![:\w.])(?=[0-9a-fA-F:]*:[0-9a-fA-F]*:)[0-9a-fA-F:]{2,39}(?![:\w])"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "technique": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "domain": re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"),
}


def refang(text: str) -> str:
    t = re.sub(r"\bhxxp(s?)", r"http\1", text, flags=re.I)
    t = re.sub(r"\bfxp\b", "ftp", t, flags=re.I)
    t = re.sub(r"\s?[\[\(\{]\s?(?:\.|dot)\s?[\]\)\}]\s?", ".", t, flags=re.I)
    t = re.sub(r"[\[\(\{]:[\]\)\}]", ":", t)
    t = re.sub(r"\s?[\[\(\{]\s?(?:@|at)\s?[\]\)\}]\s?", "@", t, flags=re.I)
    return t.replace("[://]", "://")


def normalize(kind: str, value: str) -> str:
    v = value.strip()
    if kind in ("domain", "email", "md5", "sha1", "sha256"):
        return v.lower().rstrip(".")
    if kind == "cve":
        return v.upper()
    if kind == "ipv6":
        try:
            return str(ipaddress.IPv6Address(v))
        except ValueError:
            return v.lower()
    if kind == "url":
        return v.rstrip(".,;")
    return v


def guess_type(value: str) -> str | None:
    """Type of a single value, or None if it does not look like an indicator."""
    v = refang(value.strip())
    for kind in ("url", "email", "cve", "technique", "sha256", "sha1", "md5", "ipv4", "ipv6", "domain"):
        m = _RE[kind].fullmatch(v)
        if not m or (kind == "domain" and not _ok_domain(v)):
            continue
        if kind == "ipv6" and not _is_v6(v):
            continue
        return kind
    return None


def _is_v6(v: str) -> bool:
    try:
        return not ipaddress.IPv6Address(v).is_unspecified
    except ValueError:
        return False


def _ok_domain(d: str) -> bool:
    tld = d.rsplit(".", 1)[-1].lower()
    return tld not in _FILE_EXT and not d.replace(".", "").isdigit()


def extract(text: str) -> dict[str, list[str]]:
    """Return ``{type: [values]}`` found in ``text`` (deduplicated, in order)."""
    t = refang(text or "")
    out: dict[str, list[str]] = {k: [] for k in TYPES}
    seen: set[tuple[str, str]] = set()
    taken: list[tuple[int, int]] = []

    def add(kind: str, raw: str, span: tuple[int, int]) -> None:
        v = normalize(kind, raw)
        if (kind, v) in seen:
            return
        seen.add((kind, v))
        out[kind].append(v)
        taken.append(span)

    def inside(span):
        return any(a <= span[0] and span[1] <= b for a, b in taken)

    for kind in ("url", "email", "cve", "technique", "sha256", "sha1", "md5", "ipv4", "ipv6"):
        for m in _RE[kind].finditer(t):
            if inside(m.span()):
                continue
            if kind == "ipv6" and not _is_v6(m.group(0)):
                continue
            add(kind, m.group(0), m.span())
    for m in _RE["domain"].finditer(t):
        if not inside(m.span()) and _ok_domain(m.group(0)):
            add("domain", m.group(0), m.span())
    # the host of each URL is also worth hunting
    for u in list(out["url"]):
        host = re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split(":")[0].split("@")[-1]
        k = guess_type(host)
        if k in ("domain", "ipv4") and normalize(k, host) not in out[k]:
            out[k].append(normalize(k, host))
    # and the domain of each email address
    for e in list(out["email"]):
        d = e.split("@", 1)[1]
        if _ok_domain(d) and d not in out["domain"]:
            out["domain"].append(d)
    return {k: v for k, v in out.items() if v}
