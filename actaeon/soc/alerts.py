"""Turn an alert from any source into one normal shape, and pull out its entities.

Sources name fields differently. ``normalize`` looks for each normal field
under a list of common keys (dotted paths into nested JSON); ``soc.intake.field_map``
adds your own keys in front. Nothing here names a product: the keys are the
shapes common to alert JSON in general.

Normal alert::

    {id, source, rule_id, rule_name, title, description, severity (0-100), severity_label,
     ts, entities: [{type, value}], attack: [T....], fingerprint, raw}
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

from ..intel.extract import extract

# normal field -> keys tried in order (dotted paths)
FIELD_KEYS: dict[str, list[str]] = {
    "id": ["id", "_id", "alert_id", "alert.id", "event.id", "uuid"],
    "rule_id": ["rule.id", "rule_id", "rule.uuid", "signature_id", "detection.id", "alert.signature_id"],
    "rule_name": ["rule.name", "rule.description", "rule_name", "signature", "alert.signature", "detection.name",
                  "name", "title"],
    "title": ["title", "summary", "name", "rule.description", "rule.name", "message", "alert.signature"],
    "description": ["description", "message", "full_log", "details", "rule.description"],
    "severity": ["severity", "rule.level", "level", "alert.severity", "event.severity", "risk_score", "priority",
                 "severity_label"],
    "ts": ["@timestamp", "timestamp", "ts", "time", "created", "created_at", "event.created", "date"],
    "host": ["host.name", "hostname", "agent.name", "host", "computer", "device.name", "observer.name", "dvc"],
    "user": ["user.name", "user", "username", "data.win.eventdata.targetUserName", "data.dstuser", "data.srcuser",
             "account", "target_user", "actor.user"],
    "src_ip": ["source.ip", "src_ip", "srcip", "data.srcip", "client.ip", "src", "remote_ip"],
    "dst_ip": ["destination.ip", "dst_ip", "dstip", "data.dstip", "dest_ip", "dst", "server.ip"],
    "process": ["process.name", "process", "process.executable", "image", "data.win.eventdata.image"],
    "command_line": ["process.command_line", "command_line", "cmdline", "data.win.eventdata.commandLine"],
    "parent_process": ["process.parent.name", "parent_process", "parent_image", "data.win.eventdata.parentImage"],
    "domain": ["destination.domain", "dns.question.name", "domain", "url.domain", "query"],
    "url": ["url.full", "url", "request.url"],
    "hash": ["file.hash.sha256", "process.hash.sha256", "hash", "sha256", "file.hash.md5", "md5"],
    "file": ["file.path", "file.name", "file", "syscheck.path", "target_filename"],
    "attack": ["rule.mitre.id", "threat.technique.id", "mitre", "attack", "techniques", "tags"],
}
ENTITY_FIELDS = {"host": "host", "user": "user", "src_ip": "ip", "dst_ip": "ip", "process": "process",
                 "domain": "domain", "url": "url", "hash": "hash", "file": "file"}
_LABELS = (("critical", 85), ("high", 65), ("medium", 40), ("low", 0))
_WORD_SEV = {"informational": 5, "info": 5, "low": 25, "medium": 50, "moderate": 50, "high": 75, "critical": 95,
             "severe": 90}
_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Domains found in free text must end in a known suffix (a name like "c.okafor" is a user, not a domain).
_TLDS = set(["com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co", "ai", "app", "dev", "cloud", "online", "site", "xyz", "top", "club", "shop", "store", "tech", "me", "tv", "cc", "ws", "mobi", "name", "pro", "aero", "asia", "cat", "jobs", "travel", "live", "news", "blog", "email", "link", "click", "page", "space", "website", "world", "example", "test", "invalid", "localhost", "internal", "corp", "lan", "home", "arpa", "local", "onion"])
_IGNORE_USERS = {"", "-", "n/a", "none", "null", "system", "local service", "network service", "unknown"}


def get_path(obj: Any, path: str) -> Any:
    """``a.b.c`` into nested dicts; also accepts a flat key that contains dots."""
    if isinstance(obj, dict) and path in obj:
        return obj[path]
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _first(raw: dict, keys: list[str]) -> Any:
    for k in keys:
        v = get_path(raw, k)
        if v not in (None, "", [], {}):
            return v
    return None


def severity_score(value: Any, scale: str | int = "auto") -> int:
    """0-100 from a word, or a number on the source's scale: ``soc.intake.severity_scale`` 4, 10, 15 or 100.
    "auto" reads up to 10 as 0-10, up to 15 as 0-15, and anything larger as 0-100."""
    if value is None or isinstance(value, bool):
        return 30
    if isinstance(value, (int, float)):
        v = float(value)
        top = {"4": 4, "10": 10, "15": 15, "100": 100}.get(str(scale))
        if top is None:
            top = 10 if v <= 10 else 15 if v <= 15 else 100
        return max(0, min(100, round(v / top * 100)))
    s = str(value).strip().lower()
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return severity_score(float(s), scale)
    for word, score in _WORD_SEV.items():
        if word in s:
            return score
    return 30


def severity_label(score: int) -> str:
    for label, floor in _LABELS:
        if score >= floor:
            return label
    return "low"


def _ts(value: Any) -> str:
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e12:
            v /= 1000.0
        return datetime.fromtimestamp(v, timezone.utc).isoformat(timespec="seconds")
    if isinstance(value, str) and value.strip():
        s = value.strip().replace("Z", "+00:00")
        try:
            d = datetime.fromisoformat(s)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _str(v: Any) -> str:
    if isinstance(v, list):
        v = v[0] if v else ""
    if isinstance(v, dict):
        v = v.get("name") or v.get("value") or ""
    return str(v).strip() if v is not None else ""


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128")]


def _private(ip: str) -> bool:
    """Internal address space (RFC 1918, loopback, link-local, CGNAT, ULA). Documentation ranges count as
    external, so the sample data behaves like the internet."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _INTERNAL if n.version == a.version)


def entities_of(fields: dict[str, Any], text: str = "") -> list[dict]:
    """Entities from the alert's fields, plus indicators found in its text."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, field: str = "") -> None:
        value = (value or "").strip()
        if not value or len(value) > 512:
            return
        if kind == "user" and value.lower() in _IGNORE_USERS:
            return
        key = (kind, value.lower())
        if key in seen:
            return
        seen.add(key)
        e = {"type": kind, "value": value}
        if field:
            e["field"] = field
        if kind == "ip":
            e["internal"] = _private(value)
        out.append(e)

    for f, kind in ENTITY_FIELDS.items():
        v = fields.get(f)
        if v:
            add(kind, _str(v), f)
    if text:
        found = extract(text[:20000])
        for ip in found.get("ipv4", [])[:20]:
            add("ip", ip)
        taken = {e["value"].lower() for e in out}
        for d in found.get("domain", [])[:20]:
            tld = d.rsplit(".", 1)[-1].lower()
            if d.lower() not in taken and (tld in _TLDS or len(tld) == 2):
                add("domain", d)
        for u in found.get("url", [])[:10]:
            add("url", u)
        for h in (found.get("sha256", []) + found.get("sha1", []) + found.get("md5", []))[:10]:
            add("hash", h)
    return out


def _techniques(v: Any, text: str) -> list[str]:
    vals: list[str] = []
    if isinstance(v, list):
        for x in v:
            vals += _TECH.findall(str(x))
    elif v:
        vals += _TECH.findall(str(v))
    vals += _TECH.findall(text[:5000])
    return sorted(set(vals))


def fingerprint(source: str, rule_id: str, rule_name: str, entities: list[dict]) -> str:
    """Same rule on the same main entities = the same alert again (a duplicate, not a new case)."""
    keys = sorted(f"{e['type']}:{e['value'].lower()}" for e in entities if e["type"] in ("host", "user", "ip"))
    body = json.dumps([source, rule_id or rule_name, keys[:6]])
    return hashlib.sha256(body.encode()).hexdigest()[:20]


def normalize(raw: dict, *, source: str = "webhook", field_map: dict[str, list[str]] | None = None,
              severity_scale: str | int = "auto") -> dict:
    if not isinstance(raw, dict):
        raise ValueError("an alert must be a JSON object")
    field_map = field_map or {}
    keys = {f: [*field_map.get(f, []), *ks] for f, ks in FIELD_KEYS.items()}
    fields = {f: _first(raw, ks) for f, ks in keys.items()}
    text = json.dumps(raw, default=str)[:20000]
    rule_id = _str(fields["rule_id"])[:200]
    rule_name = _str(fields["rule_name"])[:300]
    title = _str(fields["title"])[:300] or rule_name or "Alert"
    score = severity_score(fields["severity"], severity_scale)
    ents = entities_of(fields, text)
    ts = _ts(fields["ts"])
    rid = _str(fields["id"])[:200]
    if not rid:
        rid = hashlib.sha256((source + text).encode()).hexdigest()[:24]
    return {
        "id": f"{source}:{rid}"[:240],
        "source": source,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "title": title,
        "description": _str(fields["description"])[:2000],
        "severity": score,
        "severity_label": severity_label(score),
        "ts": ts,
        "entities": ents,
        "attack": _techniques(fields["attack"], ""),
        "command_line": _str(fields["command_line"])[:4000],
        "parent_process": _str(fields["parent_process"])[:300],
        "fingerprint": fingerprint(source, rule_id, rule_name, ents),
        "raw": raw,
    }


def hits_from_result(content: str) -> list[dict]:
    """Alert objects inside a connector result: a JSON list, or a dict holding one under a common key."""
    from .util import payload
    try:
        data = json.loads(payload(content))
    except ValueError:
        return []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = next((data[k] for k in ("alerts", "hits", "results", "items", "data", "events", "records", "rows")
                      if isinstance(data.get(k), list)), [])
        common = data.get("common") if isinstance(data.get("common"), dict) else None
        if common:   # compacted search results keep shared fields once
            items = [{**common, **i} if isinstance(i, dict) else i for i in items]
    else:
        items = []
    out = []
    for i in items:
        if isinstance(i, dict):
            src = i.get("_source") if isinstance(i.get("_source"), dict) else None
            out.append({**src, "_id": i.get("_id")} if src else i)
    return out
