"""Check a case's indicators against intel: Actaeon's own intel store and every connector with the ``intel`` role
and a ``lookup`` tool (Zarqa, for example). Known indicators become detections on the events that carry them.

Indicators come from fields that hold them (addresses, DNS names, hashes) and from command lines and scripts
(URLs, domains, IPs found in the text). Private, loopback and link-local addresses are skipped. Only the
indicator value is sent to a connector, never the event.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

ADDR_FIELDS = ("IpAddress", "DestinationIp", "SourceIp", "src_ip", "dst_ip", "ClientAddress", "RemoteAddress",
               "ForeignAddr", "SourceAddress", "DestAddress")
NAME_FIELDS = ("QueryName", "DestinationHostname", "domain", "Domain")
TEXT_FIELDS = ("CommandLine", "ScriptBlockText", "ImagePath", "message", "Payload")
HASH_RE = re.compile(r"(?i)\b(?:MD5|SHA1|SHA256|IMPHASH)=([0-9a-f]{32,64})")


def _public_ip(v: str) -> bool:
    try:
        ip = ipaddress.ip_address(v.strip().strip("[]"))
    except ValueError:
        return False
    return ip.is_global


def indicators(store, cid: str, limit: int = 500) -> dict[str, list[int]]:
    """{indicator: [event seq, ...]} for the case (the most widespread first, at most ``limit``)."""
    from ..intel.extract import extract, guess_type
    found: dict[str, list[int]] = {}

    def add(v: str, seq: int) -> None:
        v = v.strip().lower().rstrip(".")
        if not v or len(v) > 300:
            return
        kind = guess_type(v)
        if kind in ("ipv4", "ipv6") and not _public_ip(v):
            return
        if kind is None:
            return
        lst = found.setdefault(v, [])
        if len(lst) < 1000 and (not lst or lst[-1] != seq):
            lst.append(seq)
    for e in store.iter_events(cid):
        d = e["data"]
        for k in ADDR_FIELDS + NAME_FIELDS:
            if d.get(k):
                add(str(d[k]), e["seq"])
        for m in HASH_RE.finditer(str(d.get("Hashes") or d.get("Hash") or "")):
            add(m.group(1), e["seq"])
        for k in TEXT_FIELDS:
            t = d.get(k)
            if isinstance(t, str) and ("http" in t or "." in t):
                x = extract(t[:20_000])
                for kind in ("url", "domain", "ipv4", "sha256", "md5", "sha1"):
                    for v in x.get(kind, [])[:20]:
                        add(v, e["seq"])
    ranked = sorted(found.items(), key=lambda kv: -len(kv[1]))[:limit]
    return dict(ranked)


def _connector_lookup(hub, conn: str, value: str, cid: str) -> dict | None:
    from ..hunt.signals import payload
    try:
        r = hub.call(conn, "lookup", {"value": value}, actor="dfir", hunt_id=f"dfir-{cid}")
    except Exception:
        return None
    if r.get("is_error"):
        return None
    try:
        data = json.loads(payload(r.get("content") or ""))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def check(cfg, store, cid: str, *, hub=None, limit: int = 500) -> dict[str, Any]:
    from ..intel import IntelStore
    found = indicators(store, cid, limit)
    local = IntelStore(cfg.data_dir / "intel.sqlite")
    conns: list[str] = []
    if hub is not None:
        for spec in hub.connectors_for_role("intel"):
            try:
                if any(t["name"] == "lookup" and t.get("allowed") for t in hub.tools(spec.name)):
                    conns.append(spec.name)
            except Exception:
                continue
    matches = []
    for v in found:
        hits = []
        r = local.lookup(v)
        if r.get("found"):
            hits.append({"source": "local intel", "tags": sorted({t for m in r["matches"] for t in m.get("tags") or []})[:8]})
        for conn in conns:
            data = _connector_lookup(hub, conn, v, cid)
            if data and data.get("found"):
                tags = sorted({t for m in data.get("matches") or [] if isinstance(m, dict) for t in m.get("tags") or []})
                hits.append({"source": conn, "tags": tags[:8]})
        if hits:
            matches.append({"value": v, "events": found[v][:200], "count": len(found[v]), "hits": hits})
    rows = []
    for m in matches:
        tags = sorted({t for h in m["hits"] for t in h["tags"]})
        title = f"Known indicator {m['value']}" + (f" ({', '.join(tags[:4])})" if tags else "")
        rows += [(seq, f"intel:{m['value']}", title, "high", "intel", []) for seq in m["events"]]
    store.clear_intel(cid)
    store.add_detections(cid, rows)
    store.refresh_levels(cid)
    res = {"checked": len(found), "matched": len(matches), "sources": ["local intel", *conns], "matches": matches[:200]}
    store.save_analysis(cid, "intel", res)
    return res
