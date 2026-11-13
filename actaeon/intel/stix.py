"""STIX 2.1 export: the intel store, or the indicators and techniques of one hunt.

Object ids are derived from the content (UUIDv5), so exporting the same
indicator twice gives the same id and a platform that imports both keeps one.
CVEs and ATT&CK technique IDs are not indicators: they become ``vulnerability``
and ``attack-pattern`` objects. Push a bundle to a TAXII 2.1 collection with the
``taxii`` output (docs/outputs.md), or download it from the UI / API / CLI.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .extract import extract

NS = uuid.UUID("6f5c7d0e-3b7a-4c55-9c1e-8a6b0b9f4a11")   # Actaeon's namespace for content ids
_HASH = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
_OBJ = {"ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name", "url": "url", "email": "email-addr"}


def _ts(value: str | None = None) -> str:
    """STIX timestamp (UTC, millisecond precision, Z)."""
    if value:
        try:
            d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            d = d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            d = datetime.now(timezone.utc)
    else:
        d = datetime.now(timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def _id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, key)}"


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


def pattern(kind: str, value: str) -> str | None:
    if kind in _HASH:
        return f"[file:hashes.'{_HASH[kind]}' = '{_esc(value.lower())}']"
    if kind in _OBJ:
        return f"[{_OBJ[kind]}:value = '{_esc(value)}']"
    return None


def identity(name: str = "Actaeon") -> dict:
    now = "2026-01-01T00:00:00.000Z"
    return {"type": "identity", "spec_version": "2.1", "id": _id("identity", f"producer:{name}"), "created": now,
            "modified": now, "name": name, "identity_class": "system"}


def indicator(kind: str, value: str, *, producer: str, first_seen: str | None = None, updated: str | None = None,
              confidence: int | None = None, tags: list[str] | None = None, note: str = "",
              expires: str | None = None) -> dict | None:
    pat = pattern(kind, value)
    if not pat:
        return None
    o = {"type": "indicator", "spec_version": "2.1", "id": _id("indicator", f"{kind}:{value.lower()}"),
         "created": _ts(first_seen), "modified": _ts(updated or first_seen), "name": f"{kind}: {value}"[:250],
         "pattern": pat, "pattern_type": "stix", "valid_from": _ts(first_seen), "indicator_types": ["malicious-activity"],
         "created_by_ref": producer}
    if confidence is not None:
        o["confidence"] = max(0, min(100, int(confidence)))
    if tags:
        o["labels"] = [str(t)[:100] for t in tags][:20]
    if note:
        o["description"] = note[:2000]
    if expires:
        o["valid_until"] = _ts(expires)
    return o


def attack_pattern(tid: str, producer: str) -> dict:
    from ..hunt.attack_names import name
    now = "2026-01-01T00:00:00.000Z"
    return {"type": "attack-pattern", "spec_version": "2.1", "id": _id("attack-pattern", tid), "created": now,
            "modified": now, "name": name(tid) or tid, "created_by_ref": producer,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                     "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}]}


def vulnerability(cve: str, producer: str) -> dict:
    now = "2026-01-01T00:00:00.000Z"
    return {"type": "vulnerability", "spec_version": "2.1", "id": _id("vulnerability", cve.upper()), "created": now,
            "modified": now, "name": cve.upper(), "created_by_ref": producer,
            "external_references": [{"source_name": "cve", "external_id": cve.upper()}]}


def bundle(objects: list[dict]) -> dict:
    seen, objs = set(), []
    for o in objects:
        if o and o["id"] not in seen:
            seen.add(o["id"])
            objs.append(o)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def export_store(store, *, producer_name: str = "Actaeon", tag: str | None = None, min_confidence: int = 0,
                 changed_since: str | None = None, limit: int = 5000) -> dict:
    ident = identity(producer_name)
    objs: list[dict] = [ident]
    for r in store.list(tag=tag, min_confidence=min_confidence, changed_since=changed_since, limit=limit):
        if r["type"] == "cve":
            objs.append(vulnerability(r["value"], ident["id"]))
        elif r["type"] == "technique":
            objs.append(attack_pattern(r["value"], ident["id"]))
        else:
            objs.append(indicator(r["type"], r["value"], producer=ident["id"], first_seen=r["first_seen"],
                                  updated=r["updated"], confidence=r["confidence"], tags=r["tags"], note=r["note"],
                                  expires=r.get("expires")))
    return bundle(objs)


def hunt_bundle(h: dict, *, producer_name: str = "Actaeon") -> dict:
    """Indicators named in a hunt's findings, its ATT&CK techniques, and a report that ties them together."""
    ident = identity(producer_name)
    v = h.get("verdict") or {}
    claims = " ".join(f.get("claim", "") for f in v.get("findings") or [])
    found = extract(claims)
    when = h.get("finished") or h.get("created")
    conf = int(v.get("confidence") or 0)
    objs: list[dict] = [ident]
    for kind in ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256"):
        for val in found.get(kind, []):
            objs.append(indicator(kind, val, producer=ident["id"], first_seen=when, confidence=conf,
                                  tags=["actaeon-hunt", f"hunt:{h['id']}"],
                                  note=f"Named in Actaeon hunt {h['id']}: {h.get('hypothesis', '')[:300]}"))
    for tid in v.get("attack") or []:
        objs.append(attack_pattern(tid, ident["id"]))
    for cve in found.get("cve", []):
        objs.append(vulnerability(cve, ident["id"]))
    refs = [o["id"] for o in objs[1:] if o]
    if refs:
        objs.append({"type": "report", "spec_version": "2.1", "id": _id("report", f"hunt:{h['id']}"),
                     "created": _ts(h.get("created")), "modified": _ts(when), "published": _ts(when),
                     "name": f"Actaeon hunt: {h.get('hypothesis', '')[:200]}", "report_types": ["threat-report"],
                     "description": f"Outcome: {h.get('outcome')} (confidence {conf}). {v.get('summary', '')}"[:4000],
                     "confidence": conf, "object_refs": refs, "created_by_ref": ident["id"],
                     "labels": [str(h.get("outcome") or "unknown")]})
    return bundle(objs)
