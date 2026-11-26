"""Quality checks for a Sigma rule. Errors block the ready status; warnings are advice."""

from __future__ import annotations

from typing import Any

import yaml

from .sigma_eval import Unsupported, compile_rule

LEVELS = ("informational", "low", "medium", "high", "critical")


def _values(det: dict) -> list[tuple[str, Any]]:
    out = []
    for k, v in det.items():
        if k == "condition":
            continue
        for alt in (v if isinstance(v, list) else [v]):
            if isinstance(alt, dict):
                for f, val in alt.items():
                    for x in (val if isinstance(val, list) else [val]):
                        out.append((str(f), x))
            else:
                out.append(("(keyword)", alt))
    return out


def lint(sigma: str, *, known_fields: set[str] | None = None, field_map: dict | None = None,
         duplicates: list[str] | None = None) -> list[dict]:
    msgs: list[dict] = []

    def err(t: str) -> None:
        msgs.append({"level": "error", "text": t})

    def warn(t: str) -> None:
        msgs.append({"level": "warning", "text": t})
    try:
        doc = yaml.safe_load(sigma)
    except yaml.YAMLError as exc:
        err(f"not valid YAML: {exc}"[:300])
        return msgs
    if not isinstance(doc, dict):
        err("not a YAML mapping")
        return msgs
    for k in ("title", "logsource", "detection"):
        if k not in doc:
            err(f"missing {k}")
    det = doc.get("detection") if isinstance(doc.get("detection"), dict) else {}
    if doc.get("detection") is not None and "condition" not in det:
        err("detection has no condition")
    if not isinstance(doc.get("logsource"), dict) or not (doc["logsource"].get("category") or doc["logsource"].get("product")
                                                           or doc["logsource"].get("service")):
        warn("logsource names no category, product or service, so converters cannot pick field mappings")
    try:
        compiled = compile_rule(doc) if det else None
    except Unsupported as exc:
        compiled = None
        warn(f"cannot be tested locally: {exc}")
    if str(doc.get("level", "")).lower() not in LEVELS:
        warn("no valid level (informational, low, medium, high, critical)")
    if not doc.get("description"):
        warn("no description")
    if not doc.get("falsepositives"):
        warn("no falsepositives: say what legitimate activity looks like this")
    if not any(isinstance(t, str) and t.lower().startswith("attack.t") for t in doc.get("tags") or []):
        warn("no ATT&CK technique tag (attack.tXXXX), so it does not count towards coverage")
    vals = _values(det)
    if vals and all(f == "(keyword)" for f, _ in vals):
        warn("keyword-only rule: slow on most platforms and often noisy; match named fields if you can")
    for f, x in vals:
        s = "" if x is None else str(x)
        if s.strip("*") == "" and x is not None and "|exists" not in f:
            err(f"{f}: value '{s}' matches anything")
        elif "|contains" in f and len(s.strip("*")) < 3:
            warn(f"{f}|contains '{s}' is very short and will be noisy")
    cond = str(det.get("condition", "")).strip().lower()
    if cond.startswith("not ") and " and " not in cond and " or " not in cond:
        err("the condition only excludes, so it matches nearly everything")
    if compiled and known_fields:
        fm = {k.lower() for k in (field_map or {})}
        for f in compiled.fields():
            leaf = f.rsplit(".", 1)[-1].lower()
            if f.lower() not in known_fields and leaf not in known_fields and f.lower() not in fm:
                warn(f"field '{f}' was not seen in your data (add it to rules.field_map if it has another name)")
    for d in duplicates or []:
        warn(f"same detection logic as rule {d}")
    return msgs
