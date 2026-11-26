"""ATT&CK Navigator layers (layer format 4.5), for rule coverage and for an investigation's techniques.

Open the file in the MITRE ATT&CK Navigator (Open Existing Layer, Upload from local). ATT&CK is a trademark of
The MITRE Corporation.
"""

from __future__ import annotations

import re

TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def layer(name: str, description: str, scores: dict[str, tuple[int, str]], *, colors: tuple[str, str]) -> dict:
    """``scores``: technique id -> (score, comment)."""
    from .hunt.attack_names import version
    techs = [{"techniqueID": t, "score": int(sc), "comment": cm[:900], "enabled": True, "showSubtechniques": True}
             for t, (sc, cm) in sorted(scores.items()) if TECH.match(t)]
    top = max([x["score"] for x in techs] or [1])
    ver = re.sub(r"[^0-9.]", "", str(version() or "")).split(".")[0] or "16"
    return {"name": name[:120], "versions": {"attack": ver, "navigator": "5.1.0", "layer": "4.5"},
            "domain": "enterprise-attack", "description": description[:900], "techniques": techs,
            "gradient": {"colors": list(colors), "minValue": 0, "maxValue": max(1, top)},
            "legendItems": [], "showTacticRowBackground": False, "selectTechniquesAcrossTactics": True,
            "hideDisabled": False, "metadata": [{"name": "made by", "value": "Actaeon"}]}


def rules_layer(cov: dict) -> dict:
    scores = {}
    for x in cov["techniques"]:
        if x["ready"]:
            scores[x["technique"]] = (x["ready"], f"{x['ready']} ready rule(s): " + "; ".join(
                r["title"] for r in x["rules"] if r["status"] == "ready")[:600])
        elif x["gap"]:
            scores[x["technique"]] = (0, "gap: " + "; ".join(x["reasons"]))
    return layer("Actaeon rule coverage", "Score = rules marked ready for the technique. Score 0 = a gap: hunts, cases "
                 "or your priority list say it matters and no rule is ready.", scores, colors=("#f8d7da", "#2e7d32"))


def case_layer(title: str, detections: list[dict]) -> dict:
    scores: dict[str, list] = {}
    for d in detections:
        for t in d.get("attack") or []:
            x = scores.setdefault(t, [0, []])
            x[0] += int(d.get("n") or 0)
            if d["title"] not in x[1]:
                x[1].append(d["title"])
    return layer(f"Investigation: {title}", "Score = events with a detection tagged with the technique.",
                 {t: (n, "; ".join(titles)[:600]) for t, (n, titles) in scores.items()}, colors=("#fff3e0", "#c62828"))
