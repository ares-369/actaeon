"""Build actaeon/hunt/attack_data.json from the ATT&CK Enterprise STIX bundle.

Usage: python scripts/build_attack_data.py enterprise-attack.json
Source: https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json)
"""
import json
import sys
from pathlib import Path

bundle = json.load(open(sys.argv[1], encoding="utf-8"))
objs = bundle["objects"]
by_id = {o["id"]: o for o in objs}
version = next((o.get("x_mitre_version") for o in objs if o.get("type") == "x-mitre-collection"), "")
techs, retired = {}, {}
for o in objs:
    if o.get("type") != "attack-pattern":
        continue
    ext = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
    if not ext:
        continue
    if o.get("revoked") or o.get("x_mitre_deprecated"):
        retired[ext] = {"n": o.get("name", ""), "by": "", "id": o["id"]}
        continue
    tactics = sorted({p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"})
    techs[ext] = {"n": o["name"], "t": tactics, "d": [], "p": sorted(o.get("x_mitre_platforms", []))}
# revoked-by: map an old ID to the technique that replaced it
ext_of = {o["id"]: next((r["external_id"] for r in o.get("external_references", [])
                         if r.get("source_name") == "mitre-attack"), "") for o in objs if o.get("type") == "attack-pattern"}
for o in objs:
    if o.get("relationship_type") == "revoked-by":
        old, new = ext_of.get(o["source_ref"], ""), ext_of.get(o["target_ref"], "")
        if old in retired and new:
            retired[old]["by"] = new
for r in retired.values():
    r.pop("id", None)
# data components that detect each technique (relationship "detects")
comp_names = {}
for o in objs:
    if o.get("type") == "x-mitre-data-component":
        src = by_id.get(o.get("x_mitre_data_source_ref", ""), {})
        comp_names[o["id"]] = f"{src['name']}: {o['name']}" if src.get("name") else o["name"]
def comps_for(src):
    """Data components behind a detects relationship: a data component, or (ATT&CK 18+) a
    detection strategy -> analytics -> log source references."""
    if src.get("type") == "x-mitre-data-component":
        return [comp_names.get(src["id"])]
    out = []
    for aref in src.get("x_mitre_analytic_refs", []):
        for ls in by_id.get(aref, {}).get("x_mitre_log_source_references", []):
            out.append(comp_names.get(ls.get("x_mitre_data_component_ref")))
    return out


for o in objs:
    if o.get("type") == "relationship" and o.get("relationship_type") == "detects" and not o.get("revoked"):
        tgt = by_id.get(o["target_ref"], {})
        ext = next((r["external_id"] for r in tgt.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if ext in techs:
            techs[ext]["d"].extend(c for c in comps_for(by_id.get(o["source_ref"], {})) if c)
for t in techs.values():
    t["d"] = sorted(set(t["d"]))
out = {"source": "MITRE ATT&CK Enterprise", "version": version, "techniques": techs, "retired": retired}
p = Path(__file__).resolve().parents[1] / "actaeon" / "hunt" / "attack_data.json"
p.write_text(json.dumps(out, separators=(",", ":"), sort_keys=True), encoding="utf-8")
print(f"{len(techs)} techniques, {len(retired)} retired, version {version} -> {p} ({p.stat().st_size} bytes)")
