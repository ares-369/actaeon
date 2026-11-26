"""Rule library operations shared by the web API, the CLI and the MCP server."""

from __future__ import annotations

import io
import json
import re
import uuid
import zipfile
from typing import Any

import yaml

from ..access import can_see
from ..connectors.untrusted import SYSTEM_RULE
from ..hunt.jsonparse import first_object
from .config import of
from .lint import lint
from .store import RuleStore, detection_fingerprint, meta
from .testing import events_from_result, ready_problems, run

MAX_SIGMA = 50_000
MAX_CONTEXT = 6_000


def store_for(cfg) -> RuleStore:
    return RuleStore(cfg.data_dir / "hunts.sqlite")


def visible(rule: dict | None) -> bool:
    return bool(rule) and can_see(rule.get("restricted") or [])


def known_fields(cfg, limit_steps: int = 400) -> set[str]:
    """Lower-case field names (full and last part) seen in stored hunt and triage results and in rule tests."""
    from .. import db
    out: set[str] = set()

    def add(ev: dict) -> None:
        from .sigma_eval import flatten
        for k in flatten(ev):
            out.add(k.lower())
            out.add(k.rsplit(".", 1)[-1].lower())
    paths = [(cfg.data_dir / "hunts.sqlite", "SELECT result FROM steps WHERE kind='call' AND ok=1 "
              "AND tool NOT IN ('get_fields','list_indices','count') ORDER BY id DESC LIMIT ?"),
             (cfg.data_dir / "soc.sqlite", "SELECT result FROM soc_steps WHERE kind='call' AND ok=1 "
              "ORDER BY ts DESC LIMIT ?")]
    for path, sql in paths:
        if not db.is_pg() and not path.exists():
            continue
        try:
            with db.connect(path) as c:
                for r in c.execute(sql, (limit_steps,)):
                    for ev in events_from_result(r["result"] or "", limit=20):
                        add(ev)
        except Exception:
            continue          # the table may not exist yet
    st = store_for(cfg)
    with st._conn() as c:
        for r in c.execute("SELECT event FROM rules_tests WHERE origin='real' ORDER BY id DESC LIMIT 500"):
            try:
                add(json.loads(r["event"]))
            except ValueError:
                pass
    return out


def normalise(sigma: str, attack: list[str] | None = None) -> tuple[str, list[str]]:
    from ..hunt.detection import check_sigma
    if len(sigma) > MAX_SIGMA:
        return sigma, [f"a rule is limited to {MAX_SIGMA} characters"]
    text, problems = check_sigma(sigma, attack or [])
    if problems:
        return text, problems
    doc = yaml.safe_load(text)                   # one key order, so the same rule always reads the same
    first = [k for k in ("title", "id", "status", "description") if k in doc]
    return yaml.safe_dump({**{k: doc[k] for k in first}, **{k: v for k, v in doc.items() if k not in first}},
                          sort_keys=False, allow_unicode=True), []


def _lint(cfg, st: RuleStore, rule_id: str, sigma: str, fields: set[str] | None = None) -> list[dict]:
    dups = [x for x in st.by_fingerprint(detection_fingerprint(sigma)) if x != rule_id]
    return lint(sigma, known_fields=fields, field_map=of(cfg).field_map, duplicates=dups)


def create(cfg, sigma: str, *, actor: str, source: dict | None = None, notes: str = "",
           restricted: list[str] | None = None, attack: list[str] | None = None) -> dict:
    text, problems = normalise(sigma, attack)
    if problems:
        raise ValueError("; ".join(problems))
    rid = meta(text)["id"] or str(uuid.uuid4())
    st = store_for(cfg)
    return st.create(rid, text, actor=actor, source=source or {"kind": "manual"}, notes=notes, restricted=restricted)


def edit(cfg, rule_id: str, sigma: str, *, actor: str, note: str = "") -> dict:
    st = store_for(cfg)
    r = st.get(rule_id)
    if not visible(r):
        raise KeyError(rule_id)
    try:
        doc = yaml.safe_load(sigma)
    except yaml.YAMLError:
        doc = None
    if isinstance(doc, dict):                    # keep the rule's id when the edited text leaves it out
        if doc.get("id") and str(doc["id"]) != rule_id:
            raise ValueError("the rule id in the YAML cannot change; create a new rule instead")
        sigma = yaml.safe_dump({"id": rule_id, **{k: v for k, v in doc.items() if k != "id"}}, sort_keys=False,
                               allow_unicode=True)
    text, problems = normalise(sigma, r["attack"])
    if problems:
        raise ValueError("; ".join(problems))
    return st.update_sigma(rule_id, text, actor=actor, note=note)


def run_tests(cfg, rule_id: str, *, actor: str) -> dict:
    st = store_for(cfg)
    r = st.get(rule_id)
    if not visible(r):
        raise KeyError(rule_id)
    res = run(r, st.tests(rule_id), of(cfg).field_map)
    st.save_run(rule_id, r["version"], res, actor=actor)
    return res


def detail(cfg, rule_id: str, *, actor: str) -> dict | None:
    st = store_for(cfg)
    r = st.get(rule_id)
    if not visible(r):
        return None
    tests = st.tests(rule_id)
    last = st.last_run(rule_id)
    lt = _lint(cfg, st, rule_id, r["sigma"], known_fields(cfg))
    r.update(tests=tests, versions=st.versions(rule_id), last_run_full=last, lint=lt,
             ready_problems=ready_problems(cfg, r, tests, last, lt, actor))
    return r


ACTIONS = {"submit": ("draft",), "approve": ("testing",), "retire": ("draft", "testing", "ready"),
           "reopen": ("retired",), "back": ("testing", "ready")}


def change_status(cfg, rule_id: str, action: str, *, actor: str) -> dict:
    st = store_for(cfg)
    r = st.get(rule_id)
    if not visible(r):
        raise KeyError(rule_id)
    if action not in ACTIONS:
        raise ValueError(f"action must be one of {sorted(ACTIONS)}")
    if r["status"] not in ACTIONS[action]:
        raise ValueError(f"cannot {action} a rule that is {r['status']}")
    if action == "approve":
        d = detail(cfg, rule_id, actor=actor)
        if d["ready_problems"]:
            raise ValueError("not ready: " + "; ".join(d["ready_problems"]))
        return st.set_status(rule_id, "ready", actor=actor)
    new = {"submit": "testing", "retire": "retired", "reopen": "draft", "back": "draft"}[action]
    return st.set_status(rule_id, new, actor=actor)


def add_test(cfg, rule_id: str, *, name: str, expect: str, event: Any, origin: str, actor: str,
             source: str = "") -> list[dict]:
    st = store_for(cfg)
    if not visible(st.get(rule_id)):
        raise KeyError(rule_id)
    events = event if isinstance(event, list) else [event]
    if not events:
        raise ValueError("send an event (a JSON object) or a list of events")
    out = []
    for i, ev in enumerate(events[:50]):
        out.append(st.add_test(rule_id, name=name if len(events) == 1 else f"{name} {i + 1}", expect=expect,
                               event=ev, origin=origin, source=source or "added by hand", actor=actor,
                               max_tests=of(cfg).max_tests))
    return out


# ---------------------------------------------------------------- from a hunt

def from_hunt(cfg, hunt: dict, *, actor: str, sigma: str = "", llm=None) -> dict:
    """Make a draft rule from a finished hunt: its saved/edited Sigma text, or a new model draft. When the hunt
    found a threat, the events behind its findings become real 'must match' tests."""
    if not sigma:
        from ..hunt.detection import draft
        d = draft(llm, hunt)
        if not d.get("valid"):
            raise ValueError("no usable rule: " + "; ".join(d.get("problems") or ["the model returned nothing"]))
        sigma = d["sigma"]
    from ..hunt.attack_names import check
    v = hunt.get("verdict") or {}
    attack = check((v.get("attack") or []) + ((hunt.get("plan") or {}).get("attack") or []))[0]
    r = create(cfg, sigma, actor=actor, source={"kind": "hunt", "ref": hunt["id"]},
               restricted=hunt.get("restricted") or [], attack=attack,
               notes=f"From hunt {hunt['id']}: {hunt.get('hypothesis', '')}"[:600])
    if (hunt.get("outcome") or v.get("outcome")) == "threat":
        cited = [e for f in v.get("findings") or [] for e in f.get("evidence") or []]
        steps = {f"E{s['n']}": s for s in hunt.get("steps") or [] if s.get("kind") == "call" and s.get("ok")}
        added = 0
        for e in dict.fromkeys(cited):
            for ev in events_from_result((steps.get(e) or {}).get("result") or "", limit=3):
                if added >= 5:
                    break
                store_for(cfg).add_test(r["id"], name=f"hunt evidence {e}", expect="match", event=ev, origin="real",
                                        source=f"hunt {hunt['id']} {e}", actor=actor,
                                        max_tests=of(cfg).max_tests)
                added += 1
        if added:
            run_tests(cfg, r["id"], actor=actor)
    return store_for(cfg).get(r["id"])


# ---------------------------------------------------------------- coverage

def coverage(cfg) -> dict:
    """Which ATT&CK techniques your rules cover, and which ones you have reason to want covered."""
    from ..hunt.attack_names import info
    from ..hunt.service import store_for as hunt_store
    rows: dict[str, dict] = {}

    def row(t: str) -> dict:
        if t not in rows:
            i = info(t)
            rows[t] = {"technique": t, "name": i.get("n", ""), "tactics": i.get("t", []), "ready": 0, "testing": 0,
                       "draft": 0, "rules": [], "reasons": []}
        return rows[t]
    for r in store_for(cfg).list(limit=5000):
        if r["status"] == "retired" or not visible(r):
            continue
        for t in r["attack"]:
            x = row(t)
            x[r["status"]] += 1
            x["rules"].append({"id": r["id"], "title": r["title"], "status": r["status"]})
    for h in hunt_store(cfg).list(limit=2000):
        techs = set(((h.get("verdict") or {}).get("attack") or []) + ((h.get("plan") or {}).get("attack") or []))
        for t in techs:
            if not re.match(r"^T\d{4}(\.\d{3})?$", str(t)):
                continue
            reason = {"threat": "a hunt found a threat", "telemetry_found_benign": "hunted: data exists"}.get(
                h.get("outcome") or "")
            if reason and reason not in row(t)["reasons"]:
                row(t)["reasons"].append(reason)
    try:
        from ..soc.service import store_for as soc_store
        for c in soc_store(cfg).cases(verdict="true_positive", limit=1000):
            if not can_see(c.get("restricted") or []):
                continue
            for t in c.get("attack") or []:
                if re.match(r"^T\d{4}(\.\d{3})?$", str(t)) and "a true-positive case" not in row(t)["reasons"]:
                    row(t)["reasons"].append("a true-positive case")
    except Exception:
        pass
    for t in of(cfg).priorities:
        row(t)["reasons"].append("on your priority list")
    for x in rows.values():
        x["gap"] = bool(x["reasons"]) and x["ready"] == 0
        weight = {"on your priority list": 3, "a true-positive case": 3, "a hunt found a threat": 3,
                  "hunted: data exists": 1}
        x["score"] = sum(weight.get(r, 1) for r in x["reasons"]) if x["gap"] else 0
    out = sorted(rows.values(), key=lambda x: (-x["score"], -x["ready"], x["technique"]))
    return {"techniques": out, "ready": sum(1 for x in out if x["ready"]), "gaps": sum(1 for x in out if x["gap"]),
            "note": "Covered means at least one rule marked ready is tagged with the technique. It does not prove "
                    "every way of doing the technique is caught."}


# ---------------------------------------------------------------- draft for a technique

GAP_SYSTEM = f"""You write ONE Sigma detection rule (YAML) for an ATT&CK technique, for the organisation described.
Prefer field names from fields_seen (the fields that exist in their data); otherwise use the standard Sigma field
names for the logsource. Detect the behaviour, not one tool's file name, and keep it specific enough to avoid
noise. Reply with ONE JSON object:
{{"sigma": "<complete Sigma YAML as a string>", "notes": "one or two sentences on tuning and known gaps",
  "match_samples": [<up to 3 example events (JSON objects) the rule must catch>],
  "no_match_samples": [<up to 3 similar but legitimate events it must not catch>]}}
The rule must have: title, description, logsource, detection (selections and a condition), level,
tags (attack.tXXXX), falsepositives. Example events use the same field names as the rule.
{SYSTEM_RULE}"""


def _threat_examples(cfg, technique: str, limit: int = 3) -> list[dict]:
    from ..hunt.service import store_for as hunt_store
    hs = hunt_store(cfg)
    out: list[dict] = []
    for h in hs.list(limit=300):
        v = h.get("verdict") or {}
        if h.get("outcome") != "threat" or technique not in (v.get("attack") or []):
            continue
        full = hs.get(h["id"]) or {}
        cited = {e for f in v.get("findings") or [] for e in f.get("evidence") or []}
        for s in full.get("steps") or []:
            if f"E{s['n']}" in cited and s.get("kind") == "call":
                for ev in events_from_result(s.get("result") or "", limit=1):
                    out.append({k: (str(x)[:300] if isinstance(x, str) else x) for k, x in list(ev.items())[:40]})
            if len(out) >= limit:
                return out
    return out


def draft_for_technique(cfg, llm, technique: str, *, actor: str, context: str = "") -> dict:
    from ..hunt.attack_names import check, info
    ok = check([technique])[0]
    if not ok:
        raise ValueError(f"{technique} is not a known ATT&CK technique id")
    technique = ok[0]
    if llm is None:
        raise ValueError("drafting needs a model; none is configured")
    i = info(technique)
    fields = sorted(f for f in known_fields(cfg) if "." not in f)[:150]
    existing = [r["title"] for r in store_for(cfg).list(technique=technique, limit=20) if r["status"] != "retired"]
    facts = {"technique": technique, "name": i.get("n", ""), "tactics": i.get("t", []),
             "data_components": i.get("d", []), "platforms": i.get("p", []),
             "environment": (cfg.raw.get("environment") or {}), "fields_seen": fields,
             "events_from_hunts_that_found_this": _threat_examples(cfg, technique),
             "rules_you_already_have_for_it": existing, "analyst_context": (context or "")[:MAX_CONTEXT]}
    res = llm.for_role("reporter").chat([{"role": "system", "content": GAP_SYSTEM},
                                         {"role": "user", "content": json.dumps(facts, default=str)}],
                                        max_tokens=2500)
    if res.error:
        raise ValueError(f"the model call failed: {res.error[:300]}")
    obj = first_object(res.text or "")
    if not obj or not isinstance(obj.get("sigma"), str):
        raise ValueError("the model did not return a rule")
    r = create(cfg, obj["sigma"], actor=actor, attack=[technique],
               source={"kind": "gap", "ref": technique, "model": True},
               notes=("Model draft. " + str(obj.get("notes", "")))[:600])
    if of(cfg).draft_samples:
        st = store_for(cfg)
        for key, expect in (("match_samples", "match"), ("no_match_samples", "no_match")):
            for n, ev in enumerate([e for e in obj.get(key) or [] if isinstance(e, dict) and e][:3]):
                st.add_test(r["id"], name=f"model example {n + 1}", expect=expect, event=ev, origin="synthetic",
                            source="written by the model with the draft", actor=actor,
                            max_tests=of(cfg).max_tests)
        run_tests(cfg, r["id"], actor=actor)
    return store_for(cfg).get(r["id"])


# ---------------------------------------------------------------- import / export

def slug(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (title or "rule").lower()).strip("_")
    return s[:60] or "rule"


def import_text(cfg, text: str, *, actor: str, source: str = "import") -> dict:
    """One or more Sigma rules (YAML documents). New ids become drafts; known ids get a new version."""
    st = store_for(cfg)
    out = {"created": [], "updated": [], "unchanged": [], "errors": []}
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        out["errors"].append(f"{source}: not valid YAML: {exc}"[:300])
        return out
    for d in docs:
        if not isinstance(d, dict) or "detection" not in d:
            out["errors"].append(f"{source}: skipped a document that is not a single-event rule")
            continue
        body = yaml.safe_dump(d, sort_keys=False, allow_unicode=True)
        rid = str(d.get("id") or "")
        try:
            old = st.get(rid) if rid else None
            if old:
                new = edit(cfg, rid, body, actor=actor, note=f"imported from {source}")
                out["updated" if new["version"] != old["version"] else "unchanged"].append(rid)
            else:
                out["created"].append(create(cfg, body, actor=actor, source={"kind": "import", "ref": source})["id"])
        except (ValueError, KeyError) as exc:
            out["errors"].append(f"{source}: {d.get('title', rid)}: {exc}"[:300])
    return out


def export_zip(cfg, statuses: tuple[str, ...] = ("ready",), *, convert: bool = True) -> bytes:
    """A zip of the rules (Sigma YAML), their tests and, where connectors have a sigma: block, the converted
    queries. Nothing is sent anywhere."""
    st = store_for(cfg)
    tgts = []
    if convert:
        from ..hunt.sigma_convert import targets
        try:
            tgts = targets(cfg)
        except Exception:
            tgts = []
    buf = io.BytesIO()
    index = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for r in st.all_full():
            if r["status"] not in statuses or not visible(r):
                continue
            base = f"{r['status']}/{slug(r['title'])}_{r['id'][:8]}"
            z.writestr(base + ".yml", r["sigma"])
            tests = [{k: t[k] for k in ("name", "expect", "origin", "event", "source")} for t in st.tests(r["id"])]
            z.writestr(base + ".tests.json", json.dumps(tests, indent=1, default=str))
            if tgts:
                from ..hunt.sigma_convert import convert_for
                for row in convert_for(r["sigma"], tgts):
                    if row.get("queries"):
                        z.writestr(f"{base}.{row['connector']}.txt",
                                   "\n".join(q if isinstance(q, str) else json.dumps(q) for q in row["queries"]))
            index.append(f"{r['status']:8} v{r['version']:<3} {r['id']}  {r['title']}"
                         f"  [{', '.join(r['attack'])}]  approved by {r.get('approved_by') or '-'}")
        z.writestr("INDEX.txt", "Exported rules (review before deploying):\n" + "\n".join(index) + "\n")
    return buf.getvalue()


_compiled: dict[tuple, list] = {}


def compiled_rules(cfg, statuses: list[str]) -> list:
    """Library rules with these statuses, compiled for matching events (actaeon.dfir.analyze.Rule). Rules the
    local matcher cannot evaluate are left out. Cached until a rule changes."""
    if not statuses or not of(cfg).enabled:
        return []
    from ..dfir.analyze import Rule
    from .sigma_eval import Unsupported
    rows = [r for r in store_for(cfg).all_full() if r["status"] in statuses]
    key = (tuple(statuses), tuple(sorted((r["id"], r["version"]) for r in rows)))
    if key in _compiled:
        return _compiled[key]
    out = []
    for r in rows:
        try:
            out.append(Rule(f"library:{r['id']}", yaml.safe_load(r["sigma"]), "library"))
        except (Unsupported, yaml.YAMLError, TypeError):
            continue
    _compiled.clear()
    _compiled[key] = out
    return out
