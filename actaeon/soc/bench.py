"""Scored alert-triage benchmark.

Two modes:

* ``actaeon triage-bench [--offline] [--dir DIR]``: the five labelled cases of the demo story. ``--offline``
  uses the scripted provider and so checks the pipeline, not a model. With ``--dir``, the first run
  writes DIR/config.yaml; set the model roles there and run it again to score a model.
* ``actaeon triage-bench --cases FILE``: your own labelled alerts, triaged with the CURRENT
  configuration (connectors, models) in a scratch case store, so the live queue is not touched::

      cases:
        - name: implant in /dev/shm
          expect: true_positive            # or a list: [benign, false_positive]
          alerts: [ {...raw alert JSON...}, ... ]

A case passes when its verdict is the expected one (or in the expected list). An expected
``needs_analyst`` also passes when the case ends in the needs_analyst state for any reason.

Scores: correct, recall on true positives, precision (true_positive verdicts that were expected),
hand-overs (needs_analyst or logs_missing), wrong closures (a true positive called false_positive or
benign: the dangerous kind of miss), evidence coverage (share of findings that cite a successful
tool call), tokens and time.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from statistics import median


def _row(name: str, expected, c: dict) -> dict:
    exp = [expected] if isinstance(expected, str) else list(expected)
    r = c.get("report") or {}
    u = c.get("usage") or {}
    findings = r.get("findings") or []
    ok = c.get("verdict") in exp or ("needs_analyst" in exp and c.get("status") == "needs_analyst")
    return {"name": name, "case": c.get("id"), "expected": "/".join(exp), "expect": exp, "verdict": c.get("verdict"),
            "status": c.get("status") or "-", "confidence": c.get("confidence") or 0, "pass": bool(ok),
            "calls": len([s for s in c.get("steps") or [] if s["kind"] == "call"]),
            "findings": len(findings), "cited": sum(1 for f in findings if f.get("evidence")),
            "tokens": int(u.get("tokens_in", 0) or 0) + int(u.get("tokens_out", 0) or 0),
            "seconds": float(u.get("seconds", 0) or 0), "checks": r.get("checks") or [],
            "verification": (r.get("verification") or {}).get("result"), "summary": (c.get("summary") or "")[:400],
            "error": c.get("error")}


def score(rows: list[dict]) -> dict:
    tp_exp = [r for r in rows if "true_positive" in r["expect"]]
    tp_said = [r for r in rows if r["verdict"] == "true_positive"]
    found = [r for r in tp_exp if r["verdict"] == "true_positive"]
    findings = sum(r["findings"] for r in rows)
    secs = [r["seconds"] for r in rows if r["seconds"]]
    return {
        "passed": sum(r["pass"] for r in rows), "total": len(rows),
        "tp_found": len(found), "tp_total": len(tp_exp),
        "recall": round(len(found) / len(tp_exp), 2) if tp_exp else None,
        "false_alarms": len([r for r in tp_said if "true_positive" not in r["expect"]]),
        "precision": round(len([r for r in tp_said if "true_positive" in r["expect"]]) / len(tp_said), 2) if tp_said else None,
        "handed_over": len([r for r in rows if r["verdict"] in ("needs_analyst", "logs_missing")
                            or r["status"] == "needs_analyst"]),
        "wrong_closures": len([r for r in tp_exp if r["verdict"] in ("false_positive", "benign")
                               and r["status"] != "needs_analyst"]),
        "evidence_coverage": round(sum(r["cited"] for r in rows) / findings, 2) if findings else None,
        "tokens": sum(r["tokens"] for r in rows),
        "median_seconds": round(median(secs)) if secs else 0,
    }


def models_used(rows: list[dict] | None = None) -> dict[str, str]:
    """provider/model per role, from the current configuration ("rules" when no model is used)."""
    from ..config import LLM_ROLES, get_config
    cfg = get_config()
    if cfg.soc.analysis == "rules":
        return {role: "rules (no model)" for role in LLM_ROLES}
    out = {}
    for role in LLM_ROLES:
        rc = cfg.role_cfg(role)
        prov = rc.get("provider", "ollama")
        model = rc.get("model") or ((cfg.llm.get("providers") or {}).get(prov) or {}).get("default_model", "")
        out[role] = f"{prov}/{model}" if model else prov
    return out


def record(res: dict, path: Path, *, label: str = "") -> dict:
    """Append one run to a JSON-lines file of results (for the suitability table)."""
    import json

    from .util import iso
    row = {"date": iso()[:10], "label": label or res.get("file") or "demo cases", "models": res.get("models") or {},
           "cases": res["score"]["total"], **{k: res["score"][k] for k in res["score"]}}
    with Path(path).open("a") as f:
        f.write(json.dumps(row) + "\n")
    return row


def table(path: Path) -> str:
    """Markdown table of recorded runs, one row per run; providers with no run read "not measured"."""
    import json

    from ..config import PROVIDERS
    rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()] if Path(path).exists() else []
    head = ("| Date | Cases | Models (planner / analyst) | Correct | Recall | Precision | Handed to analyst | "
            "Wrong closures | Evidence coverage | Tokens | Median s/case |\n|---|---|---|---|---|---|---|---|---|---|---|")
    lines = [head]
    seen = set()
    for r in rows:
        m = r.get("models") or {}
        seen |= {str(v).split("/")[0] for v in m.values()}
        cell = lambda v: "not measured" if v is None else v  # noqa: E731
        lines.append(f"| {r['date']} | {r['label']} ({r['cases']}) | {m.get('planner', '?')} / {m.get('analyst', '?')} | "
                     f"{r['passed']}/{r['total']} | {cell(r['recall'])} | {cell(r['precision'])} | {r['handed_over']} | "
                     f"{r['wrong_closures']} | {cell(r['evidence_coverage'])} | {r['tokens']} | {r['median_seconds']} |")
    missing = [p for p in PROVIDERS if p not in seen and p not in ("demo", "cli")]
    if missing:
        lines.append("")
        lines.append("Not measured: " + ", ".join(missing) + ".")
    return "\n".join(lines)


def run_bench(home: Path | None = None, *, offline: bool = False, analysis: str | None = None) -> dict:
    """The demo cases, in their own home folder."""
    from ..demo.data import EXPECTED
    from ..demo.setup import init_demo
    home = home or Path(tempfile.mkdtemp(prefix="actaeon-triage-bench-"))
    cfg_file = home / "config.yaml"
    old_cfg = cfg_file.read_text() if cfg_file.exists() and not offline else None
    init_demo(home, offline=offline)
    if old_cfg:   # keep the user's model settings between runs
        import yaml
        new = yaml.safe_load(cfg_file.read_text())
        new["llm"] = (yaml.safe_load(old_cfg) or {}).get("llm") or new["llm"]
        cfg_file.write_text(yaml.safe_dump(new, sort_keys=False))
    for f in (home / "data").glob("soc.sqlite*") if (home / "data").exists() else []:
        f.unlink()
    os.environ["ACTAEON_HOME"] = str(home)
    os.environ.pop("ACTAEON_CONFIG", None)
    from .. import config as _c
    from ..connectors import hub as _hub
    from ..providers import get_llm
    _c._CONFIG, _hub._HUB = None, None
    get_llm(reload=True)
    cwd = os.getcwd()
    os.chdir(home)
    try:
        cfg = _c.get_config(reload=True)
        if analysis:
            cfg.soc.analysis = analysis
        from .intake import poll_source
        from .service import store_for, triage_case
        store = store_for(cfg)
        src = cfg.soc.intake.sources[0]
        poll_source(cfg, store, _hub.get_hub(cfg), src)
        for c in store.cases(status="new", limit=50):
            triage_case(cfg, c["id"], actor="bench", manual=True)
        rows = []
        for alert_id, expected in EXPECTED.items():
            a = store.get_alert(f"{src['name']}:{alert_id}") or {}
            rows.append(_row(alert_id, expected, store.get_case(a.get("case_id") or "") or {}))
        _hub.get_hub().close()
    finally:
        os.chdir(cwd)
    return {"home": str(home), "cases": rows, "score": score(rows), "models": models_used()}


def run_cases(path: Path, *, cfg=None, llm=None, hub=None, analysis: str | None = None) -> dict:
    """Labelled alerts from a YAML file, triaged with the current configuration in a scratch store."""
    import yaml

    from .intake import ingest
    from .service import triage_case
    from .store import SocStore
    doc = yaml.safe_load(Path(path).read_text()) or {}
    cases = doc.get("cases") or []
    if not cases:
        raise ValueError(f"{path}: no cases")
    if cfg is None:
        from ..config import get_config
        cfg = get_config()
    if analysis:
        cfg.soc.analysis = analysis
    rows = []
    with tempfile.TemporaryDirectory(prefix="actaeon-triage-bench-") as tmp:
        for i, case in enumerate(cases):
            if not case.get("alerts") or not case.get("expect"):
                raise ValueError(f"{path}: case {i + 1} needs alerts and expect")
            # one throw-away SQLite store per case: nothing groups across cases, and with PostgreSQL nothing
            # reaches the live tables
            store = SocStore(Path(tmp) / f"case{i}.sqlite", scratch=True)
            out = ingest(cfg, store, list(case["alerts"]), source=str(case.get("source") or "bench"))
            ids = out["cases_opened"]
            if not ids:
                rows.append({**_row(str(case.get("name") or i + 1), case["expect"], {}), "error": f"no case opened: {out}"})
                continue
            c = triage_case(cfg, ids[0], actor="bench", manual=True, store=store, llm=llm, hub=hub)
            rows.append(_row(str(case.get("name") or i + 1), case["expect"], c))
    if hub is None:
        from ..connectors import get_hub
        get_hub().close()
    return {"file": str(path), "cases": rows, "score": score(rows), "models": models_used()}
