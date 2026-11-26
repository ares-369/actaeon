"""Rule regression check: run a folder of labelled evidence (attack samples, your own recorded tests) through
the investigation analyzers with the current rules, and compare which rules match each file with a saved
baseline. A rule that matched before and does not now is a regression (exit code 1 on the command line).

    actaeon rules regress SAMPLES/ --baseline rules-baseline.json --update   # record the baseline once
    actaeon rules regress SAMPLES/ --baseline rules-baseline.json            # after every rule change

The run uses a throw-away SQLite store, never the real cases.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path


def run(cfg, corpus: Path) -> dict[str, dict[str, dict]]:
    from ..dfir.analyze import run_all
    from ..dfir.config import of
    from ..dfir.service import import_file
    from ..dfir.store import DfirStore
    corpus = Path(corpus)
    files = sorted(p for p in corpus.rglob("*") if p.is_file()) if corpus.is_dir() else [corpus]
    out: dict[str, dict[str, dict]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        st = DfirStore(Path(tmp) / "regress.sqlite", scratch=True)
        for f in files:
            rel = str(f.relative_to(corpus)) if corpus.is_dir() else f.name
            cid = st.create_case(rel, "", actor="regress")["id"]
            try:
                r = import_file(cfg, cid, f, f.name, actor="regress", store=st)
            except Exception as exc:                   # an unreadable sample is reported, not fatal
                out[rel] = {"_error": {"title": str(exc)[:200], "n": 0}}
                continue
            if r.get("status") == "failed":
                out[rel] = {"_error": {"title": r.get("note", "failed")[:200], "n": 0}}
                continue
            run_all(cfg, of(cfg), st, cid)
            out[rel] = {d["rule_key"]: {"title": d["title"], "n": int(d["n"])} for d in st.detection_summary(cid)
                        if d["origin"] != "analyzer"}
    return out


def compare(baseline: dict, now: dict) -> dict:
    lost, fewer, new = [], [], []
    for f, rules in baseline.items():
        cur = now.get(f)
        if cur is None:
            continue
        for k, v in rules.items():
            if k == "_error":
                continue
            if k not in cur:
                lost.append({"file": f, "rule": v["title"], "rule_key": k, "was": v["n"]})
            elif cur[k]["n"] < v["n"]:
                fewer.append({"file": f, "rule": v["title"], "was": v["n"], "now": cur[k]["n"]})
    for f, rules in now.items():
        for k, v in rules.items():
            if k != "_error" and k not in (baseline.get(f) or {}):
                new.append({"file": f, "rule": v["title"], "now": v["n"]})
    missing = sorted(set(baseline) - set(now))
    return {"lost": lost, "fewer": fewer, "new": new, "missing_files": missing,
            "errors": {f: r["_error"]["title"] for f, r in now.items() if "_error" in r}, "ok": not lost}


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else {}
