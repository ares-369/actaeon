"""Why did questions fail? Sort every miss of an ExCyTIn run by cause, from its stored tool calls.

    python benchmarks/excytin/analyze.py --results excytin-results.json --questions DIR/questions/test \\
        [--traces '/tmp/excytin-*'] [--max-calls 25] [--markdown]

For each question with reward < 1, the cause is decided from facts in the trace, not by a model:

  service error      the model service failed (quota, rate limit, outage, timeout); says nothing about
                     the hunting, and a rerun should not count it
  malformed call     the model produced a tool call the provider rejected; a real model failure
  out of calls       the question used every allowed tool call
  never retrieved    the expected answer appears in no successful tool result: the searches did not
                     reach the evidence (query planning, wrong table or filter, or a pivot not taken)
  retrieved, missed  the expected answer was in a tool result, but the final answer was wrong: the
                     model saw the evidence and did not connect it (reasoning, correlation)

"Retrieved" means the whole expected value appears as a token in a successful result. Values that can
appear by chance (short numbers, SYSTEM, common process names) are reported as weak matches: the
value was seen, but maybe not in the place that answers the question. "out of calls" is also split
into retrieved / never retrieved. Results written by run.py now carry the
trace folder; for older results the trace is found by the question text (the newest one written before
the results file).
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sqlite3
from collections import Counter
from pathlib import Path

_SERVICE = re.compile(r"(?i)\b(429|503|500|502|504)\b|resource_exhausted|quota|rate.?limit|unavailable|timed? ?out|"
                      r"timeout|overloaded|connection")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s)).strip().lower()


def _appears(value: str, text: str) -> bool:
    """The whole value appears as a token (not inside a longer word or number)."""
    v = _norm(value)
    return bool(v) and re.search(r"(?<![\w.@-])" + re.escape(v) + r"(?![\w@-])", _norm(text)) is not None


_COMMON = {"system", "powershell.exe", "cmd.exe", "schtasks.exe", "rundll32.exe", "administrator", "true", "false"}


def _weak(value: str) -> bool:
    """A value that can appear in logs by chance (short numbers, common process or account names)."""
    v = _norm(value)
    return len(v) < 6 or v.isdigit() or v in _COMMON


def load_questions(qdir: str) -> dict[tuple[str, int], dict]:
    out = {}
    for f in sorted(Path(qdir).glob("incident_*_qa*.json")):
        inc = "_".join(f.name.split("_")[:2])
        for i, q in enumerate(json.loads(f.read_text(encoding="utf-8"))):
            out[(inc, i)] = q
    return out


def index_traces(pattern: str, before: float) -> dict[str, str]:
    """question text (first 200 chars) -> newest trace folder written before ``before``."""
    best: dict[str, tuple[float, str]] = {}
    for db in glob.glob(os.path.join(pattern, "hunts.sqlite")):
        mtime = os.path.getmtime(db)
        if mtime > before:
            continue
        try:
            from actaeon import db as store_db
            with store_db.connect(db) as c:
                row = c.execute("SELECT hypothesis FROM hunts LIMIT 1").fetchone()
        except sqlite3.Error:
            continue
        if row and (row[0] not in best or best[row[0]][0] < mtime):
            best[row[0]] = (mtime, os.path.dirname(db))
    return {k: v[1] for k, v in best.items()}


def trace_text(folder: str) -> tuple[str, int, int]:
    """(text of every successful tool result, successful calls, failed calls)."""
    from actaeon import db  # the same storage the runner wrote with (SQLite, or PostgreSQL if configured)
    with db.connect(os.path.join(folder, "hunts.sqlite")) as c:
        rows = c.execute("SELECT ok, result FROM steps WHERE kind='call'").fetchall()
    good = [r[1] or "" for r in rows if r[0]]
    return "\n".join(good), len(good), len(rows) - len(good)


def classify(r: dict, q: dict, folder: str | None, max_calls: int) -> dict:
    out = {"incident": r["incident"], "index": r["index"], "reward": r["reward"], "calls": r.get("calls", 0)}
    if r.get("error"):
        out["cause"] = "service error" if _SERVICE.search(r["error"]) else (
            "malformed call" if "MALFORMED" in r["error"] else "other error")
        out["error"] = r["error"][:160]
        return out
    if not folder:
        out["cause"] = "no trace"
        return out
    text, ok, failed = trace_text(folder)
    out.update(ok_calls=ok, failed_calls=failed)
    seen = _appears(str(q["answer"]), text)
    out["weak_match"] = bool(seen and _weak(str(q["answer"])))
    if r.get("calls", 0) >= max_calls:
        out["cause"] = "out of calls (retrieved)" if seen else "out of calls (never retrieved)"
    else:
        out["cause"] = "retrieved, missed" if seen else "never retrieved"
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--questions", required=True)
    ap.add_argument("--traces", default="/tmp/excytin-*")
    ap.add_argument("--max-calls", type=int, default=25)
    ap.add_argument("--markdown", action="store_true")
    a = ap.parse_args()
    results = json.loads(Path(a.results).read_text())["results"]
    qs = load_questions(a.questions)
    by_text = index_traces(a.traces, os.path.getmtime(a.results) + 1)
    rows = []
    for r in results:
        if r["reward"] >= 1:
            continue
        q = qs[(r["incident"], r["index"])]
        folder = r.get("trace") or by_text.get(q["question"][:200])
        rows.append(classify(r, q, folder, a.max_calls))
    causes = Counter(x["cause"] for x in rows)
    weak = Counter(x["cause"] for x in rows if x.get("weak_match"))
    partial = sum(1 for x in rows if 0 < x["reward"] < 1)
    failed_calls = sum(x.get("failed_calls", 0) for x in rows)
    all_calls = failed_calls + sum(x.get("ok_calls", 0) for x in rows)
    service = [x for x in rows if x["cause"] == "service error"]
    scored = [r for r in results if not (r.get("error") and _SERVICE.search(r["error"]))]
    summary = {"questions": len(results), "missed": len(rows), "partial_credit": partial,
               "weak_matches": dict(weak),
               "without_service_errors": {"questions": len(scored),
                                          "mean_reward": round(sum(r["reward"] for r in scored) / max(1, len(scored)), 3),
                                          "fully_correct": sum(1 for r in scored if r["reward"] >= 1)},
               "causes": dict(causes.most_common()),
               "failed_tool_calls_in_misses": f"{failed_calls}/{all_calls}"}
    if a.markdown:
        print("| Cause | Questions | of which a weak match |\n|---|---|---|")
        for k, v in causes.most_common():
            print(f"| {k} | {v} | {weak.get(k, '') if 'retrieved' in k and 'never' not in k else ''} |")
        w = summary["without_service_errors"]
        print(f"\n{len(rows)} of {len(results)} questions missed ({partial} with partial credit); "
              f"{failed_calls} of {all_calls} tool calls in the missed questions failed. Leaving out the "
              f"{len(service)} service errors: mean reward {w['mean_reward']} over {w['questions']} questions, "
              f"{w['fully_correct']} fully correct.")
    else:
        print(json.dumps({"summary": summary, "misses": rows}, indent=1))


if __name__ == "__main__":
    main()
