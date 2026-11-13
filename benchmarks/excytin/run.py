"""Run Actaeon on ExCyTIn-Bench questions and score it with the benchmark's grading rules.

Usage:
  ACTAEON_HOME=<home with model config> python run.py --db-dir <sqlite dir> --questions <questions/test>
      [--incident incident_38 ...] [--per-incident N] [--max-calls 25] [--seed 0] [--out results.json]

Each question is answered by Actaeon's read-only tool loop over one SQL connector (the
incident's SQLite file, via `actaeon bridge sql`). Answers are graded with the benchmark's
published judge prompts (fuzzy answer check, then step-wise partial credit with discount 0.4),
using the configured `reporter` model as the judge. The judge model differs from the paper's,
so treat scores as indicative, not as a leaderboard entry.

ExCyTIn-Bench: https://github.com/microsoft/SecRL (MIT). Judge prompts below are copied from
secgym/evaluator.py and keep that project's license.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import tempfile
import time
from pathlib import Path

ANSWER_SYSTEM = """You are a security analyst investigating an incident. You can query the incident's logs with
read-only SQL tools. Work step by step: list tables, describe the ones you need, then query. Each tool
result is labelled E1, E2, ...

Reply with exactly ONE JSON object per turn, either a tool call:
{"action": "call", "connector": "<connector>", "tool": "<tool>", "arguments": {...}, "thought": "<why>"}
or your final answer:
{"action": "answer", "answer": "<the specific value(s) asked for>", "evidence": ["E3"]}

Answer with the exact value the question asks for (a name, IP, hash, time, count...). Do not list many
candidates. If you cannot find it, give your best supported answer.

Tools:
{tools}"""

FUZZY_ANSWER_CHECK_PROMPT = """Given a golden answer to a security question and a submitted answer, please evaluate whether the submitted answer matches the golden answer.
You are given:
- The question
- The golden answer
- The submitted answer

Note:
The submitted answer does not need to match the golden answer exactly. But the key content should be present.
If the submitted answer presents the golden answer along with additional context, it should be considered correct.
If the submitted answer is an overly large enumeration (>15 is the strict limit) that includes the golden answer and lacks relevance, it should be considered false. All enumerations less than 10 and containing the golden answer should be considered correct. Between 10 and 15, use your discretion to determine if the answer is relevant enough to be considered correct.
If the format of the submitted answer is different from the golden answer but the meaning is the same, it should be considered as true. Ignore the case of the text.
For time-based questions, the submitted answer should be within a reasonable time frame of the golden answer and the format of the timestamps is not required to match exactly.
For domain-specific questions, the submitted answer should contain the key information mentioned in the golden answer. Ignore differences in http/https, www, and trailing slashes in URLs.
In case you find discrepancies between the question and the golden answer, please consider the golden answer as the ground truth as you do not have full context of the question.

First give a brief analysis using 1-2 short sentences, then give your decision.
Follow this format:
Analysis: <your analysis>
Is_Answer_Correct: <"True" or "False">
"""

STEP_CHECK_PROMPT = """Given a security question, a submitted answer, and a ground truth solution, please evaluate the correctness of the submitted answer.
The ground truth solution may contain several steps. Please go through each step of the ground truth solution and evaluate whether the given answer correctly contains key info (the Indicator of Comprise) of that step, which is usually enclosed in `< >`.
Note:
- If the format of the submitted answer is different from the golden answer but the meaning is the same, it should be considered as true.
- The key information should not be the ones that is already present in the question.

Your response should be in JSON format:
{
    "<step_i>" : {
            "analysis": "<your analysis>",
            "is_step_correct": "<"True" or "False">,
        },
    ...
}
step_i is the step number from the ground truth solution, starting from 0.
For each step, you must have two fields:
- `analysis`: a quick analysis of whether this step is correct.
- `is_step_correct`: whether the answer matches the key info from this step.
"""


def full_question(q: dict) -> str:
    return f"{q.get('context', '')}\n{q['question']}".strip()


def judge(llm, q: dict, answer: str) -> dict:
    """The benchmark's reward: 1 for a correct final answer, else discounted credit for solution steps."""
    from actaeon.hunt.jsonparse import first_object
    bound = llm.for_role("reporter")
    user = f"Question: {full_question(q)}\nGolden Answer: {q['answer']}\nSubmitted Answer: {answer}"
    res = bound.chat([{"role": "system", "content": FUZZY_ANSWER_CHECK_PROMPT}, {"role": "user", "content": user}],
                     max_tokens=400)
    m = re.search(r"Is_Answer_Correct:\s*\"?(True|False)", res.text or "", re.I)
    if m and m.group(1).lower() == "true":
        return {"reward": 1.0, "correct": True, "judge": (res.text or "")[:400]}
    out = {"reward": 0.0, "correct": False, "judge": (res.text or res.error or "")[:400]}
    sol = q.get("solution")
    if not sol:
        return out
    steps = "".join(f"Step {i}: {s}\n" for i, s in enumerate(sol)) if isinstance(sol, list) else str(sol)
    res = bound.chat([{"role": "system", "content": STEP_CHECK_PROMPT},
                      {"role": "user", "content": f"Question: {full_question(q)}\nGolden Solution:\n{steps}\n"
                                                  f"Submitted Answer: {answer}"}], max_tokens=1500)
    obj = first_object(res.text or "") or {}
    evals = [str((v or {}).get("is_step_correct", "")).strip('"') for v in obj.values() if isinstance(v, dict)]
    evals.reverse()
    total, cur = 0.0, 0.4
    for b in evals[1:]:               # the last step is the final answer, already judged
        if b == "True":
            total += cur
        if total >= 1:
            total = 1.0
            break
        cur *= 0.4
    out["reward"] = round(total, 4)
    out["steps"] = evals
    return out


def answer_one(cfg, llm, db: Path, q: dict, max_calls: int, notes: str = "") -> dict:
    from actaeon.connectors.audit import AuditLog
    from actaeon.connectors.hub import ConnectorHub
    from actaeon.connectors.spec import parse_connectors
    from actaeon.hunt.store import HuntStore
    from actaeon.hunt.toolloop import available_tools, run_loop
    work = Path(tempfile.mkdtemp(prefix="excytin-"))
    spec = parse_connectors([{"name": "incident_logs", "roles": ["log_search"], "transport": "stdio",
                              "command": "actaeon", "args": ["bridge", "sql", "--url", f"sqlite:///{db}",
                                                              "--max-rows", "50"],
                              "description": "Security logs of one incident (Microsoft Sentinel / Defender style tables)",
                              "timeout_sec": 120}])
    hub = ConnectorHub(spec, AuditLog(work / "audit.sqlite"), max_result_bytes=30_000)
    store = HuntStore(work / "hunts.sqlite")
    hid = store.create(q["question"][:200], origin="excytin")
    tools = available_tools(hub)
    listing = "\n".join(f"- connector \"{t['connector']}\", tool \"{t['name']}\": {t.get('description', '')} "
                        f"args {json.dumps((t.get('inputSchema') or t.get('input_schema') or {}).get('properties', {}))}"
                        for t in tools)
    t0 = time.monotonic()
    system = ANSWER_SYSTEM.replace("{tools}", listing)
    if notes:
        system += f"\n\nNotes about this data source (written by the team):\n{notes}"
    final, _made, calls = run_loop(llm=llm, hub=hub, store=store, hid=hid, system=system,
                                   user=full_question(q), final_action="answer", max_calls=max_calls,
                                   max_results=100, actor="excytin", why_prefix="")
    final = final or {}
    ans = str(final.get("answer") or final.get("text") or final.get("error") or "")
    return {"answer": ans[:2000], "calls": calls, "seconds": round(time.monotonic() - t0, 1),
            "error": final.get("error")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db-dir", required=True)
    ap.add_argument("--questions", required=True)
    ap.add_argument("--incident", action="append", default=[])
    ap.add_argument("--per-incident", type=int, default=0, help="sample N questions per incident (0 = all)")
    ap.add_argument("--max-calls", type=int, default=25)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="excytin-results.json")
    ap.add_argument("--resume", action="store_true", help="keep results already in --out and skip those questions")
    ap.add_argument("--notes", default="", help="query notes file describing the tables (as a deployment would write)")
    a = ap.parse_args()

    from actaeon.config import get_config
    from actaeon.providers import get_llm
    cfg = get_config()
    llm = get_llm()
    rng = random.Random(a.seed)
    notes = Path(a.notes).read_text(encoding="utf-8") if a.notes else ""
    results = []
    if a.resume and Path(a.out).exists():
        results = json.loads(Path(a.out).read_text()).get("results", [])
    done = {(r["incident"], r["index"]) for r in results}
    files = sorted(Path(a.questions).glob("incident_*_qa*.json"))
    for f in files:
        inc = "_".join(f.name.split("_")[:2])
        if a.incident and inc not in a.incident:
            continue
        db = Path(a.db_dir) / f"{inc}.db"
        if not db.exists():
            print(f"{inc}: no database, skipped", file=sys.stderr)
            continue
        qs = json.loads(f.read_text(encoding="utf-8"))
        idx = list(range(len(qs)))
        if a.per_incident:
            idx = sorted(rng.sample(idx, min(a.per_incident, len(idx))))
        for i in idx:
            if (inc, i) in done:
                continue
            q = qs[i]
            r = answer_one(cfg, llm, db, q, a.max_calls, notes)
            r.update(judge(llm, q, r["answer"]))
            r.update(incident=inc, index=i, golden=q["answer"])
            results.append(r)
            print(f"{inc} q{i:<3} reward {r['reward']:.2f} calls {r['calls']:>2} {r['seconds']:>6}s  "
                  f"golden {str(q['answer'])[:40]!r} got {r['answer'][:60]!r}", flush=True)
            Path(a.out).write_text(json.dumps({"results": results, "usage": llm.usage_summary()}, indent=1))
    n = len(results)
    per_inc: dict[str, list[float]] = {}
    for r in results:
        per_inc.setdefault(r["incident"], []).append(r["reward"])
    summary = {"questions": n, "mean_reward": round(sum(r["reward"] for r in results) / max(1, n), 4),
               "exact_correct": sum(r["correct"] for r in results),
               "per_incident": {k: round(sum(v) / len(v), 4) for k, v in per_inc.items()},
               "models": {r: cfg.role_cfg(r) for r in ("analyst", "reporter")},
               "usage": llm.usage_summary()}
    Path(a.out).write_text(json.dumps({"summary": summary, "results": results}, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
