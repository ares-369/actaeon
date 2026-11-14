# Benchmarks

Actaeon includes a scored hunting benchmark (`actaeon bench`) that runs labelled
hypotheses through the real hunt engine and checks each verdict against expected
outcomes, reporting overall accuracy plus threat precision and recall.

## Running the built-in demo benchmark

The built-in suite uses the synthetic demo data (`actaeon/demo/data.py`,
8 labelled cases covering both true-positive threats and benign/absent
scenarios):

```bash
actaeon demo --dir /tmp/actaeon-bench --offline
ACTAEON_HOME=/tmp/actaeon-bench actaeon bench
```

Each run writes a timestamped JSON report under `data/bench-*.json` with
per-case outcomes, confidence, tool-call counts, runtime, and summary metrics.

## Running against your own data

Create a YAML file of labelled hypotheses:

```yaml
- id: my-case
  hypothesis: "An Office application started PowerShell with an encoded command in the last 7 days."
  expect: [threat]

- id: clean-case
  hypothesis: "A scheduled task named TestLabUpdate ran on LAB-01 in the last 7 days."
  expect: [telemetry_found_benign, no_results]
```

Then run:

```bash
actaeon bench --cases my-cases.yaml
```

## Comparing models

Run the same cases with another model, without editing `config.yaml`:

```bash
actaeon bench --model ollama/qwen3:32b --markdown                 # every role on one model
actaeon bench --model openai_compatible/<model> --role-model analyst=anthropic/<model>
```

`--model` and `--role-model` turn off fallbacks, so the score belongs to the model you named.
`--markdown` prints a row for the table below. The JSON report records the Actaeon version, the
models of each role, tokens, cost (when `llm.prices` lists the model) and time per case.

### Results per model (send yours)

Built-in demo cases unless noted. Add a row in a pull request with the JSON report attached; say
which cases you ran and anything you changed. A run on your own data is welcome too, described in
words when the cases are private.

| Model | Cases | Correct | Threat precision | Threat recall | False positives | Time / case | Tokens / case | Cost / case | Date | Version |
|---|---|---|---|---|---|---|---|---|---|---|
| fast cloud model (all roles) | built-in demo cases | 7/8 | 1.00 | 1.00 | 0 | 1-7 min | n/a | n/a | 2026-11-13 | 0.1.0-dev |

## Notes on interpreting scores

- Results depend heavily on the model assigned to the `analyst` role and on the
  quality of your connector query guides.
- A handful of synthetic cases is a regression smoke check, not a measure of
  real-world detection coverage.
- Always inspect cited evidence (`E1`, `E2`, ...) rather than relying on a
  verdict label alone.

## Recorded results

Synthetic demo suite only (8 cases written by the project, not an independent benchmark).

| Date | Analyst model | Accuracy | Threat precision | Threat recall | Notes |
|---|---|---|---|---|---|
| 2026-11-13 | fast cloud model, native tool calling | 7/8 (88%) | 1.00 | 1.00 | The miss was an empty model reply that ended the hunt; it is now retried. 15-25 tool calls and 1-7 minutes per case. |
| 2026-11-13 | 7B local model | not usable | - | - | Tool calls worked, query logic did not. |

### ExCyTIn-Bench sample (2026-11-13)

80 of 589 questions (10 per incident, fixed seed), read-only SQL bridge, 25 tool calls per question,
graded with the benchmark's published judge prompts by the same fast cloud model.

| Run | Mean reward | Fully correct | Partial | Used all 25 calls |
|---|---|---|---|---|
| Without query notes | 0.495 | 38 / 80 | 4 | 38 |
| With query notes describing the tables (`--notes`) | 0.512 | 40 / 80 | 3 | 29 |

Query notes made the investigations shorter (fewer questions ran out of calls) but barely changed the
score: two incidents improved a lot, three got worse, which is within run-to-run noise. Indicative only:
the judge model and the sample differ from the paper. `benchmarks/excytin/run.py --quick --workers 4`
runs a 16-question regression subset in about 10 to 15 minutes.

**Why the 40 misses of the second run failed** (`benchmarks/excytin/analyze.py`, decided from each
question's stored tool calls, not by a model):

| Cause | Questions | What it means |
|---|---|---|
| Ran out of tool calls, answer already in a result | 11 (4 weak matches) | It had seen the value and kept searching instead of answering |
| Model service error (quota limit, outage) | 8 | Not a hunting failure; the runner did not retry these |
| Ran out of tool calls, answer never retrieved | 7 | The searches did not reach the evidence within 25 calls |
| Model produced a malformed tool call | 6 | A real model failure: the provider rejected the call |
| Answer never retrieved | 5 | It answered without the searches reaching the evidence |
| Answer retrieved, wrong final answer | 3 | It saw the evidence and did not connect it |

"Answer in a result" means the whole expected value appears as a token in a successful tool result. A
weak match is a value that can appear by chance (a short number, `SYSTEM`, a common process name).
Only 13 of the 532 tool calls in the missed questions failed, so broken queries were not the problem.
Leaving out the 8 service errors, the run scores a mean reward of 0.569 over 72 questions (40 fully
correct); the scores in the first table keep them in, as recorded.

What this points to: the biggest group is investigations that had the answer and did not stop. That
is a loop-control problem (when to answer), not a data-access problem, and it is the first thing to
work on. The runner now retries a question that dies on a service error (up to two more times) and
records the trace folder of each question for this analysis.

### Lab benchmark on real data (2026-11-13)

A frozen copy of one home lab's real SIEM data (37k alerts, 294k raw events, host inventory and
vulnerability findings) with 11 labelled cases:

- **5 threats:** 4 attacks planted on a throwaway host before the freeze (a hidden process in `/dev/shm`,
  a listener from a hidden interpreter copy, a second UID 0 account, and log lines with real indicators
  from a security news advisory in the intel store), plus a root crontab entry left by an earlier test.
- **6 that must not be called a threat:** an agent outage that was planned maintenance, a benign
  key-file change, two hunts whose data does not exist in this lab, and two real known-exploited CVEs
  that are installed but were not exploited.

| Run | Correct | Threats found | False positives | Input tokens per hunt |
|---|---|---|---|---|
| Field test hunts, before handoff, known-good list and missing-data fix | - | - | 2 of 2 "threats" were the owner's own activity | - |
| Lab run 2, after those fixes | 10 / 11 | 4 / 5 | 0 | 533k |
| Lab run 4, after compact results and trimmed history | **11 / 11** | **5 / 5** | **0** | **438k (-18%)** |

One label was corrected after review: the frozen week also held an earlier test that planted a root
crontab entry, so finding it is the right answer for the cron/systemd case (run 2 had called it benign).
In both runs the two Windows hunts correctly ended as "logs missing" and were handed to an analyst as
low-severity leads. A run where the cloud model's shared capacity ran out (most hunts failed on rate
limits) is not counted; `actaeon bench` now reruns cases that die on service errors and reports them.

Small and written by someone who knows the answers, so read it as "it checks and clears correctly" rather
than proof that it finds stealthy attackers. See `benchmarks/lab/` to build one on your own data.
