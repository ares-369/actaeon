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
models of each role, model calls, tokens (input, cached input, output) and time per case.

### Results per model (send yours)

Built-in demo cases unless noted. Add a row in a pull request with the JSON report attached; say
which cases you ran and anything you changed. A run on your own data is welcome too, described in
words when the cases are private.

| Model | Cases | Correct | Threat precision | Threat recall | False positives | Time / case | Input tokens / case | Output tokens / case | Date | Version |
|---|---|---|---|---|---|---|---|---|---|---|
| fast cloud model (all roles) | built-in demo cases | 7/8 | 1.00 | 1.00 | 0 | 1-7 min | n/a | n/a | 2026-11-13 | 0.1.0-dev |
| gemini/gemini-3.8-flash | built-in demo cases | 8/8 | 1.00 | 1.00 | 0 | 1-2 min | 52k (26% cached) | 2.8k | 2026-11-14 | 0.1.0b2+ |
| gemini/gemini-3.1-pro-preview | built-in demo cases | 8/8 | 1.00 | 1.00 | 0 | 1-3 min | 23k (2% cached) | 3.2k | 2026-11-14 | 0.1.0b2+ |
| gemini/gemini-3.1-flash-lite | built-in demo cases | 6/8 | 1.00 | 0.50 | 0 | under 1 min | 18k (28% cached) | 0.7k | 2026-11-14 | 0.1.0b2+ |
| ollama/qwen2.5-coder:7b (4 GB laptop GPU, compact) | built-in demo cases | 3/8 | n/a | 0.00 | 0 | 2.7 min | 28k (0% cached) | 0.7k | 2026-11-15 | 0.2.0-beta |
| ollama/qwen2.5-coder:7b, second run | built-in demo cases | 3/8 | n/a | 0.00 | 0 | 7.4 min | 66k (0% cached) | 2.0k | 2026-11-15 | 0.2.0-beta |
| ollama/qwen3:4b (thinking, `think_tokens` 3000) | built-in demo cases | 3/8 | 1.00 | 0.25 | 0 | 5.1 min | 9k (0% cached) | 11.5k | 2026-11-15 | 0.2.0-beta+ |
| ollama/qwen3:4b, 3 failed cases rerun with `think_tokens` 6000 | 3 demo cases | 1/3 | n/a | 0.00 | 0 | 8.5 min | 12k (0% cached) | 17.7k | 2026-11-15 | 0.2.0-beta+ |

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

### Three models on the lab benchmark (2026-11-14)

The same 11 cases and frozen data, the current code, each model for every role, no fallback model.

| Model | Correct | Threats found (of 5) | False positives | Input tokens per hunt | From the provider's cache | Output tokens per hunt | Model calls per hunt |
|---|---|---|---|---|---|---|---|
| gemini-3.8-flash | 10 / 11 | 5 | 0 | 247k | 58% | 4.2k | 19 |
| gemini-3.1-pro-preview | 9 / 11 | 3 | 0 | 195k | 36% | 6.0k | 18 |
| gemini-3.1-flash-lite | 8 / 11 | 2 | 0 | 70k | 58% | 1.1k | 9 |

- **gemini-3.8-flash** was run four times while tuning: 11, 11, 11 and 10 correct. The one miss in the last
  run was a hunt where the model gave three unusable replies in a row. That last run is the only one in
  which the second look worked (see the fix below): it confirmed all five threats (confidence 80 to 95).
- **gemini-3.1-pro-preview** found all five threats on its first pass, but its own second look talked it
  out of two ("found a benign explanation"), so they ended as `inconclusive` and went to an analyst. This
  run was before the second-look fix.
- **gemini-3.1-flash-lite** uses far fewer tokens but missed three of the five threats, answering
  `no_results` or `logs_missing` where the activity was there. It did not raise false alarms.
- **Gemini 4 Hydrogen and Gemini 4 Argon** did not work: see
  [known limitations](known-limitations.md). They are not scored here.
- After these runs the cloud project began to reject every request on policy grounds ("Request rejected
  in accordance with our terms of use and policies"), probably because hunt prompts are full of attack
  techniques. A rerun of the ExCyTIn sample and of gemini-3.1-pro-preview after the fix could not be done.

### Alert triage on real lab data (2026-11-16)

`actaeon triage-bench --cases` on 9 labelled cases over the frozen copy of the lab's real data (the same
indices as the lab benchmark above). 4 are planted attacks, written as the alerts a detection rule would
raise (a process running from `/dev/shm` with a daemon-like name, a hidden process listening on port 4444, a
second account with user id 0, a download piped into a shell from an address in a published campaign); their
activity is really in the data. 5 are real alerts that are not attacks (firewall blocks from a LAN client,
a decoy port probed by the lab's own proxy, a host low on memory, a hypervisor configuration change, a
hardening check on a new container). The local model is qwen3:4b on Ollama, on a 4 GB laptop GPU.

| Run | Correct | Attacks found | False alarms | Handed to an analyst | Wrong closures | Claims with evidence | Tokens (9 cases) | Median per case |
|---|---|---|---|---|---|---|---|---|
| qwen3:4b, no fixed checks | 5/9 | 0/4 | 0 | 8 | 0 | 0.79 | 245,137 | 555 s |
| fixed checks only, **no model** (`soc.analysis: rules`) | 9/9 | 4/4 | 0 | 5 | 0 | 1.0 | 0 | 9 s |
| qwen3:4b with the fixed checks, model allowed to overrule them | 6/9 | 1/4 | 0 | 7 | 0 | 0.81 | 220,086 | 739 s |
| qwen3:4b with the fixed checks (what ships) | 9/9 | 4/4 | 0 | 4 | 0 | 0.95 | 225,414 | 692 s |

What the runs show:

- **The small model alone found none of the attacks.** It made one or two queries per case and called all four
  false positives; the rule that a high or critical alert is not dismissed without confirmation kept them open.
- **The fixed checks found all four with no model**, from the host's inventory (the `/dev/shm` process, the
  hidden listener, the second root account) and the host's events with the intel store (the download from a
  campaign address). They also hand every real non-threat alert to a person: rules do not dismiss.
- **Given the same evidence, the small model still argued three of the four away.** Since then, evidence-backed
  signals about the alert's own activity keep the case a true positive and the model's view is recorded against
  it. With that rule the model adds what the rules cannot: it labelled the real non-threat alerts (benign or
  false positive), so one fewer case waits for a person, at about 25,000 tokens and 11 minutes per case.

Read these numbers with care:

- **The rules were tuned on these 9 cases.** In particular the rule that a finding only counts when it concerns
  the alert's own activity came from the hardening-check case (its host also carried the planted attacks). The
  9/9 is an in-sample result.
- **Out of sample**, on three days of real alerts from the live lab (329 alerts in 10 cases, no known attacks),
  the no-model rules produced no false alarms and closed nothing: every case went to a person with its evidence,
  in 70 seconds for all 10. Rules alone do not reduce noise; a model, tuning or suppressions still have to.
- **Nine cases is small**, and the planted attacks are of the kinds the checks look for. Attacks that leave no
  trace in inventory, host events or intel would not be found this way.
- Larger and cloud models have not been measured on alert triage. `actaeon triage-bench --table results.jsonl`
  prints every recorded run; providers with no run are listed as not measured.

### Alert triage on attacks the rules had never seen (2026-11-17)

The test the previous section called for: new attacks, planted after the rules were written, with no rule or
code change before or after the run. A throwaway container in the lab got a normal monitoring agent (logs,
inventory every 5 minutes, file-integrity monitoring), then six inert stand-in attacks of kinds the fixed
checks have no rule for, and four harmless look-alikes. The labels, the hand-written alerts and a prediction
were written down before anything was planted, the data was frozen, and each mode ran once.

| Case | Expected |
|---|---|
| A cron entry that runs a renamed binary from a hidden folder (not a temporary path) | true positive |
| A user reading `/etc/shadow` through sudo and copying it | true positive |
| A renamed interpreter in a hidden folder holding a connection to a local listener (reverse-shell style) | true positive |
| A key appended to root's `authorized_keys` | true positive |
| Base64 content piped into `sh` | true positive |
| A file downloaded, made executable and started (not piped; the address is not in the intel store) | true positive |
| An admin script run from `/tmp` | not a threat |
| A normal backup account created | not a threat |
| An ordinary `curl` download of a checksum file | not a threat |
| A logrotate cron job added | not a threat |

| Run | Correct | Attacks found | False alarms | Handed to an analyst | Wrong closures | Tokens (10 cases) | Median per case |
|---|---|---|---|---|---|---|---|
| fixed checks, no model | 4/10 | 0/6 | 0 | 10 | 0 | 0 | 9 s |
| qwen3:4b with the fixed checks | 3/10 | 0/6 | 1 | 8 | 0 | 207,331 | 945 s |

What this shows:

- **Neither found any of the new attacks.** The fixed checks collected the evidence every time (all their calls
  succeeded: the sudo lines reading `/etc/shadow`, the hidden processes in the host inventory, the changed key
  file), but no rule recognises these kinds of trace, so they raised no signal. The 9/9 of the previous section
  was in-sample, as it said: it does not carry over to attacks the rules were not written for.
- **The small model dismissed all six**, as benign or false positives, several times by pointing at a note in the
  environment description about earlier container changes. It also called the ordinary backup account an attack.
- **Nothing was wrongly closed.** All six attacks are high-severity alerts, and a high or critical alert is not
  dismissed without an independent confirmation, so every one went to a person with its evidence collected. The
  rules raised no false alarm (the `/tmp` admin script and the new cron job did not fire anything).
- **What would have caught them** is plain to see: rules for cron and service entries pointing at hidden paths,
  reads of credential files, `authorized_keys` changes, decoded content piped into a shell, and a download that is
  then executed. Adding them now would be tuning to this set, so they need a fresh set of their own to be
  measured on. The environment note the model leaned on also shows that broad notes can become an excuse; notes
  should name exact accounts and hosts.

### Alert triage on a held-out set after adding rules (2026-11-27)

After the test above, rules for those kinds of trace were written as Sigma rules for Wazuh's fields
(`examples/rules/wazuh-linux`) and the rule library was connected to triage (rules marked ready are signals). While
checking them, two faults in the fixed checks showed up and were fixed: a log row counted as "about the alert"
whenever it named the alert's account, and `root` is on nearly every Linux row; and the context search returned
the newest rows of a window reaching 30 minutes past the alert, so on a busy host the alert's own rows could be
missing (it is now centred on the alert, with a second search for the alert's own program and files).

Measured three ways, rules only (no model), so each number has a plain cause:

| Set | What it is | Correct | Attacks found | False alarms | Wrong closures |
|---|---|---|---|---|---|
| 2026-11-16 lab set (9 cases) | regression check | 9/9 | 4/4 | 0 | 0 |
| 2026-11-17 unseen set (10 cases) | **in-sample**: the rules were written from it | 7/10 | 3/6 | 0 | 0 |
| **held-out set (11 cases, below)** | **new attacks and look-alikes, labels and predictions written before planting** | 5/11 | 3/6 | 3 | 0 |

The held-out set was planted on a fresh throwaway container the same way as before (inert stand-ins, hand-written
alerts, data frozen with Wazuh's own index mappings), with new variants of the covered kinds, two kinds no rule
covers, and realistic admin actions that look like attacks:

| Case | Expected | Rules only |
|---|---|---|
| A crontab line running a binary in `/var/lib/.syslogd/` | true positive | missed (to an analyst) |
| An SSH key added to a normal user's `authorized_keys` | true positive | found |
| A renamed perl in `/srv/.cache/` opening a socket from inline code | true positive | found |
| `curl -o /usr/bin/...` then run | true positive | found |
| A systemd unit running a hidden binary (no rule covers it) | true positive | missed (to an analyst) |
| `/etc/ld.so.preload` created (no rule covers it) | true positive | missed (to an analyst) |
| A tool installed with `curl -o /usr/local/bin/helm` | not a threat | **false alarm** |
| Root adding its own key | not a threat | **false alarm** |
| A certbot cron job | not a threat | to an analyst |
| A node_exporter systemd unit | not a threat | to an analyst |
| An application cache file in `/opt/grafana/.cache/` | not a threat | **false alarm** |

The result matched the predictions written before planting, case for case.

What this shows:

- **The rules carry over to new variants of the kinds they were written for** (a different user's key, a renamed
  perl instead of python, curl instead of wget, other folders): 3 of 3 found. They do nothing for kinds they do not
  describe (the systemd unit, `ld.so.preload`), and a crontab change is still not linked to the hidden binary it
  runs, because nothing in the logs connects the two.
- **Rules cannot tell intent.** A key added by its owner, a tool installed by hand and an application's cache look
  the same in the logs as the attacks; with rules that confirm on their own they became 3 false alarms out of 5.
  That is the cost of letting a single rule decide: keep such rules at medium (they then raise a hint, and the
  case goes to an analyst), or run with a model and use `soc.never_dismiss` / known-good notes for your own
  admin habits.
- **Nothing was wrongly closed** in any of the three sets.

The same held-out set with qwen3:4b reading the evidence after the fixed checks (local model, 4 GB GPU):

| Run | Correct | Attacks found | False alarms | Handed to an analyst | Wrong closures | Tokens (11 cases) | Median per case |
|---|---|---|---|---|---|---|---|
| fixed checks and rules, no model | 5/11 | 3/6 | 3 | 5 | 0 | 0 | 10 s |
| qwen3:4b with the fixed checks and rules | 5/11 | 3/6 | 3 | 4 | 0 | 235,829 | 393 s |

The model added nothing here: the three attacks it confirmed and the three false alarms were already decided by
rule signals it cannot overrule. On the two attacks no rule covers it was wrong (the systemd unit "benign",
`ld.so.preload` "false positive"), and both still went to an analyst because a high-severity alert is not
dismissed without a second confirmation. It correctly called the certbot job benign.

## Token usage

Every hunt records model calls and tokens per model: input, the part of the input the provider served from
its prompt cache, and output (thinking tokens included). The hunt page, reports and `actaeon bench` show
them. Measured on the lab benchmark above with gemini-3.8-flash:

| Version | Input tokens per hunt | From cache | Output tokens per hunt |
|---|---|---|---|
| 0.1.0b2 era, with gemini-3.5-flash (lab run 4 above) | 438k | not recorded | 7.7k |
| Older results shortened in batches (prompt start stays the same) | 260k | 60% | 4.5k |
| Plus: stop once the evidence answers the hypothesis, calls used shown on each result | 210k | 58% | 3.8k |
| Same, with `hunt.prompt_mode: compact` | 177k | 49% | 4.4k |
| Final: with the second look working on threats (extra calls on the five threats) | 247k | 58% | 4.2k |

On the synthetic demo data a hunt uses about 20k to 50k input tokens, because the results are small.
Prompt caching depends on the provider: Gemini served more than half of the input from its cache on real
data, and almost none on the small demo prompts. Runs vary: the same model and cases ranged from 210k to
247k input tokens per hunt across runs.

To use fewer tokens:

- `hunt.max_steps` (default 25): fewer tool calls per hunt.
- `hunt.max_result_bytes` (default 8000): how much of each tool result the model sees. The lab scored the
  same at 8,000 as at 20,000.
- `hunt.prompt_mode: compact`: shorter tool descriptions and older results cut more; about 16% fewer input
  tokens on the lab, with the same score in the one run measured.
- `hunt.max_tokens`: a hard cap per hunt; when it is reached the model must give its verdict.
- A smaller model: gemini-3.1-flash-lite used about a third of the tokens and missed three of five threats.
- `hunt.verify: false` turns off the second look on threats. It saves the extra calls on every threat, and
  loses the check that tries to prove the threat wrong.
