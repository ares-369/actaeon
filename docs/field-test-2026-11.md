# Field test, November 2026: a home lab and a hidden implant

This is a record of running Actaeon against a real network, not synthetic data. It is one run
in one small environment with one fast cloud model, so treat it as evidence, not proof. Failures
are listed with the passes.

## The environment

- About 24 hosts with an endpoint agent: 20 Debian, 3 Ubuntu, 1 Kali, and 1 Windows 11 (a dual-boot
  machine that was switched off throughout, so only its months-old inventory was there). Mostly
  containers running self-hosted services, plus two hypervisor hosts.
- One SIEM collecting from those agents. Actaeon read three kinds of data from it, all read-only:
  - **alerts**: events that matched a detection rule (about 8,900 in 7 days);
  - **raw events**: every event the SIEM received, rule or not. This archive was switched on for
    the test and is deleted after 7 days;
  - **host inventory**: what is running, listening, installed and who has an account on each host,
    from the agents' hourly scans (a snapshot with no event time).
- Actaeon itself ran in its own container, behind the lab's single sign-on, local network only.
- Model: a fast cloud model for planning, hunting and reporting, with a small local model as backup.

## 1. Detection-gap test: an implant that raised no alert

**Goal.** Plant attack-like activity that no detection rule covers, confirm that no alert fired,
then ask Actaeon to hunt without telling it what was planted.

**What did not work, and why that matters.** The first three attempts produced nothing a hunter
could find, because the telemetry was not there:

| Planted | Why it was invisible |
|---|---|
| Regular outbound connections to a never-seen domain | That host's traffic did not pass the firewall that logs connections |
| A cron job in a user crontab | Cron execution lines were not collected |
| A process started from `/dev/shm` | It was recorded in the host inventory, which Actaeon could not read yet |

A hunter can only find what is collected. The fix was in Actaeon: the search bridge gained a
**snapshot mode** for inventory data (no time bounds, path matching with leading wildcards, and no
time arguments advertised to the model).

**The test that counted.** On one container, a copy of a harmless system binary was started from
`/dev/shm` under a hidden name that imitates a system daemon (`.systemd-udevd`). Checks before the
hunt: present in the host inventory; **zero alerts** for it.

The hunt was given only a general hypothesis: *a process is running from a memory-backed or
world-writable path, or has a hidden name masquerading as a system daemon*. Result:

- Verdict **threat**, confidence 80, with cited evidence from the inventory.
- It named the host, the process, its path and process ID, and said it imitates a system daemon.
- It also noticed, from the parent process, that the endpoint agent had been restarted right after
  the process started, and described that as a possible attempt to evade detection. (The restart
  was the tester forcing an inventory scan, but reading it as suspicious is the right instinct.)

The implant was removed afterwards.

## 2. Starter hunts on real data

Sixteen starter hypotheses that fit a Linux-heavy lab, plus two Windows-only ones, run unattended
(about 3 to 8 minutes each):

| Outcome | Hunts | Notes |
|---|---|---|
| no results | 9 | Sudo abuse, log tampering, web shells, lateral SSH, tool downloads, and others |
| benign activity found | 3 | Correctly cleared a changed SSH key file (a cluster filesystem artifact: only the inode changed, hashes identical), internal scanning and a privileged account change |
| threat | 2 | **Both false positives**, see below |
| inconclusive | 2 | One used its whole step budget; one stopped after replies that were not valid JSON |

**False positives.** Both came from the owner's own infrastructure:

1. "New cron job or systemd unit" called the owner's own custom services, and well-known noisy
   rootkit-check alerts about standard binaries, a threat (confidence 80).
2. "Security tool tampering" saw five endpoint agents disconnect within two hours and not come
   back. That was a planned consolidation of five services into one container. The verification
   pass flagged this one: *a second pass could not confirm this; review it*.

The lesson: an AI hunter needs to know what is normal. Without a list of known-good services and
changes it will flag the environment's own administration. A known-good list for the environment
profile is the next piece of work.

**Windows hunts in a Linux lab** came back as "no results" with high confidence. They should have
said the data was missing: there was no Windows process-access telemetry to search. The engine
already refuses "no results" when no data search succeeded; it cannot yet tell that a search
succeeded but could never have matched.

## 3. Public benchmark: ExCyTIn-Bench sample

ExCyTIn-Bench (public, MIT licensed) asks investigation questions about eight recorded incidents
in a SQL database. Actaeon answered through its read-only SQL bridge with up to 25 tool calls per
question, and answers were graded with the benchmark's published judge prompts using the same fast
model as the judge. Ten questions per incident were sampled with a fixed seed (80 of 589).

| Measure | Result |
|---|---|
| Mean reward | **0.495** |
| Fully correct | 38 of 80 |
| Partial credit | 4 |
| Questions that used all 25 calls | 38 |
| Average per question | 18 tool calls, about 2.4 minutes |

Per incident, mean reward ranged from 0.14 to 0.88. The paper reports roughly 26 to 56 percent for
strong models, but the judge model and the sample differ, so this is indicative only, not a
leaderboard entry. Reproduce with `benchmarks/excytin/` (see its docstrings). A later run with query
notes describing the tables scored 0.512 (40 / 80); see benchmarks.md.

## 3b. Follow-up: a repeatable lab benchmark

The same week of data was later frozen and turned into 11 labelled cases (planted attacks, real intel,
and real activity that must not be called a threat). After adding analyst handoff, a known-good list and
missing-data detection, Actaeon scored 11 of 11 with no false positives. See benchmarks.md and
`benchmarks/lab/`.

## 4. Bugs found only by testing on real data

All fixed, with tests:

- A filtered field lookup was taken as the full field list, so valid fields were refused.
- On its last turn the model made one more tool call, and that call was recorded as its answer.
- A reply with a stray sentence inside the JSON ended an investigation instead of being retried.
- The model wrote verdicts in the native tool-call shape inside plain text; they were rejected.
- Empty replies that "finished normally" ended hunts; they are now retried.
- Short rate limits locked a model out for an hour; they are now retried with backoff.
- Inventory sources still advertised time arguments, which the query validator then demanded.
- Two hunts sharing one connector process could lose each other's replies.
- Each hunt's token count was the server's running total, not its own.
- A loopback address from a news article was stored as an indicator.

## 5. What this test does not show

- Accuracy over weeks: how many leads a team would close as benign over time.
- Other SIEMs, other log types, and larger or noisier networks.
- Other models. Small local models were not good enough to hunt in earlier tests.
- Attacks that leave no trace in alerts, raw events or inventory. Those need better collection,
  not a better hunter.
