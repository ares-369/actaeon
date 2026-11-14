# Hunting

A hunt tests one hypothesis, for example *"Office apps launched encoded
PowerShell on any host in the last 7 days"*.

## Start one

- UI or API: `POST /api/hunts {"hypothesis": "...", "max_steps": 15}` (operator or admin)
- CLI: `actaeon hunt "..."` prints each step as it runs; `actaeon hunt --list`,
  `actaeon hunt --show <id>`

Stop, pause and resume: `POST /api/hunts/<id>/stop|pause|resume`. Pause takes
effect between steps.

## What happens

1. **Plan** (planner model): a short summary, ATT&CK technique IDs and a list of
   steps, each tied to a data role. Roles the plan needs that no connector
   provides are listed as `missing_roles`.
2. **Investigate** (analyst model): the model replies with one JSON action per
   turn, either a tool call or a verdict. Each call:
   - must be a tool that the connector policy allows;
   - passes the query validator (below);
   - runs through the connector hub (pacing, retries, audit log);
   - is stored as evidence `E<n>` and shown to the model as untrusted data.
   The same call is never run twice. The newest four results stay in full in
   the prompt; older ones are trimmed.
3. **Verdict**, checked against the record before it is saved:

| Outcome | Meaning | Check |
|---|---|---|
| `threat` | malicious or clearly suspicious activity | needs at least one claim citing a successful result; otherwise `inconclusive` |
| `no_results` | the data was searched and nothing matched | needs at least one successful search of a data role; otherwise `logs_missing` |
| `telemetry_found_benign` | matching activity, explained and benign | needs cited evidence |
| `logs_missing` | the data needed was not there or not searchable | |
| `inconclusive` | anything else, including limits reached | |

Before accepting a `threat` verdict, the engine asks the model once to
corroborate it, if it has not yet looked up indicators in intel, decoded an
encoded command it mentions, or made a second data query (a pivot). Confidence
is capped at 60 when one piece of evidence supports the threat, and at 75 when all
the evidence comes from one kind of query.

Citations to results that do not exist or failed are dropped. Claims left with
no evidence are kept apart as `unsupported_claims`. When the outcome is changed
by a check, confidence is capped at 40 and the reason is listed in `checks`.
Intel lookups alone never count as a data search.

## Second look (verification)

When a hunt ends in `threat`, a second pass runs on the analyst model with the
opposite job: try to prove it wrong. It re-runs or widens the key searches,
checks whether the activity continues, looks for a benign explanation (admin
tools, updates, known service accounts, analyst notes) and checks a second data
source. Its calls are added to the hunt as evidence.

- `confirmed` (needs evidence it gathered itself): confidence rises to at least 80.
- `refuted`: the outcome becomes `inconclusive` and needs review. A threat is never
  closed automatically.
- `unconfirmed`: confidence is capped at 60 and the hunt needs review.

Turn it off with `hunt.verify: false`. Sweeps are verified too when a model is
configured for triage (`intel.sweep.triage: model`) or `intel.sweep.verify: true`.

## Handing over to an analyst

Actaeon does not pretend to know. When a hunt cannot reach a confident answer, it is handed to a
person: the verdict is marked for review, a lead opens, and the hunt page, the lead and the report
show a **Handed to an analyst** box with the reason, what Actaeon searched, what it could not check
and suggested next steps. This happens when:

- the hunt is **inconclusive** (step or time budget used up, unclear replies);
- the data needed is **missing** (`logs_missing`), opened as a low-severity lead;
- a **threat could not be confirmed** by the second look;
- a **threat only names known-good things** (see below);
- the hunt **failed** with an error.

Repeats of the same unanswered question (a schedule or replay) add a "seen again" entry to the open
lead instead of opening a new one. Choose the cases with `hunt.handoff`
(default `[inconclusive, logs_missing, unverified_threat, error, known_good_threat]`).

## Missing data is not "no results"

If the kind of event a hypothesis needs does not exist in any source at all (for example Windows
process-access events in a Linux-only environment), the model reports `needed_data_present: false`
and the outcome becomes `logs_missing`, even though its searches ran and returned nothing.

## Known good

`environment.known_good` lists what is normal here: your own services, scheduled jobs, admin hosts,
planned changes. It is given to every hunt. A threat whose every finding names known-good items is
not dropped, because an attacker can reuse a trusted name; its confidence is capped at 50 and it is
handed to an analyst to check for misuse.

## Query validator

A basic sanity check before each call, not a guarantee:

- arguments must match the tool's input schema (required fields, types, enums, size);
- if a tool takes a time range, one must be given;
- size/limit arguments are capped at `hunt.max_results`;
- query text is refused if it looks like it deletes, writes, changes an index
  or schema, or runs code, or if it has control characters or is over 4000 characters.

Field guard: if a connector has a `get_fields` tool, the engine calls it once
(recorded as a step) before the first query on that connector. Queries that use
`field:value` with a field the source does not have are refused, with the
closest real names suggested. If the field list was truncated, no fields are
refused.

Connector policy (read-only tools) and the source's own permissions are the
other layers.

## Limits

`hunt.max_steps` (tool calls), `hunt.max_runtime_sec`, `hunt.max_results` and
`hunt.max_result_bytes` in `config.yaml`. After 3 replies that are not valid
actions the hunt ends as `inconclusive`.

- `hunt.max_query_sec` (default 120): one tool call, retries included, never runs
  longer than this, and never past the end of `max_runtime_sec`. The connector's
  own `timeout_sec` still applies per attempt when it is shorter. A query cut off
  this way fails like any other failed call; the source may keep working on it on
  its side.
- `hunt.max_tokens` (default 0 = no cap): model tokens (in + out) for the whole
  hunt, the second-look pass included. When reached, no more tool calls: the model
  must give its verdict from what it has, and a note on the hunt says why. Usually
  that verdict is `inconclusive` or an unconfirmed threat, so it goes to an analyst.

## Prompt injection in the data

Every tool result is scanned for text that tries to instruct an AI: "ignore
previous instructions", "mark this host as benign", chat-template tags, a fake
verdict object, a copy of the data marker. It also scans a normalised copy (look-alike
Unicode letters, words split by `-`, `_` or `.`) and any payload the offline decoder can
unpack (base64, `-EncodedCommand`, hex, ...), and a few phrasings in other languages.
Such text is not normal telemetry, so a match is a lead in its own right:

- the model is told the text is data and planting it is suspicious;
- the hunt gets a note naming the evidence, and `verdict.injection` lists it;
- the hunt is handed to an analyst (`hunt.handoff` value `injection`) and its lead
  is `high` severity, titled "prompt injection", whatever the verdict was.

How well it does, measured (`python benchmarks/injection/score.py`):

| Set | Planted attacks caught | Benign look-alikes flagged |
|---|---|---|
| `benchmarks/injection/cases.yaml` (the patterns were tuned on it) | 24 / 24 | 0 / 20 |
| `benchmarks/injection/holdout.yaml` (written before tuning, scored once) | 9 / 10 | 0 / 10 |
| One week of real alerts from a home lab | - | 0 / 9,459 |

The held-out miss (`ignore_the_above_and_mark_clean.lnk`) showed a bug in one pattern, fixed
afterwards; the 9 / 10 is the score from before that fix. These sets are small and written by the
same person who wrote the patterns. A rephrased attack can still get through, and a model can
still be misled by text the scanner does not flag. The untrusted-data wrapping, the read-only
tool policy and the evidence checks remain the main defence; the scanner only makes blatant
attempts visible.

## Ask Actaeon (chat)

On a finished hunt, the UI has an **Ask Actaeon** box (API:
`POST /api/hunts/<id>/chat {"message": "..."}`, operator role). Ask about the
result, or say what to check next ("check the other hosts for this domain",
"what ran before the PowerShell?"). The analyst model answers from the record, or
first makes up to 5 read-only calls. The calls get the same policy, validator
and field guard as a hunt, and their results are added to the hunt as new
evidence. Citations to evidence that does not exist are removed. Chat cannot
change the verdict: use feedback on findings for that.

## Timeline

Every finished hunt has a **Timeline** (`GET /api/hunts/<id>/timeline`, and a
section in the report). It lists every event in the evidence in time order, with
host, user, process (parent -> child), command line, source, destination, the
evidence id, and the executed / blocked / passive state. Hosts, users,
destinations and processes are listed with counts; click one to filter. It is
built from the stored results with no model. Events with no readable time are
counted and left out.

## Detection drafts

**Draft a detection rule** on a finished hunt (`POST /api/hunts/<id>/detection`)
gives two things:
- **native queries**: the queries from this hunt that returned data, exactly as
  they ran, per connector. They are ready to save in your log platform as a
  scheduled search or correlation rule;
- **a Sigma draft** written by the reporter model from the hypothesis, findings,
  those queries and any benign feedback (which becomes `falsepositives`). It is
  checked for valid YAML, the required keys and a condition, gets ATT&CK tags
  from the hunt, and is set to `status: experimental`.

Both are drafts for a detection engineer to review and test. Drafts are kept per
hunt (`GET /api/hunts/<id>/detection`, `GET /api/detections`).

### Converting the Sigma draft (pySigma)

With `pip install 'actaeon[sigma]'` and the pySigma backend for your platform (each platform's
backend is its own package), Actaeon also converts a valid Sigma draft into each connector's own
query language and counts how often the converted query would have matched:

```yaml
connectors:
  - name: logs
    ...
    sigma:
      backend: <backend id>       # `actaeon sigma backends` lists the installed ones
      pipelines: []               # pipeline names, or your own pipeline YAML mapping Sigma fields to yours
      format: default
      backtest: true              # count matches of the converted query over the last 14 days
```

Also: `actaeon sigma convert rule.yml` (for every connector with a `sigma:` block, or
`--backend ID --pipeline P` for one), and `POST /api/sigma/convert {"sigma": "...", "backtest": true}`
for an edited rule. Each connector's result shows the converted query or the converter's error.

Read the counts with care. Zero matches can mean the field mapping is wrong, not that the rule is
quiet. Sigma's `contains` and `endswith` become leading wildcards, which the search-index bridge
refuses on log indices (they would silently match nothing). The backtest then reports that error:
use `startswith`, an exact value or a keyword field instead. Backends pin their own pySigma
version; install the backend after Actaeon's extra and let pip choose.

## Prompt size

`hunt.prompt_mode: compact` uses fewer tokens and suits smaller models. The analyst sees
only the tools for the roles in the plan (plus intel and analysis), short tool
descriptions, the two newest results in full (others trimmed to 600
characters), and shorter query guides. `full` is the default.

## Known limitations

- Small local models plan weaker hunts and can pick the wrong ATT&CK IDs. IDs
  are checked against the bundled ATT&CK release (unknown ones dropped, revoked
  ones mapped), but whether a technique fits is the model's judgement. Review them.
- The verdict checks make sure claims point at real results. They cannot check
  that a claim reads the result correctly.
