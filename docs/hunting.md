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

## Prompt size

`hunt.prompt_mode: compact` is for cheaper or smaller models. The analyst sees
only the tools for the roles in the plan (plus intel and analysis), short tool
descriptions, the two newest results in full (others trimmed to 600
characters), and shorter query guides. `full` is the default.

## Known limitations

- Small local models plan weaker hunts and can pick the wrong ATT&CK IDs.
  IDs are checked for format only. Review them.
- The verdict checks make sure claims point at real results. They cannot check
  that a claim reads the result correctly.
