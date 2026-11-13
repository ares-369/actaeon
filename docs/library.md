# Library, replays, sweeps and memory

## Saved hunts and replays

Save a finished hunt and its successful data calls are kept:

```bash
actaeon library save <hunt-id> --name "Encoded PowerShell" --every 360 --escalate
actaeon library list
actaeon library run <id>        # replay now
```

API: `GET/POST /api/library`, `POST /api/library/<id>` (name, interval_minutes,
escalate, enabled), `POST /api/library/<id>/run|delete`.

A **replay** runs the saved calls again with no model. Each call is validated
again (a changed connector policy or validator still applies), and its hit
count is read from the result (`total`, `count`, `matches` and similar keys).
Then:

- any matches: `inconclusive` with `needs_review: true`;
- no matches and every count readable: `no_results`;
- results whose count can't be read are compared with the last replay by
  fingerprint, and any change is flagged for review;
- no call succeeded: `logs_missing`.

With `--escalate`, a replay that needs review starts a full model-driven hunt
with the replay results as context. Relative times (`now-24h`) move forward
with each replay; saving warns about fixed times, which don't move.

`actaeon library starters` lists built-in starter hypotheses (generic, no
queries) to hunt with the model.

## Intel sweeps

A sweep searches the logs for indicators from the intel store, with no model.
It is driven by the IOC ledger: only indicators added or changed since the last
successful sweep are searched. Use `--full` to search all of them.

```bash
actaeon sweep            # or POST /api/intel/sweep {"full": false}
```

- Searchable types: IP, IPv6, domain, URL, email and hashes. CVEs and technique
  IDs are not searched as text.
- Values are searched in OR batches (`batch`, default 20). When a batch matches,
  each value is searched on its own (`max_attribution_calls`, default 50) so the
  match names the indicator.
- Each match is **triaged** from the events that matched:
  - `executed`: the indicator was used (process start, allowed connection, file written, successful sign-in);
  - `blocked`: it was stopped (drop or deny, quarantine, prevention, failed sign-in);
  - `passive`: it was only mentioned (email text, enrichment, report);
  - `unknown`: none of the above can be read from the events.

  The outcome is `threat` only if an indicator `executed`. It is
  `telemetry_found_benign` when every match was blocked or passive, and
  `inconclusive` (needs review) when something could not be classified.
  `intel.sweep.triage: model` asks the analyst model to look at the `unknown`
  ones; `rules` (the default) uses field names and values only; `off` turns
  triage off. The rules read words, not meaning, so check before acting.
- If a search fails, the ledger position does not move, so the next sweep tries again.

Targets come from `intel.sweep.targets` (connector, tool, and an argument
template with `{values}` and `{lookback}`). With none set, every connector
running the built-in search-index bridge is used with its allowed indices.
Set `intel.sweep.interval_minutes` to run sweeps on a schedule.

## Advisory hunts

`actaeon hunt --advisory <id>` (or `POST /api/hunts/advisory/<id>`) runs a
model-driven hunt for a stored advisory. The model gets the advisory text, as
untrusted data, along with its indicators, CVEs and techniques.

## Memory

Before each hunt, the most related past hunts and analyst notes are added to the
model's context, found with SQLite full-text search. Notes are written by people,
for example "the patch tool runs encoded PowerShell on build servers at night".

```bash
actaeon note "Backup agent uses rclone to cloud storage from backup01" --tag benign
actaeon note --list
```

API: `GET/POST /api/memory/notes` (`{"text", "tags", "expires_days"}`),
`POST /api/memory/notes/<id>/retire`, `GET /api/memory/related?q=...`. Models and
data sources can never write notes.

Notes can expire. A wrong "benign" call would otherwise hide that activity from
every later hunt. Notes made from a benign or false-positive call (finding
feedback, or closing a lead that way) stop being used after
`memory.benign_note_days` (default 90; 0 = never), unless the request gives its
own `expires_days`. Notes you add by hand never expire unless you say so
(`actaeon note "..." --expires-days 30`). Expired notes stay in the list, marked
as expired. The model sees who wrote each note and when.
Past verdicts are context only; the model is told to check them again.

## Scheduler

The server checks every minute for due replays and sweeps and queues them as
jobs. Nothing is scheduled unless you set an interval.
