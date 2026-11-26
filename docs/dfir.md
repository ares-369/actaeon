# Investigations (offline DFIR)

Load evidence files into a case, get one timeline across hosts and sources, run Sigma rules and analyzers over
it, mark what matters, and have a model write the story of what happened, citing the events. Everything is
read-only towards other systems: evidence is parsed and stored in Actaeon, nothing is queried or changed
anywhere.

The design borrows ideas from established open-source tools: one timeline from many event logs with Sigma rules
and a field mapping (Hayabusa, Chainsaw), least-frequent stacking and logon summaries (Takajo), one case with
several timelines and starred, tagged and commented events (Timesketch), and hypotheses with open questions next
to the timeline. No code from those projects is used.

```yaml
dfir:
  enabled: true
  max_upload_mb: 1024
  max_events_per_case: 2000000
  library_rules: [ready, testing]  # rule library statuses run over the evidence (needs rules.enabled)
  builtin_rules: true              # Actaeon's small set of high-value Windows and Linux checks
  rule_dirs: []                    # extra Sigma folders, e.g. a SigmaHQ checkout's rules/windows
  story_events: 250                # events the model sees for the story
  evtx_dump: ""                    # optional: path to the evtx_dump tool for much faster .evtx reading
```

Reading `.evtx` files needs `pip install 'actaeon[dfir]'` (python-evtx, Apache-2.0).

## Evidence

| Format | Notes |
|---|---|
| Windows event logs (`.evtx`) | python-evtx by default (about 300 events per second). With `dfir.evtx_dump` set, the external evtx_dump tool is used instead; this path is tested against its JSON format but not yet against the tool itself. |
| JSON or JSON lines | Velociraptor results, Hayabusa JSONL (its detections are kept as "imported"), event logs exported as JSON, osquery, or any records with a time field |
| CSV | Plaso l2tcsv (UTC rows) and psort's dynamic output, Hayabusa CSV, or any CSV with a time column |
| syslog, auth.log | RFC 3164 and ISO time stamps; SSH logons, failures, sudo commands and new users are recognised. Lines without a year get `--year` (CLI) or the current year. |
| `.gz`, `.zip` | `.gz` of any text format; `.zip` collections are read member by member (at most 5000 files) |

Each file's SHA-256 is recorded before it is read, with its name, size, who imported it and when. The same file
twice in one case is skipped. Unreadable records are counted and a few are kept as samples; the rest of the file
is still read. All times are stored in UTC.

Windows events keep the field names Sigma rules use (`EventID`, `Channel`, `Provider_Name`, `Computer` and the
EventData names). Security 4688 events also get `Image`, `ParentImage` and `User`, so process-creation rules work
on them.

## Analyzers

"Run the analyzers" (or `actaeon dfir analyze CASE`) runs, with no model:

- **Sigma**: ready and testing rules from the [rule library](rules.md), the built-in checks, and every rule in
  `dfir.rule_dirs`, over every event. A rule's logsource decides which events it is tried on
  (`process_creation` only on Sysmon 1 and Security 4688, `service: security` only on the Security log, and so on).
  Rules for other platforms never match Windows events and the other way round. A noisy rule stops tagging after
  `max_rule_hits` events.
- **Imported detections**: results already in the evidence (Hayabusa's `RuleTitle` and `Level`).
- **Logons**: successful and failed logons per account and source; a success after 10 or more failures from
  the same source within 30 minutes becomes a high detection.
- **Stacking**: the least frequent processes, parent-child pairs, services, scheduled tasks and logon sources.
- **Metrics**: events per host, log, event id and day.

Measured on the public EVTX-ATTACK-SAMPLES set (277 files, 37,357 events): the 14 built-in checks found the
comsvcs LSASS dump, the shadow-copy deletion, LSASS access by mimikatz, procdump and others, and 26 cleared logs on
9 hosts. With the SigmaHQ Windows rules added (2,432 rules, all evaluated by the local matcher), 345 rules matched
and analysis took 71 seconds.

## Timeline

Search words anywhere in an event, or `field:value` (for example `Image:powershell`, `TargetUserName:admin`).
Filter by host, time range (UTC), detections only, starred only, tag or rule. Open an event to see every field,
add tags and a comment; star the events that matter. Export the timeline (or only detections) as CSV.

## Story and questions

Notes keep hypotheses, questions and findings, each with a status (open, confirmed, refuted, answered, closed) and
the events it is about.

"Write the story" gives the reporter model the starred events, a sample of the events behind each detection, the
events your notes point to, the analyzer results and your notes. It must cite event ids. Every citation is
checked against the events it was shown: ids it was not shown are removed and counted, and a part of the story
with no valid citation is kept but marked "not supported by a cited event". The story lists open questions and
next steps.

The prompt is fitted to the model: with Ollama, `num_ctx` (minus the reply and any `think_tokens`) sets how much
fits. The case facts take at most 40% of it; events fill the rest in priority order (starred, then detections by
level), and the story says how many events were left out.

What the check proves: every cited id is an event the model was shown. It does not prove the event supports the
sentence. In a test with a local 7B model, one cited event was a registry backdoor listed under credential theft.
Open the cited events before you rely on a statement.

Measured on a 4 GB GPU with Ollama (EVTX-ATTACK-SAMPLES case, `num_ctx: 8192`, `story_events: 40`):
qwen2.5-coder:7b wrote the story in 93 seconds from 25 events, with every citation valid. With 250 events and a
16k context it did not finish within 15 minutes; qwen3:4b spent its whole thinking budget without answering. On
small local models keep `story_events` around 40 and `num_ctx` at 8192; larger models can take more.

"Ask" answers a question about the case. The model may search the case up to three times before answering, and
its answer is checked the same way. Prompts go through the same privacy masking as hunts.

## Report

The Markdown report holds the evidence list with SHA-256 hashes, the latest story (labelled as written by a
model), the detections, the starred events with comments, and the notes.

## Command line

```
actaeon dfir new "Web server breach" [--description TEXT]
actaeon dfir import CASE FILE_OR_FOLDER... [--year 2026]
actaeon dfir analyze CASE
actaeon dfir show CASE
actaeon dfir timeline CASE [--q WORDS] [--detected] [--limit N]
actaeon dfir story CASE
actaeon dfir ask CASE "Which account ran mimikatz?"
actaeon dfir report CASE [--out report.md]
actaeon dfir export CASE --out timeline.csv [--detected]
```

The CLI suits large evidence: no upload limit, and it runs in the foreground.

## MCP

Read-only tools: `list_investigations`, `get_investigation`, `search_investigation`.

## Limits

- Search uses the database's LIKE matching, so it slows down on cases with millions of events.
- python-evtx is slow on large logs; use the CLI, or set `dfir.evtx_dump`.
- Plaso l2tcsv rows in a time zone other than UTC get no time stamp; export from Plaso in UTC.
- Registry hives, prefetch, the MFT, shimcache, amcache, SRUM and memory images are not parsed directly; process
  them with your usual tools (Plaso, Velociraptor, Volatility) and load their CSV or JSON output.
- An import or analysis started from the web page runs in the server process; a restart in the middle leaves the
  file marked "importing". Import it again.
