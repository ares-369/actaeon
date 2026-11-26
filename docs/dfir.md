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
  yara_dirs: []                    # YARA rule folders: evidence files are scanned at import
  yara_max_mb: 512
```

Reading `.evtx` files needs `pip install 'actaeon[dfir]'` (python-evtx, Apache-2.0).

## Evidence

| Format | Notes |
|---|---|
| Windows event logs (`.evtx`) | python-evtx by default (about 300 events per second). With `dfir.evtx_dump` set, the external evtx_dump tool is used instead; this path is tested against its JSON format but not yet against the tool itself. |
| JSON or JSON lines | Velociraptor results, Hayabusa JSONL (its detections are kept as "imported"), event logs exported as JSON, osquery, or any records with a time field |
| CSV | Plaso l2tcsv (UTC rows) and psort's dynamic output, Hayabusa CSV, or any CSV with a time column |
| syslog, auth.log | RFC 3164 and ISO time stamps; SSH logons, failures, sudo commands and new users are recognised. Lines without a year get `--year` (CLI) or the current year. |
| Volatility 3 JSON | `vol -r json` output; nested rows (`__children`) are flattened with their depth and parent pid; the plugin name comes from the file name (`windows.pslist.PsList.json`) |
| `.gz`, `.zip` | `.gz` of any text format; `.zip` collections are read member by member (at most 5000 files) |
| A connector | "Pull evidence from a connector" calls one read-only tool (for example a Velociraptor MCP server's collection results) and imports what it returns, hashed like an upload. The connector's policy decides which tools are allowed. |

Evidence that names no host (memory-image output, for example) can be given one at upload (`--host` on the
command line).

Imports and analysis run as jobs: with `jobs.mode: queue` a worker (`actaeon worker`) runs them. Uploaded files are
kept until their import finishes; an import cut off by a restart shows as "interrupted" with an "Import again"
button that uses the kept file. Each file's SHA-256 is recorded before it is read, with its name, size, who imported it and when. The same file
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

- **Accounts**: per account, logons, failures, hosts and sources, and any source or host first seen more than a day
  after the account's first logon (often where lateral movement shows).

## Indicators and intel

"Check indicators against intel" takes addresses, DNS names and hashes from the fields that hold them, and URLs,
domains and addresses from command lines and scripts, skips private, loopback and link-local addresses, and looks
up the 500 most common in Actaeon's intel store and every intel connector with a `lookup` tool (Zarqa, for
example). Only the indicator value is sent, never the event. Known indicators become high detections on the
events that carry them; running the analyzers again keeps them.

## YARA

With `pip install 'actaeon[yara]'` and `dfir.yara_dirs` set, every evidence file (and every member of a zip) is
scanned when it is imported. A match becomes an event (log `yara`) with a detection; the level comes from the
rule's `severity`, `level` or `score` metadata (high when it has none). A rule file that does not compile is
skipped and named in the import note.

## Process tree

"Process tree" on any event rebuilds the parents above its process and the children below it on that host, from
Sysmon process GUIDs or from Security 4688 process ids and times. Events that only name a process (network,
file, registry, process access) are mapped to the process that made them. Processes with a high or critical
detection are marked.

## Hunting what you found

"Hunt for this in the live logs" on an event opens the Hunts page with a hypothesis and the event's key fields
filled in, to check whether the same activity happens on other hosts or accounts. Nothing runs until you start
the hunt.

## Alert cases

"Open an investigation" on an alert case copies its alerts and the log events its investigation found into a
new investigation (two evidence sources, hashed like files) and links the two; the alert case then shows an
"Investigation" button.

## Working as a team

An investigation has an assignee, a discussion (comments, which may name events as E123), and an activity log of
imports, analysis, marks, notes, stories, questions and changes, with who did each and when.

## ATT&CK Navigator

"ATT&CK Navigator layer" downloads the investigation's techniques (scored by events with detections) as a layer
file for the MITRE ATT&CK Navigator. The rule library's Coverage page has the same for rule coverage.

## Timeline

Words are searched through a full-text index (every word must appear; the last one may be the start of a word, so
`mimi` finds `mimikatz`); `field:value` matches inside one field (for example `Image:powershell`, `TargetUserName:admin`).
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

What the checks prove: every cited id is an event the model was shown, and each cited event is tested against
its statement without a model: it fits when one of its detections belongs to the phase's ATT&CK tactic, or when
it shares a significant word (a tool, host, account or file name) with the statement. Events that do not fit are
marked with a "?", and a part where no cited event fits is flagged. This catches citations that point at
unrelated events (in a test with a local 7B model, a registry backdoor cited for credential theft); it does not
prove the statement is true. Open the cited events before you rely on it.

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

- `field:value` searches use LIKE matching and slow down on cases with millions of events; word searches use the
  index on SQLite (a few milliseconds on 37,000 events). On PostgreSQL word searches match substrings without an
  index, so they slow down on very large cases there.
- python-evtx is slow on large logs; use the CLI, or set `dfir.evtx_dump`.
- Plaso l2tcsv rows in a time zone other than UTC get no time stamp; export from Plaso in UTC.
- Registry hives, prefetch, the MFT, shimcache, amcache, SRUM and memory images are not parsed directly; process
  them with your usual tools (Plaso, Velociraptor, Volatility) and load their CSV or JSON output.
- Measured on the EVTX-ATTACK-SAMPLES case: the process tree rebuilt cmd.exe, powershell.exe, cmd.exe,
  vssadmin.exe (the shadow-copy deletion) in order; YARA with a two-string mimikatz rule matched 4 event log files.
