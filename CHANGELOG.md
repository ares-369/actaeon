# Changelog

All notable changes to Actaeon are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Actaeon is pre-1.0 beta software, so
behaviour may still change between releases.

## [Unreleased]

## [0.6.0-beta] — 2026-11-26

### Added

- Rule library (`rules:`, off by default; docs/rules.md): Sigma rules with versions and a draft, testing, ready,
  retired status. Each rule has sample-event tests that run locally with a built-in Sigma matcher (no log platform
  needed). A rule can be marked ready only with passing tests, at least one real event it must catch, one it must
  not, no check errors, and an approver other than the last editor. Checks warn about noisy values, missing ATT&CK
  tags, fields never seen in your data and duplicate logic.
- ATT&CK coverage by ready rules, with gaps from hunts that found threats, true-positive cases and
  `rules.priorities`. A model can draft a rule for a gap; its example events are marked synthetic and never count
  as real tests.
- A hunt's detection draft can be added to the library; the events behind the hunt's findings become real tests.
- Investigations (`dfir:`, off by default; docs/dfir.md): load evidence files (Windows event logs, JSON lines,
  CSV from Plaso or Hayabusa, syslog and auth.log, .gz and .zip collections) into a case, with each file's
  SHA-256 recorded first. One timeline across hosts with search, `field:value`, filters, stars, tags and comments.
  Analyzers run the rule library, 14 built-in checks and any Sigma folder over the evidence (logsource-aware),
  keep detections already in Hayabusa output, summarise logons (a success after a burst of failures is flagged)
  and stack the least frequent processes, parent-child pairs, services, tasks and logon sources. A model writes
  the story of what happened and answers questions, citing events; citations are checked and uncited parts are
  marked. Markdown report and CSV export, `actaeon dfir`, read-only MCP tools. Extra `actaeon[dfir]`
  (python-evtx); optional `dfir.evtx_dump` for faster event log reading.
- The local Sigma matcher also evaluates `fieldref` and items with no field name.
- Investigations: each cited event is checked against its statement without a model (detection tactic or a shared
  significant word); events that do not fit are marked and a part with no fitting event is flagged.
- Investigations: imports, analysis, intel checks and connector pulls run as jobs (queue-mode workers run them);
  uploads are kept until imported and an interrupted import can run again.
- Investigations: word search through a full-text index (FTS5, or a GIN index on PostgreSQL).
- Investigations: process tree around any event; accounts view with sources and hosts first seen late.
- Investigations: check indicators against the intel store and intel connectors (Zarqa); YARA scanning of evidence
  at import (extra `actaeon[yara]`); Volatility 3 JSON; pull evidence from a read-only connector tool; a host for
  evidence that names none.
- Investigations: hunt for an event's activity in the live logs; open an investigation from an alert case;
  assignee, discussion and an activity log; ATT&CK Navigator layers for a case and for rule coverage.
- `actaeon rules regress`: run labelled evidence through the analyzers and fail when a rule stops matching.
- `actaeon rules` (list, show, test, lint, coverage, draft, import, export), a zip export, and read-only MCP tools
  `list_rules`, `get_rule`, `rule_coverage`. Rules are never deployed into a log platform.

## [0.5.1-beta] — 2026-11-24

### Added

- An assistant panel opens from the title bar (Ctrl+I) on every page.
- Column sorting, a loading bar, a skip link, and keyboard access to rows that open something.
- `soc.never_dismiss`: rules whose alerts the model cannot call benign or a false positive (decoys, canaries); applied
  after every model pass. `soc.authorised_tests`: recorded test windows; a case is labelled an authorised test only when
  every alert matches a window's source, target and time; another alert that joins removes the label and sends the case
  back to triage.

### Changed

- The web UI has the same frame in OniOps, Actaeon and Zarqa: an icon sidebar that opens on hover and can be pinned, a
  title bar, dark and light themes, and on phones a bottom bar and tables shown as labelled records. New logo.

### Fixed

- Save on the Settings page stopped with an error, so model changes were not saved.
- Lead and case titles are shown on phones.
- Approving a response action asks first, naming the action, the target and whether it can be undone.
- Controls have accessible names and readable contrast.

## [0.5.0-beta] — 2026-11-23

### Added

- `actaeon detection-check RUN`: scores a run file of authorised tests by the layer each reached (alert source,
  Actaeon alert, case), with a control window so background alerts do not count. Reads only.
- CI: a UI smoke test opens every page of the offline demo in headless Chromium (desktop and phone width) and
  fails on script errors, failed requests or "undefined" on screen.
- Autopilot `intel_sources`: connector tools that return reports rated relevant to this environment become a
  planner input; hunts started from them carry the report as context, and a report is hunted once.

### Security

- Cross-origin state-changing requests are refused in every auth mode (before: only local and OIDC). Behind a proxy
  that does not pass the public host name, set the external URL.
- Handed-over hunt context and intel reports reach the model as untrusted data, and cannot close their own block
  (also after JSON decoding); advisory links are clickable only for http(s); non-ASCII tokens are refused cleanly.

### Fixed

- Alert intake re-reads `soc.intake.overlap_min` (default 30) minutes before its bookmark, so alerts indexed late are
  taken in; known alerts are skipped and not counted as repeats.
- Search index bridge: a partial answer (index recovering after a crash, or a timeout) is an error, not "no hits";
  alert intake no longer moves its bookmark past a gap it could not read.

## [0.4.3-beta] — 2026-11-20

### Added

- Hunts page: a link to `#hunts?hypothesis=...&context=...&from=...` fills in a new hunt (for example handed over
  from a threat intelligence tool). Nothing runs until an analyst reviews it and presses Start. The new hunt form
  also takes an optional context.

## [0.4.2-beta] — 2026-11-20

### Fixed

- Hunts with a local model stopped with "the prompt filled the context" once the evidence outgrew the model's
  window (every hunt on an 8192-token context could fail this way). The hunt now switches to compact prompts and
  tries again, then once more keeping only the latest result in full, and records each step in the hunt log.
- A high or critical alert whose dismissal is held for an analyst showed the AI's lower severity (for example
  LOW) next to a check saying it was high. The check now says what severity the alert came in with, and the case
  keeps that severity until an analyst decides.
- The web UI had no favicon, so every page load logged a 404.

## [0.4.1-beta] — 2026-11-20

### Security
- An IPv4 address followed by a full stop ("login from 10.1.2.3.") was not recognised. So an internal address at
  the end of a sentence was not masked before a prompt went to a cloud model, the web bridge's leak guard did not
  refuse it, and indicator extraction and the decoder missed it. Fixed in all four places, with a test.

### Measured
- Alert triage on attacks the rules were never written for (6 new attacks and 4 look-alikes, planted after the
  rules, labels and a prediction written first, run once with no tuning): fixed checks with no model found none
  of the 6 with no false alarm; qwen3:4b with the checks found none and called one look-alike an attack. Nothing
  was wrongly closed: all 6 went to a person with the evidence collected. The earlier 9/9 was in-sample and does
  not carry over. See docs/benchmarks.md.

## [0.4.0-beta] — 2026-11-16

Alert triage no longer needs a model.

### Added
- **Fixed evidence checks** before any model sees a case (`soc.collect`, on by default): decode the command
  line, look indicators up in intel, read the host's events around the alert, read what runs, listens and
  which accounts exist on the host, count the accounts a source tried and its successful sign-ins, and see
  which other hosts contacted the same destination. Field names are found per connector with `get_fields`
  (or set with `fields:` on the connector). Results are stored as evidence and read in full.
- **Signals** from plain rules over those results, each citing its evidence (intel match, decoded download,
  download piped into a shell, process from a temporary path, hidden listening process, non-root account with
  user id 0, password spraying, success after failures, Office starting a shell, spread, known-good match). A
  finding only counts for the alert when it concerns the alert's own process, account, command, address or
  domain; other findings on the host send the case to a person ("the host also shows ...").
- **`soc.analysis: rules`**: triage with no model at all. With a model (`ai`), the model can add to what the
  fixed checks proved but not take it away (an evidence-backed attack signal keeps the case a true positive, with
  the model's view shown against it), and a failed or unreachable model falls back to the rules' verdict.
- **`soc.escalate`**: re-run hard cases (undecided, unconfirmed, or rules and model disagreeing) on a stronger
  model you choose, for high and critical cases only, within a daily limit.
- Playbooks list their fixed checks (`collect:`); `decode` and `intel` always run.
- `triage-bench --analysis rules|ai`; the case page, report and evidence bundle show the signals.

### Measured
- 9 labelled cases over the lab's real data (4 planted attacks, 5 real non-threat alerts): qwen3:4b alone 5/9 (0
  of 4 attacks); fixed checks with no model 9/9 (4 of 4) in 9 s per case; qwen3:4b with the fixed checks 9/9 (4
  of 4, one fewer case for a person), 0 false alarms and 0 wrong closures. The rules were tuned on these cases. On
  three days of live lab alerts (out of sample) the no-model rules raised no false alarm. See docs/benchmarks.md.

### Fixed
- Tool results on alert cases are stored up to 200 kB (was 20 kB), with a note when cut.
- When the evidence overrules the model, the case keeps the alert's title, not the model's.

## [0.3.0-beta] — 2026-11-16

Alert triage joins hunting: the agentic SOC work done as Haymdhal is now part of Actaeon.

### Security
- Secret-shaped values (private keys, cloud and code-hosting tokens, JWTs, bearer tokens, URL passwords,
  values of password/secret/token keys) are removed from every prompt for every provider before it is sent
  (`privacy.strip_secrets`, on by default). This applies to hunts too.

### Added
- **Alert triage** (`soc:` in config.yaml, docs/alert-triage.md). Alerts arrive through `POST /api/alerts`
  (login, or a send-only bearer token), a polled connector tool (new `alerts` connector role) or
  `actaeon alerts import`. They are normalised, suppressed, de-duplicated and grouped into cases. Each case
  gets a first look (planner model: priority and questions) and an investigation (analyst model) through the
  same read-only connectors as hunts, with playbook guidance. Verdicts: true positive, false positive,
  benign, needs analyst, logs missing, with a summary, findings and timeline tied to evidence, entities,
  ATT&CK techniques, a fix (remediation steps or a tuning proposal) and proposed actions. The same kind of
  checks as hunt verdicts apply, and a second look tries to prove true positives wrong, and serious
  dismissals right.
- Case pages with the entity graph, timeline and ATT&CK chain; a triage dashboard (verdicts per day,
  AI and analyst agreement, noisiest rules, tokens per day); approvals; suppressions with expiry and a
  warning when they hide high-severity alerts; a shift report. "Hunt this" starts a full hunt from a case.
- **Approval-gated response actions** (`soc.response`, docs/response.md), off by default: configured
  per connector with the new `response` role, proposed on true positives, run only after a person approves
  the exact call (optionally two people), bound to the case as reviewed, with reversible or compensating
  undo, audited. Destructive operations are never possible. Hunts and investigations still never see
  response tools.
- `actaeon triage-bench`: scored triage on the labelled demo cases, or on your own labelled alerts
  (`--cases FILE`), with recall, precision, hand-overs, wrong closures, evidence coverage, tokens and time.
- Every verdict lists the cited facts that point against it and what could not be established; cited
  contradicting evidence caps the confidence at 70.
- Sealed evidence bundle per case (`actaeon cases export` / `verify`, `GET /api/cases/<id>/evidence.json`):
  alerts, every tool call and result with digests, verdict, second look, actions, notes, digests of every
  prompt and reply, audit rows and chain head, HMAC-SHA256.
- Separation of duties for response: whoever proposed an action cannot approve it (unless
  `allow_self_approval`); proposals expire after `proposal_hours`.
- `triage-bench --record` / `--table`: a per-model suitability table; untested providers read "not measured".
- MCP tools `list_cases`, `get_case`, `submit_alerts`, `triage_case` (no tool approves an action). Case
  outputs: `when: [case_true_positive, case_needs_analyst, case_action_proposed, ...]`.
- Investigation graph: every node and link carries the first and last time it was seen in the hunt's
  events (shown when you click a node or hover a link, and in `GET /api/hunts/<id>/graph`).

## [0.2.1-beta] — 2026-11-15

### Added
- qwen3:4b measured on a 4 GB laptop GPU (`docs/local-models.md`, `docs/benchmarks.md`): 4 of 8 demo cases
  correct, 1 of the 4 planted threats found, no false alarms; 4 to 13 minutes per hunt with thinking on.

### Fixed
- Reasoning models on Ollama (such as qwen3): their thinking counts against the reply limit, so a 900-token
  limit could be spent entirely on thinking and return an empty answer. The provider now leaves extra room
  (`think_tokens`, default 6000; a cap, so other models are not slowed) and reports an answer-less reply
  as an error. With this Ollama version, `think: false` made qwen3 write its reasoning into the answer
  instead of skipping it, so leave `think` unset for it.

## [0.2.0-beta] — 2026-11-15

### Security
- Two more checks on the verdict, so a confused model cannot quietly close a real finding: a `no_results`
  whose own findings cite searches that matched becomes `inconclusive` and goes to an analyst, and a
  `benign` verdict when an intel lookup matched is capped at confidence 50 and goes to an analyst. Both
  were seen with a local 7B model on the demo cases.
- Scheduled replays run as the person who saved the hunt; the scheduler's own work can be given an identity
  (`scheduler.groups`); notes and saved hunts made from restricted hunts are restricted; the audit log names
  the identity a call ran as.
- The prompt-injection scanner also checks a normalised copy of each result (look-alike letters, words
  split by `-`, `_`, `.`), payloads the offline decoder unpacks, and a few other languages, with broader
  phrasings. Measured on new scored sets in `benchmarks/injection/`: 24/24 on the set it was tuned on,
  9/10 on a held-out set scored once, 0 false alarms on both and on 9,459 real lab alerts.

### Added
- `docs/local-models.md`: running with a local model, and what qwen2.5-coder:7b on a 4 GB laptop GPU did on
  the demo cases (3 of 8 correct over two runs, none of the 4 planted threats found, no false alarms).
- Ollama provider settings `num_ctx`, `timeout_sec` and `think` (turns off a reasoning model's thinking
  step).
- Inventory drift: what is new on each host since the last snapshot (ports, accounts, services,
  processes), with no model; new items and new hosts open a lead (docs/drift.md).
- Entities across hunts: hosts, users, IPs, domains and hashes that findings relied on, with their history
  and a "recurring" flag for entities in several recent unresolved hunts (docs/entities.md).
- Investigation graph on each hunt: user, host, process, destination and intel match, linked to evidence.
- Hunt profiles (quick, standard, deep), hunts that resume after a restart, and retention of old hunts.
- PostgreSQL: `actaeon db migrate` copies a SQLite data folder; the scheduler lock is held in the database.
- Search-index bridge: `--leading-wildcard-hours` allows leading wildcards over short windows, so converted
  Sigma `contains` rules can be backtested (counted day by day).
- Three Gemini models on the lab benchmark, and the token usage per hunt, in docs/benchmarks.md.
  gemini-3.8-flash 10 to 11 of 11 over four runs, gemini-3.1-pro-preview 9 of 11, gemini-3.1-flash-lite
  8 of 11; no false positives. Gemini 4 Hydrogen and Argon did not work (known limitations).
- `benchmarks/excytin/analyze.py` sorts every missed question by cause from its stored tool calls. On the
  recorded 80-question run: 18 ran out of tool calls (11 of them had already seen the answer), 8 were
  model service errors, 6 malformed tool calls, 5 never reached the evidence, 3 saw it and answered
  wrong. The runner now retries questions that die on a service error.
- A second held-out prompt-injection set (multi-step, encoded, multilingual, email-borne), scored once:
  11 of 16 attacks caught, 0 of 12 benign look-alikes flagged. Misses (non-English, non-Spanish text
  and authority-style wording) are listed in docs/hunting.md and left unfixed in the score.

### Changed
- README screenshots rebuilt from the current demo, shown under the demo GIF: a finished hunt, the
  investigation graph, entities, leads and ATT&CK coverage.
- Version format matches the author's other tools: `0.2.0-beta` in the code and tags, `0.2.0b0` on PyPI.
  `docs/project-standard.md` lists the shared naming, packaging and release rules. Install with
  `pipx install actaeon`; publishing a GitHub release uploads to PyPI (trusted publishing).
- The changelog follows Keep a Changelog; `SECURITY.md` has the same layout as the other tools.
- The icon font ships only the 100 icons the UI uses (7 KB instead of about 3.6 MB of font files), so the
  wheel drops from 2.5 MB to about 0.36 MB. CI checks the five required packages and the wheel size, and
  the wheel smoke test runs the offline demo.
- When every search in a hunt matched nothing and the model answers `no_results`, it is asked once to
  search again more broadly first (small models tend to stack guessed filters into one query and stop).
- `actaeon hunt --plan-only` (also `POST /api/hunts/plan` and a **Plan only** button): the planning step
  alone, with no data queried and no hunt stored.
- Token usage records the part of the input served from the provider's prompt cache (Gemini, Claude,
  OpenAI-compatible) next to input and output; hunt pages, reports and `actaeon bench` show it.
- Fewer tokens per hunt: older tool results are shortened in batches so the prompt start stays the same
  (and can be cached), the analyst is told to stop once the evidence answers the hypothesis and sees the
  calls used on each result, and tool results default to 8,000 bytes. On the lab benchmark with
  gemini-3.8-flash: about 210k to 250k input tokens per hunt, down from about 440k, with the same score.
- Gemini: optional `thinking_budget` / `thinking_level`.
- Usage is reported in tokens only (the optional `llm.prices` setting was removed).
- `docker compose --profile demo up demo`: the synthetic demo in a container, in memory, on port 8611.
- README: CI, licence and Python badges, a diagram of a hunt, a plainer opening, the bridge types and the
  offline decoder named, PostgreSQL and worker install lines.

### Fixed
- Bridges accept relative times rounded down (`now-7d/d`, `now/h`), as search indexes do; they were
  refused before.
- The investigation graph was wider than its box at laptop widths and cut off the Intel column; it now
  shrinks to fit (and scrolls on small screens). The top bar no longer wraps to two lines at 1280 px
  now that it has an Entities tab (labels hide below 1240 px, icons stay).
- The demo data source read a range such as `@timestamp:[now-7d TO now]` as three loose words and
  matched nothing; it now supports ranges, as real search indexes do. Found by a local 7B model that
  writes its time window into the query.
- Local models: Ollama was called with its own default context window (2,048 to 4,096 tokens), which
  silently drops the start of a longer prompt. Actaeon now asks for `num_ctx` tokens (default 8192,
  `llm.providers.ollama.num_ctx`) and reports a prompt that still fills the window as an error instead of
  using the answer. The request timeout is configurable (`timeout_sec`, default 300).
- Chat and the second look on threats failed silently on newer Gemini models (every reply a malformed
  tool call), so threats were never confirmed. Every tool loop now declares its final action as a native
  tool next to `call_tool`, and requests without tools say so. With gemini-3.8-flash the second look now
  confirms threats (confidence 80 to 95 instead of a cap of 60).
- A malformed tool call that repeats after the retry is treated as an unusable reply (asked again), not
  as an error that ends the hunt.
- Parallel workers upgrading the same database could crash on "duplicate column"; column migrations are
  now safe to run at the same time.
- `actaeon bench`: one case raising an exception no longer ends the whole run.
- Gemini: the civic-integrity and jailbreak filters are relaxed along with the others.

## [0.1.0b2] — 2026-11-14

Still a beta: tested in one home lab, on public and synthetic benchmarks, and in CI (the whole test
suite on SQLite and on PostgreSQL), not yet in production.

### Security
- `hunt.max_tokens`: a token budget per hunt; when it is used up the model must give its verdict.
- `hunt.max_query_sec` (default 120): one tool call, retries included, cannot run longer, nor past
  the hunt's own time limit.
- The search-index bridge also refuses leading wildcards inside raw query clauses (wildcard,
  regexp, query_string) on time-series indices.
- Tool results that match known prompt-injection patterns ("ignore previous instructions", "mark
  this host as benign", chat-template tags, fake verdicts) are flagged: the hunt goes to an analyst
  as a high-severity "prompt injection" lead. Pattern-based, so it catches blatant attempts only.
- Memory notes can expire; notes made from a benign or false-positive call expire after
  `memory.benign_note_days` (90 by default). The model sees who wrote each note and when.
- The audit log is hash-chained; `actaeon audit verify` and `GET /api/audit/verify` find changed
  or removed rows.
- Roles from identity-provider groups (`auth.group_roles`, OIDC `groups_claim`, proxy
  `proxy_groups_header`, `require_group_role`).
- Per-connector `access` (groups, `role:`, `user:`). People outside it cannot use the connector, and
  hunts that read it are hidden from them everywhere (hunts, leads, reports, exports, memory,
  assistant conversations, detection drafts) and are not sent to outputs unless an output opts in.
  See docs/access.md.

### Added
- Storage choice at install: SQLite stays the default (nothing to install); PostgreSQL is optional
  (`actaeon[postgres]`, `actaeon init --database postgres`, the installer asks). The stores share one
  code path; PostgreSQL gets its own full-text search and audit-log triggers. CI runs the whole test
  suite on PostgreSQL.
- `jobs.mode: queue` and `actaeon worker`: the web server records jobs as named tasks and worker
  processes run them, as the person who started each one. Stop and pause work across processes,
  stale jobs are marked interrupted, and a lock file keeps a single scheduler. With SQLite, workers
  run on the same machine as the server; with PostgreSQL they can run elsewhere (tested in CI on one
  machine, not yet across several).
- Sigma drafts are converted with pySigma (optional `actaeon[sigma]` plus your platform's backend) into
  each connector's query language, set per connector with a `sigma:` block, and the converted query is
  backtested. `actaeon sigma backends|convert`, `/api/sigma/convert`, `/api/sigma/backends`.
- Hunt packs: the 65 starter hypotheses are now one YAML file per hunt under `actaeon/hunts/<tactic>/`,
  with a schema, `actaeon library validate`, and `hunt.library_dirs` for private packs.
- STIX 2.1 export of the intel store (`actaeon intel export`, `/api/intel/export.stix`) and of a hunt
  (indicators, techniques and a report; **STIX** button). New `taxii` output pushes a hunt's bundle to a
  TAXII 2.1 collection.
- `actaeon connectors check`: a contract check for hunting connectors (read-only hints, time ranges,
  result caps, descriptions, TLS, timeouts), and a one-file connector template that passes it.
- `actaeon bench --model provider/model` and `--role-model`, with `--markdown` for the per-model results
  table in docs/benchmarks.md.
- Air-gapped guide, and a test that runs the offline demo and the UI with outbound connections refused.

### Changed
- Ticket replies: `POST /api/tickets/reply` turns an analyst's answer in a ticket into a question
  for Actaeon, a follow-up hunt (`/hunt ...`) or a resume (`/resume`). Answers go back through
  outputs that list `reply`. Optional bearer token scoped to that path (`tickets.token_env`).

### Fixed
- Search-index bridge: a query string with a leading wildcard on a log index now fails with a clear
  error. The index answered 0 for it, which a hunt could read as "nothing there".

### Removed
- The Excel output and the `excel` extra. Use the email output for alerts; every hunt can still be
  downloaded as CSV, JSON, PDF or Word. A config that still has `type: excel` stops with a message
  saying so.

## [0.1.0b1] — 2026-11-13

The first version meant for others to try. It is read-only, it runs on one machine, and it has been
tested in one home lab and on public and synthetic benchmarks (see `docs/benchmarks.md` and
`docs/field-test-2026-11.md`). Expect rough edges; please report them.

### Added
- Every source is an MCP connector tagged with a role (log search, endpoint, identity, email, asset,
  network, cloud, intel). Read-only by default; response and destructive actions (isolate,
  quarantine, kill, delete, disable, revoke, block, ...) are always refused, whatever the config.
- Connector auth: bearer, API key, OAuth client credentials, and interactive OAuth sign-in
  (`actaeon connectors login`). Tested with the public MCP reference servers over stdio and HTTP.
- Built-in bridges for sources without an MCP server: search indices (with a snapshot mode for host
  inventory and compact results), SQL (SQLite, MySQL/MariaDB, PostgreSQL), STIX/TAXII 2.1,
  REST/OpenAPI and the web.
- A local intel store: paste or import indicators and advisories (text, files, URL, PDF, HTML) with
  defang-aware extraction; a ledger with first and last seen; intel sweeps that search your logs
  for new or changed indicators and triage the matches.
- Web intel from RSS/Atom feeds and pages. Each new advisory is checked for relevance to your
  environment first; only relevant ones are hunted, and every decision is kept in the ledger.
- Threat-actor profiles and campaign hunts.
- Web UI (leads, hunts, ask, library, intel, coverage, reports, connectors, settings), with a
  phone layout. Leads with acknowledge, assign, close and history; reports in PDF, Word and
  Markdown; outputs to email, Excel, a webhook or an allowed tool.
- Auth: none (loopback only), basic, local accounts, OIDC or a trusted reverse-proxy header, with
  viewer, operator and admin roles. It will not listen on a network address without a login.
- Models per role (planner, analyst, reporter): Ollama, Anthropic, Gemini (API key or Vertex AI),
  OpenAI, Azure OpenAI, any OpenAI-compatible endpoint, or a signed-in model CLI; fallbacks,
  retries on rate limits, native tool calling where supported, token and cost tracking per hunt.
  Personal data is masked before prompts reach cloud models.
- Actaeon as an MCP server for other agents (`actaeon mcp`, `POST /mcp`).
- Install with `scripts/install.sh` (systemd), Docker, or `pip install -e .`; `actaeon doctor`
  checks a setup; `actaeon demo` runs on synthetic data with no model needed.
- `actaeon bench` with labelled cases, parallel workers and reruns of cases that fail on service
  errors; an ExCyTIn-Bench runner (`benchmarks/excytin/`) and a lab benchmark on a frozen copy of
  your own data (`benchmarks/lab/`).
- Give a hypothesis; Actaeon plans the hunt, queries your sources, pivots on what it finds and
  writes a verdict (threat, no results, benign activity found, logs missing, inconclusive) that
  cites its evidence and maps to MITRE ATT&CK.
- Checks on every verdict: claims must cite successful results, the values a claim names must
  appear in that evidence, a threat needs corroboration and gets a second look, and missing data
  is reported as missing, never as clean.
- When it cannot answer (out of steps, data missing, threat not confirmed, only known-good things
  found, an error), the hunt is handed to an analyst: a "needs analyst" lead with what was
  searched, what was missing and what to check next.
- Environment profile: platforms, products, key assets, what is not present and what is known good,
  given to every hunt.
- 65 starter hypotheses including baseline and rarity hunts, a hunt library with scheduled replays
  that need no model, hunt memory and analyst notes, chat about a finished hunt, a timeline,
  draft detection rules (native queries and a checked Sigma draft) and a backtest of how often
  they would have fired.
- ATT&CK: IDs are checked against the bundled release (20.1) and revoked IDs map to their
  replacement; a coverage view shows breadth per tactic and the log sources behind gaps.

### Fixed
- Two hunts sharing one connector process could lose each other's replies.
- Filtered field lists made the field guard refuse valid fields.
- The model's last-turn tool call or a malformed reply could end up as the answer.
- Per-hunt token counts showed the server's running total.
- Loopback and private addresses from news articles were stored as indicators.
- Short rate limits locked a model out for an hour.
- A count that matched an indicator did not count as evidence for it.
- Table cells in the UI broke words in the middle.

### Known limitations
See `docs/known-limitations.md`. In short: one process with SQLite (no high availability), benchmark
numbers for one model only, and hunts flag your own administration until the known-good list
describes it.
