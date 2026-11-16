# Changelog

All notable changes to Actaeon are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Actaeon is pre-1.0 beta software, so
behaviour may still change between releases.

## [Unreleased]

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
