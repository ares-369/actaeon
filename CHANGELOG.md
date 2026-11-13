# Changelog

## Unreleased

### Safety and cost
- `hunt.max_tokens`: a token budget per hunt; when it is used up the model must give its verdict.
- `hunt.max_query_sec` (default 120): one tool call, retries included, cannot run longer, nor past
  the hunt's own time limit.
- The search-index bridge also refuses leading wildcards inside raw query clauses (wildcard,
  regexp, query_string) on time-series indices.
- Tool results that try to instruct an AI ("ignore previous instructions", "mark this host as
  benign", chat-template tags, fake verdicts) are flagged: the hunt goes to an analyst as a
  high-severity "prompt injection" lead.
- Memory notes can expire; notes made from a benign or false-positive call expire after
  `memory.benign_note_days` (90 by default). The model sees who wrote each note and when.
- The audit log is hash-chained; `actaeon audit verify` and `GET /api/audit/verify` find changed
  or removed rows.

### Workflow
- Ticket replies: `POST /api/tickets/reply` turns an analyst's answer in a ticket into a question
  for Actaeon, a follow-up hunt (`/hunt ...`) or a resume (`/resume`). Answers go back through
  outputs that list `reply`. Optional bearer token scoped to that path (`tickets.token_env`).

## 0.1.0b1 (2026-11-13), first beta

The first version meant for others to try. It is read-only, it runs on one machine, and it has been
tested in one home lab and on public and synthetic benchmarks (see `docs/benchmarks.md` and
`docs/field-test-2026-11.md`). Expect rough edges; please report them.

### Hunting
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

### Data sources
- Every source is an MCP connector tagged with a role (log search, endpoint, identity, email, asset,
  network, cloud, intel). Read-only by default; response and destructive actions (isolate,
  quarantine, kill, delete, disable, revoke, block, ...) are always refused, whatever the config.
- Connector auth: bearer, API key, OAuth client credentials, and interactive OAuth sign-in
  (`actaeon connectors login`). Tested with the public MCP reference servers over stdio and HTTP.
- Built-in bridges for sources without an MCP server: search indices (with a snapshot mode for host
  inventory and compact results), SQL (SQLite, MySQL/MariaDB, PostgreSQL), STIX/TAXII 2.1,
  REST/OpenAPI and the web.

### Intel
- A local intel store: paste or import indicators and advisories (text, files, URL, PDF, HTML) with
  defang-aware extraction; a ledger with first and last seen; intel sweeps that search your logs
  for new or changed indicators and triage the matches.
- Web intel from RSS/Atom feeds and pages. Each new advisory is checked for relevance to your
  environment first; only relevant ones are hunted, and every decision is kept in the ledger.
- Threat-actor profiles and campaign hunts.

### Working with it
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

### Benchmarks
- `actaeon bench` with labelled cases, parallel workers and reruns of cases that fail on service
  errors; an ExCyTIn-Bench runner (`benchmarks/excytin/`) and a lab benchmark on a frozen copy of
  your own data (`benchmarks/lab/`).

### Fixed during testing
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
