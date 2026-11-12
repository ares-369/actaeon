# Changelog

## Unreleased
- Foundation: YAML + .env config, model providers with per-role models and a Settings
  model picker, auth modes (none/basic/local/oidc/proxy) with RBAC, SQLite job engine
  with stop/pause, waitress server with a startup security check, CLI, tests and CI.
- Connector hub: MCP client for stdio and streamable HTTP (bearer, API key, OAuth client
  credentials), role tags, read-only policy with allow/deny lists, untrusted-data wrapping,
  per-connector pacing, 2 retries with backoff, append-only audit log, API and CLI.
- Bridges (`actaeon bridge ...`): built-in stdio MCP servers for search indices (`_search` API,
  time-bounded, capped, index allowlist, no scripts), STIX/TAXII 2.1 (read-only) and
  REST/OpenAPI (GET only, POST only when named).
- Local intel store: add indicators and advisories (paste with defang-aware extraction,
  files, URL feeds); ledger with first/last seen and count; served to hunts as the built-in
  read-only `local-intel` connector; UI panel, API and `actaeon intel` CLI.
- Hunt engine: planner and analyst roles, a JSON action protocol that works with any
  provider, a query validator, evidence ids, checked verdicts (threat / no_results /
  telemetry_found_benign / logs_missing / inconclusive), step, time and size limits,
  stop/pause/resume, API and `actaeon hunt` CLI. Provider settings accept `${VAR}`.
- Hunt library: save finished hunts, replay them on a schedule without a model, escalate
  replays with matches to a full hunt; 16 generic starter hypotheses.
- Intel sweeps: ledger-driven searches for new or changed indicators with per-value
  attribution; advisory hunts; hunt memory (past verdicts and analyst notes, FTS5).
- Intel timestamps now use microseconds so the ledger never skips or repeats an indicator.
- Web UI: hunts (start, live steps, stop/pause, verdict with clickable evidence), library,
  intel, coverage, connectors and settings (models, memory notes, audit log). Strict CSP,
  no inline script, untrusted data only rendered as text.
- Reports: Markdown report, JSON and CSV export (formula-safe), optional reporter-model
  narrative kept apart from the record. ATT&CK coverage view from hunts, saved hunts and starters.
- Privacy masking for cloud model providers (emails, IPs, labelled usernames, custom terms and
  patterns), restored in replies so tools get real values.
- Offline decoder (`actaeon decode`, built-in `local-tools` connector, role `analysis`).
- Environment profile, finding feedback (benign / false positive / confirmed, saved to memory),
  advisory import from URL, PDF or HTML with private-address and redirect checks.
- Actaeon as an MCP server: `actaeon mcp` (stdio) and `POST /mcp` (HTTP) with role checks per
  tool, an optional `/mcp`-only bearer token, and opt-in intel writes.
- Demo mode (`actaeon demo`): synthetic, labelled sample data through a demo bridge, a sample
  advisory and note, a UI banner, and an optional scripted offline run that is marked as not AI.
- Docs: known limitations, threat model, contributing, security policy.
- Engine fixes found with a real 7B model: refused and unknown calls now use the step budget
  (no loops), tool resolution tolerates "connector.tool" and role names, `*` copied into
  argument names is stripped, and the tool list format is clearer.
- Field guard: before the first query on a connector that offers get_fields, the engine fetches
  the field names itself and refuses queries that use fields the source does not have
  (with close-match suggestions). Found with a 7B model that guessed field names.
- Autonomy: web intel sources (RSS/Atom/pages) with optional auto advisory hunts; autopilot that
  proposes checked hypotheses from new advisories, coverage gaps and follow-ups and hunts them
  within caps; web lookups during hunts with a leak guard.
- `cli` model provider for signed-in model CLIs; per-role fallback models with quota cooldown.
- Web and imported advisories keep domains, URLs and emails only when the text defanged them,
  and never the publisher's own domain (a live pull showed reference links being stored as IOCs).
- The field guard reuses the model's own get_fields result instead of fetching it twice.
- Stricter threat verdicts: the analyst is asked once to corroborate (intel lookup, decode, a pivot)
  before a 'threat' verdict; confidence is capped at 60 with one piece of evidence and at 75 when all
  evidence comes from one kind of query.
- `connectors test` now reads from the source (list_indices, list_collections and similar), so a wrong
  password shows up as a failure instead of an OK.
- IOC triage in sweeps: each match is executed / blocked / passive / unknown (rules, optional model second
  look); only executed matches make a threat.
- Gemini provider: API key, Vertex AI (service account, workload identity, VM identity, gcloud login),
  Vertex express key, AI gateway base URL and headers; `actaeon models test` and a UI Test button.
- Outputs: email (SMTP, extra recipients for critical), Excel workbook rows, webhook and an allowed MCP tool
  (e.g. create a case); `actaeon outputs test`.
- Query guides per connector (notes, file, examples, plus queries that found data before) and a compact
  prompt mode for cheaper models.
- Docker image (non-root, read-only root, health check) and compose file; CI builds and checks it.
- Ask Actaeon: chat on a finished hunt with read-only follow-up calls added as evidence.
- Threat-actor profiles and campaigns: actor indicators swept with triage, plus a model hunt for its
  techniques and tools; actors feed autopilot.
- Detection drafts: the hunt's working native queries plus a checked Sigma draft (experimental).
- Timeline per hunt from its evidence (entities, states, filters), also in the report.
- UI fixes found by clicking through in a browser: action buttons sent GET instead of POST (pause/stop, run,
  delete, test, sweep, web pull, actor hunt, narrative, detection, model test); finished hunts re-drew every
  2 s and wiped open panels; lists printed as text. A test now checks every UI call against the server routes.
- Second look: threats are re-checked by a sceptical verifier pass that re-queries (confirmed / refuted /
  unconfirmed); shared read-only tool loop for chat and verification. CI container name fix.
- Cases: auto-opened for threats and review items; acknowledge (assign to me), assign, in progress, close with
  resolution and comment, reopen, comments, full history, stats (time to acknowledge / close).
- Named accounts for basic/local login (`actaeon users add`), the signed-in user on every request, login page.
- Ask assistant: questions and hunt requests in plain language; it searches records, starts stored hunts
  (origin ask:<user>), follows up on hunts, and saves the conversation with links.
- Reports in PDF, Word and Markdown: per hunt, per case, and a period summary (`actaeon report`, UI, API).
