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
