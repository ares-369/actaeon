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
