# Known limitations

Actaeon is pre-alpha. These are the limits we know about.

## Hunting quality

- Results depend on the model. Small local models (7B class) plan weaker hunts,
  write poorer queries and sometimes pick the wrong ATT&CK technique. ATT&CK IDs
  are checked for format only, not meaning.
- The verdict checks make sure every claim cites a result that exists and
  succeeded. They cannot check that the model read the result correctly. Read
  the cited evidence before acting.
- One informal check: a 7B local model was run on the demo data, where the attack is
  present. Its tool calls worked, and the field guard corrected its made-up field
  names, but its query logic was still wrong and it answered `no_results`, a
  false negative. Use a stronger model for the analyst role.
- No benchmark has been run. There are no published detection or accuracy numbers.
- Claude, Gemini and OpenAI-compatible providers use native tool calling and
  fall back to the JSON action protocol when a model rejects tools (turn it off
  with `native_tools: false` in the provider config). The native path is only
  unit-tested; it has not been run against live cloud models yet. Ollama and
  the `cli` provider always use the JSON protocol, which costs more tokens.

## Safety layers and their gaps

- Read-only enforcement is layered: the connector policy (deny/allow lists,
  write-like names and hints), the query validator, and the bridges' own limits.
  The name and pattern checks are heuristics and can be wrong in both directions.
  The strongest control is a read-only account on each source; use one.
- Tool output is wrapped as untrusted data, and the model is told not to follow
  instructions inside it. This lowers prompt-injection risk; it does not remove it.
  A crafted log line can still mislead the model's reasoning. It cannot make
  Actaeon call write tools that the policy blocks.
- Privacy masking is pattern-based. Unlabelled usernames and hostnames are missed
  unless you add terms or patterns. See docs/privacy.md.
- The URL guard for advisory import checks DNS before connecting. A host that
  changes its DNS answer between the check and the connection (DNS rebinding) is
  not covered.

## Connectors and bridges

- The MCP client is Actaeon's own small implementation (initialize, tools/list,
  tools/call, stdio and streamable HTTP). Resources, prompts, sampling and
  server-sent notifications are not used. Interactive OAuth sign-in
  (authorization code) is not supported; client credentials, bearer and API key are.
- So far it has been tested against Actaeon's own bridges and test servers, not a
  wide range of third-party MCP servers.
- The search-index bridge uses the common `_search` API; other query languages
  need their own MCP server or the OpenAPI bridge.
- `find_indicator` in the TAXII bridge scans patterns by substring and is slow on
  large collections.
- Intel extraction is pattern-based: review the preview before saving.

## Operations

- Single process: hunts run on a thread pool inside the web server, with SQLite
  storage. No clustering or high availability.
- Hunts that are running when the server restarts are marked stopped.
- The scheduler runs inside the server; with several server processes,
  schedules would run more than once.
- Hit counts for replays are read from common keys (`total`, `count`, `matches`,
  ...). Other result shapes fall back to "changed since last time".
