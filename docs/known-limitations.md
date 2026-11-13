# Known limitations

Actaeon is in beta (0.1.0b1). These are the limits we know about.

## Hunting quality

- **Which model was tested.** Every result in the benchmarks and the field test used one fast cloud
  model for all roles. Other providers work through the same interface but have no measured results yet.
- **Small local models are not good enough to hunt.** Early on, a 7B local model was tried on the demo
  data, where the attack is present: its tool calls worked and the field guard corrected its made-up
  field names, but its query logic was wrong and it answered `no_results`, a false negative. Use a
  stronger model at least for the analyst role; a small local model is fine as a fallback.
- The verdict checks make sure every claim cites a result that exists and succeeded, and that
  indicators and quoted identifiers in a claim appear in the evidence. They cannot check that the
  model interpreted the result correctly. Read the cited evidence before acting.
- ATT&CK IDs are checked against the bundled release (unknown IDs dropped, revoked ones mapped to
  their replacement), but whether a technique fits the activity is the model's judgement.
- Benchmarks so far: an 8-case synthetic demo suite, a sample of the public ExCyTIn-Bench, and an
  11-case lab benchmark on a frozen week of one home lab's data (see benchmarks.md). The samples are
  small, the lab cases were written by someone who knew the answers, and results vary between runs.
  Nothing has been measured in a production environment yet.
- Hunts flag the environment's own administration (custom services, planned changes) unless the
  environment profile describes it. List normal activity in `environment.known_good` and
  `environment.notes`; a threat that only names known-good items is handed to an analyst rather
  than dropped.
- The analyst model reports whether the data a hypothesis needs exists at all; if it gets that wrong,
  a hunt can still say `no_results` where `logs_missing` is right.
- Native tool calling (Claude, Gemini, OpenAI-compatible providers) falls back to the JSON action
  protocol when a model rejects tools (`native_tools: false` turns it off). It has been exercised live
  with one cloud provider so far. Ollama and the `cli` provider always use the JSON protocol, which
  costs more tokens.
- A hunt uses roughly 400k to 500k input tokens with the fast cloud model (about 25 tool calls).

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
- The URL guard for advisory import checks DNS before connecting and pins the
  checked address for the request. Requests through an HTTP proxy are resolved by
  the proxy and are not pinned.

## Connectors and bridges

- The MCP client is Actaeon's own small implementation (initialize, tools/list,
  tools/call, stdio and streamable HTTP). Resources, prompts, sampling and
  server-sent notifications are not used. Auth: bearer, API key, OAuth client
  credentials and interactive OAuth sign-in (authorization code + PKCE).
- Tested against Actaeon's own bridges and the public MCP reference servers; vendor
  MCP servers for SIEM/EDR products have not been tried yet.
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
