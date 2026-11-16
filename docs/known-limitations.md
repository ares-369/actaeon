# Known limitations

Actaeon is in beta. These are the limits we know about.

## Hunting quality

- **Which models were tested.** The benchmarks and the field test used Gemini models (gemini-3.5-flash,
  gemini-3.8-flash, gemini-3.1-pro-preview, gemini-3.1-flash-lite). Other providers work through the same
  interface but have no measured results yet.
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
- Token use per hunt is measured in [benchmarks.md](benchmarks.md#token-usage). On the frozen lab data
  it is roughly 200k to 450k input tokens per hunt, more than half of them served from the provider's
  prompt cache when the provider has one.
- Two newer models did not work with Actaeon when tested (2026-11-14): Gemini 4 Hydrogen blocks the
  analyst prompt with a safety filter that the API settings do not switch off, and Gemini 4 Argon returns
  malformed tool calls even when no tools are declared. Hunts with them end as `inconclusive`.
- A cloud provider can refuse hunt prompts on policy grounds: they are full of attack techniques, malware
  names and prompt-injection text. During benchmark runs on 2026-11-14 the cloud project began to reject
  every request ("Request rejected in accordance with our terms of use and policies"). A local or
  self-hosted model avoids this; with a cloud provider, expect to talk to them if it happens.

- Host inventory is the last scan the agent sent. A machine that is switched off (a laptop, a
  dual-boot system) keeps months-old inventory and vulnerability data, and hunts cannot tell how old it
  is. Note such hosts in `environment.notes`, and remove agents of machines that no longer exist.

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

- Storage is SQLite by default: one machine. With `jobs.mode: queue`, hunts run in
  separate `actaeon worker` processes there. For several machines, choose PostgreSQL at
  install (`actaeon[postgres]`). It is new: CI runs the whole test suite against
  PostgreSQL, and it has not been used in a production deployment.
- A hunt interrupted by a restart continues from its stored steps (at most twice), but the model may
  take a different path from there than it would have without the interruption.
- Only one process schedules at a time (a lock file in the data folder, or a database lock with
  PostgreSQL); if it stops, another server or `worker --scheduler` takes over at its next tick.
- Hit counts for replays are read from common keys (`total`, `count`, `matches`,
  ...). Other result shapes fall back to "changed since last time".

## Alert triage

- **New.** Merged in November 2026 and tested on synthetic alerts and on real alerts from one home lab
  with one small local model (see [benchmarks.md](benchmarks.md)). Not run in a production SOC.
- **Small local models cannot triage.** qwen3:4b found none of 4 planted attacks on real data and called
  them false positives; the guards sent them to an analyst instead of closing them. Use a capable model for
  the analyst role; no larger model has been measured on alert triage yet.
- **Field mapping is heuristic.** Unusual alert formats need `soc.intake.field_map`. Indicators found in
  free text are shown on the case but never used to group alerts; they can be mis-typed.
- **Grouping is simple.** Shared host, user, source address, external destination, domain or hash within a
  time window. Shared infrastructure that every alert names must go in `soc.intake.no_group`, or it merges
  unrelated alerts. One incident with different entities can split across cases.
- **Exposure alerts** (a vulnerable package) do not fit the verdicts well: they are neither an attack nor a
  false positive. Expect `needs_analyst`.
- **Polling** starts each poll where the last one started, by the source's time field. Alerts that reach
  the source late, with an older timestamp, can be missed; push them to the webhook instead. A poll that
  fills its page (`page_full`) may have left alerts for the next poll.
- **Response actions** depend on the response connector. Actaeon does not verify that a tool does only what
  its name says, or that an undo really restores things.
- **The webhook** has a batch limit (1000) but no rate limit; use the daily limits for automatic triage.
