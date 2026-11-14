# Threat model

What Actaeon protects, from whom, and how. Beta (0.1.0b2): treat this as a working draft.

## Assets

1. Access to security data sources (log search, endpoint, identity, and so on)
   through connector credentials.
2. The data itself: events and intel, which can contain personal data.
3. Hunt records, reports, memory notes and the audit log.
4. Model provider keys.

## Trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| Web UI / API / `/mcp` | authenticated users with a role | the network |
| Connector hub | Actaeon's policy and validator | MCP servers and everything they return |
| Model | Actaeon's checks of every action | model output (it can be wrong or steered) |
| Intel import | the analyst who imports | the content of feeds, advisories and URLs |

## Threats and controls

**T1. A model (wrong or steered by injected text) tries to change or delete data.**
Tools are read-only by default: deny/allow lists, write-like names and server
hints are blocked, and write tools need `allow_write` plus an exact allow entry.
Response and destructive actions (isolate, quarantine, kill, delete, disable,
revoke, block, ...) are blocked whatever the configuration says.
The query validator refuses write, delete, index-change and code-execution
patterns. Bridges expose only read endpoints. Every call is audited.
*Residual:* the heuristics can miss a write path on a source with unusual tool
names. Use read-only credentials on every source.

**T2. Prompt injection through log content, intel or advisories.**
All tool output is wrapped in nonce-tagged untrusted-data markers, and copies of
the marker inside the data are altered. The system prompts say to treat the
content as data. Verdict claims must cite real successful results. Results that
contain text addressed to an AI are flagged: the hunt goes to an analyst as a
high-severity "prompt injection" lead. Benign memory notes expire (90 days by
default), so a wrong or socially-engineered "benign" call does not blind later
hunts for good.
*Residual:* the model's reasoning can still be misled, and the injection patterns
only catch blatant attempts; findings need analyst review.

**T3. A data source tries to drive the model or the user.**
Server-to-client MCP requests (sampling, elicitation, roots) are refused, and
stdio connectors get a minimal environment.

**T4. Unauthorised use of the UI, API or MCP endpoint.**
Auth modes are basic, local (hashed passwords, login rate limit), OIDC, or
proxy (trusted proxy IPs required). There are three roles (viewer, operator,
admin). Actaeon will not start on a network address with no login. Session
requests get a CSRF origin check. The `/mcp` token is scoped to `/mcp` only, and
the ticket-reply token (`tickets.token_env`) to `POST /api/tickets/reply` only.

**T4b. An analyst sees data they should not (insider, HR, executive sources).**
Connectors can be limited to groups, roles or users. Others' hunts cannot call them, and hunts
that read them are hidden from people outside the list (hunts, leads, reports, exports, memory,
assistant conversations, outputs). Roles can come from identity-provider groups.
*Residual:* scheduled work reads every connector; analyst notes are not restricted; the source's own
permissions remain the real boundary.

**T5. Cross-site scripting through data shown in the UI.**
The UI only ever sets text, never HTML (a test enforces this), and the CSP
allows scripts from the server only, with no inline script. CSV exports guard
against spreadsheet formulas, and report code fences are neutralised.

**T6. Server-side request forgery through advisory import.**
http(s) only, every redirect hop checked, and private and reserved addresses
refused by default, with a 15 MB cap.
*Residual:* DNS rebinding between check and connect.

**T7. Personal data sent to cloud model providers.**
Masking of emails, IPs, labelled usernames, custom terms and patterns, per
hunt, restored only locally.
*Residual:* pattern-based; unlabelled names and hosts can leak.

**T8. Secrets in config or logs.**
Secrets come only from `.env` or environment variables, and plain-text secrets
in connector config are rejected at startup. Audit arguments are redacted, as
are diffs in the settings preview. A secret scan runs in CI.

**T9. Runaway cost or load on sources.**
Limits on steps, runtime, tokens per hunt (`hunt.max_tokens`), time per query
(`hunt.max_query_sec`) and result size, per-connector pacing, a size cap on
every query, and a mandatory time range when a tool takes one. The search-index
bridge refuses leading wildcards on time-series indices, in query strings and in
raw query clauses.

**T10. Tampering with the audit log.**
SQLite triggers refuse updates and deletes, and every row is hash-chained to the
one before; `actaeon audit verify` finds changed or removed rows.
*Residual:* someone with file access can rewrite the whole chain or cut rows off
the end. Keep the `head` hash, or ship the audit log elsewhere, if you need
stronger guarantees.

## Out of scope

- A compromised host running Actaeon.
- Malicious MCP servers that the admin chose to install and run (stdio servers
  run with Actaeon's user rights). Review a server before adding it.
- Response actions: Actaeon does not contain, isolate or remediate.
