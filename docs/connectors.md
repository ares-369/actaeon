# Connectors

Actaeon reaches every data source through an MCP server. A connector is one MCP
server plus a few settings in `config.yaml`.

## Roles

The hunt engine asks for a role, never a product:

| Role | Typical data |
|---|---|
| `log_search` | central log search, event search |
| `endpoint` | process, file and host telemetry |
| `identity` | sign-ins, directory, privileged access |
| `email` | message trace, attachments, URLs |
| `asset` | inventory, owners, criticality |
| `network` | flows, DNS, proxy, firewall |
| `cloud` | control-plane and audit logs |
| `intel` | indicators, reports, reputation |

| `alerts` | where alerts come from (polled by `soc.intake.sources`, also searched during investigations) |
| `ticketing` | case or ticket systems: written to only by outputs, never offered to a model |
| `response` | containment tools: run only as approved actions, never offered to a model |

A connector can carry more than one role.

## Transports and auth

- `stdio`: Actaeon starts the server as a child process. The child gets only
  `PATH`, `HOME`, `LANG` and `TMPDIR` from the parent, plus the `env:` you set.
- `http`: streamable HTTP (JSON or event-stream responses; the session header is kept).

`auth.type` for `http`:

| type | settings |
|---|---|
| `none` | |
| `bearer` | `token_env` |
| `api_key` | `api_key_env`, `header` (default `X-API-Key`), optional `prefix` |
| `oauth_client_credentials` | `token_url`, `client_id`, `client_secret_env`, optional `scope`, `audience` |
| `oauth` | interactive sign-in (authorization code + PKCE); optional `client_id`, `client_secret_env`, `scope`, `redirect_port`. See below |

Secrets never go in `config.yaml`. Use `*_env` keys or `${VAR}` references to
values in `.env`; a plain-text secret is rejected at startup.

## Query guides

Each connector can tell the analyst how to search it:

```yaml
- name: logs
  dialect: "the platform's query language"
  query_notes_file: "/etc/actaeon/notes/logs.md"   # or query_notes: "inline text"
  query_examples:
    - {goal: "process starts by parent", query: "..."}
```

Start from [templates/query-notes.md](templates/query-notes.md). Queries that
returned data in earlier hunts on the same connector are added automatically as
"queries that returned data here before", so every model learns what works on
your data. This is the biggest help for models writing a language they know
little about.

## Who may use a connector

`access: [group, "role:admin", "user:name"]` limits a connector to those people; hunts that read
it are then visible only to them. See [access.md](access.md).

## Read-only by default

For each tool, in order:

1. A match in `tools.deny` (glob) blocks it.
2. If `tools.allow` is set, anything not matching it is blocked.
3. A response or destructive action is always blocked. This covers names with
   words such as isolate, contain, quarantine, kill, terminate, delete, remove,
   purge, wipe, disable, revoke, ban, block, uninstall, shutdown, reboot, lock,
   reset or remediate, and any tool the server marks `destructiveHint`. No
   setting enables these for hunts or alert investigations, not even
   `allow_write`. They can only run as an approved response action
   ([response.md](response.md)).
4. A tool that looks like it changes state is blocked unless the connector has
   `allow_write: true` **and** the tool is named exactly in `tools.allow`. This
   is how an output can create a case or ticket.

"Looks like it changes state" means the server marks it `destructiveHint` or
`readOnlyHint: false`, or its name contains a word such as delete, update,
isolate, block, run or send. Server hints are not proof, so a write-like name
is blocked even if the server says the tool is read-only. Name matching can be
wrong in both directions; use `tools.deny` for anything you are unsure of.

Actaeon refuses server-to-client requests (sampling, elicitation, roots), so a
data source cannot ask the model or the user for anything.

## Tool output is data

Every result is wrapped in `UNTRUSTED-DATA` markers with a random nonce before it
reaches a model. Copies of the marker inside the data are altered so a source
cannot close the block early. The model is told to treat the block as evidence
only. This lowers prompt-injection risk; it does not remove it.

## Retries, pacing, audit

- Each call is paced to `rate_per_min` per connector.
- A failed call is retried twice (1 s, then 2 s backoff, with a fresh
  connection), then recorded as an error.
- Every call, including blocked ones, goes to an append-only audit log
  (`data/audit.sqlite`) with redacted arguments, outcome, attempts and timing.
  Admins can read it at `/api/audit`.
- Each audit row stores a SHA-256 of the previous row's hash plus its own content.
  `actaeon audit verify` (or `GET /api/audit/verify`, admin) walks the chain and
  names any row that was changed or removed. Rows written before this existed are
  counted but not checked. Cutting rows off the end does not break the chain:
  note the `head` hash somewhere else if that matters to you.

## Checking a connector

`actaeon connectors check [name]` tests whether a connector is fit for hunting, beyond "it
answers":

| Level | Examples |
|---|---|
| FAIL | cannot connect, no tools, every tool blocked by policy, input schemas that are not objects |
| WARN | allowed tools not marked `readOnlyHint`, a search tool with no time argument or result cap, missing descriptions, `allow_write` on, plain http to a remote host, TLS checks off, a very long timeout, no query notes |
| OK | everything else that was checked |

It exits 1 on any FAIL, so it can run in CI. It cannot prove the account on the source is
read-only: use a read-only account as well.

To write your own connector, start from
[templates/connector_template.py](templates/connector_template.py): one file, no dependencies,
a read-only search tool with a time range and a result cap, ready for `connectors check`.

## Commands

```bash
actaeon connectors             # list
actaeon connectors test        # connect and count allowed tools
actaeon connectors check logs  # contract check: read-only hints, time ranges, caps, TLS
actaeon connectors tools logs  # show every tool and whether it is allowed
```

## Sign in with OAuth (browser login)

For HTTP MCP servers that ask users to sign in:

```yaml
  - name: remote-logs
    roles: [log_search]
    transport: http
    url: https://mcp.example.internal/mcp
    auth: {type: oauth}          # optional: client_id, client_secret_env, scope, redirect_port
```

Then run `actaeon connectors login remote-logs`. Actaeon finds the authorization server from
the MCP server's metadata, registers itself if no `client_id` is set, and opens a one-time
listener on `127.0.0.1:8765` for the sign-in to return to (PKCE S256, state checked). On a
headless server add `--manual`: open the printed URL on any device, sign in, then paste the
address the browser ended on. Tokens are stored in `data/oauth/<name>.json` (mode 600) and
refreshed automatically; sign in again when the refresh token expires.

## Tested third-party servers

Checked on 2026-11-13 against the public MCP reference servers (`everything`, `filesystem`,
`memory`) over stdio, and `everything` over streamable HTTP: tools listed, read tools called,
results wrapped as untrusted data. Write and delete tools (`write_file`, `edit_file`,
`create_entities`, `delete_entities`, ...) were blocked by the policy; server-declared
destructive tools fell in the never-allowed class.
