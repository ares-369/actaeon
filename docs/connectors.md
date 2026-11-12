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

Secrets never go in `config.yaml`. Use `*_env` keys or `${VAR}` references to
values in `.env`; a plain-text secret is rejected at startup. Interactive OAuth
(authorization-code sign-in) is not supported yet.

## Read-only by default

For each tool, in order:

1. A match in `tools.deny` (glob) blocks it.
2. If `tools.allow` is set, anything not matching it is blocked.
3. A tool that looks like it changes state is blocked unless the connector has
   `allow_write: true` **and** the tool is named exactly in `tools.allow`.

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

## Commands

```bash
actaeon connectors             # list
actaeon connectors test        # connect and count allowed tools
actaeon connectors tools logs  # show every tool and whether it is allowed
```
