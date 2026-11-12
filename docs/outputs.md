# Outputs

Outputs send a hunt's result somewhere when it finishes: model hunts, replays,
sweeps and autopilot hunts alike. Each output has a `when` list:

| when | fires for |
|---|---|
| `threat` | outcome threat |
| `needs_review` | anything flagged for review (replay matches, unknown triage states) |
| `benign` | telemetry found, explained and benign (for example, every IOC match blocked or passive) |
| `no_results`, `logs_missing`, `inconclusive` | those outcomes |
| `all` | every result (use this for an audit log) |

Optional `origins: ["sweep", "autopilot"]` limits an output to some kinds of hunt.

## Types

**email** (SMTP; works with a mail relay or a provider's SMTP service)
```yaml
- name: soc-mail
  type: email
  when: [threat]
  smtp_host: "mail.example.org"
  smtp_port: 587          # STARTTLS; use ssl: true and 465 for implicit TLS
  username_env: SMTP_USER
  password_env: SMTP_PASSWORD
  from: "actaeon@example.org"
  to: ["soc@example.org"]
  to_critical: ["soc-leads@example.org"]   # added for threats with confidence >= critical_confidence (80)
  subject: "{title}"                        # optional template
```
The body has the outcome, the summary, findings with their evidence ids,
indicators, ATT&CK, the queries that ran and a link (set `actaeon.external_url`).

**excel** (an `.xlsx` workbook; needs the `excel` extra)
```yaml
- name: audit-sheet
  type: excel
  when: [all]
  path: "/var/lib/actaeon/hunt-audit.xlsx"
  sheet: "Hunts"
```
One row per result: time, hunt id, origin, hypothesis, outcome, confidence,
needs review, summary, findings, indicators, queries executed, result per query,
ATT&CK and link. Cells that start with `=`, `+`, `-` or `@` are written as text.

**webhook**: POST JSON (the same facts, or your own `body` template) to a URL,
with optional `headers` (`${VAR}` for secrets).

**mcp_tool**: call a tool on a connector, for example to open a case:
```yaml
- name: open-case
  type: mcp_tool
  when: [threat]
  connector: cases
  tool: create_case
  arguments: {title: "{title}", description: "{summary}", severity: "{severity}"}
```
This is the one place Actaeon writes to another system, and only when you allow
it. The connector must have `allow_write: true` and list `create_case` exactly in
`tools.allow`. Everything else stays read-only.

Template fields: `{title} {summary} {hypothesis} {outcome} {confidence} {severity}
{findings} {indicators} {queries} {attack} {link} {hunt_id} {origin} {time}`.

## Checking

`actaeon outputs` lists them. `actaeon outputs test <name>` sends a clearly
labelled sample. Each output that runs is recorded on the hunt as an `output`
step, with OK or the error. A failing output never stops a hunt.
