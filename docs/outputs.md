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

A record of every hunt stays in Actaeon; download any hunt as CSV or JSON from its page
(`/api/hunts/<id>/export.csv`, `.json`) or the PDF/Word report.

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

## Sharing indicators (TAXII 2.1)

```yaml
outputs:
  - name: share-intel
    type: taxii
    when: [threat]
    url: "https://tip.example.org/taxii2/api1/collections/<collection-id>/objects/"
    headers: {Authorization: "Bearer ${TIP_TOKEN}"}
    min_confidence: 70          # optional
```

Posts the hunt's STIX 2.1 bundle (indicators from the findings, ATT&CK techniques, a report) to
the collection's objects endpoint. Hunts with nothing to share are skipped. Any platform that
accepts TAXII 2.1 writes can receive it; check what your platform does with `indicator` objects
before turning this on, because it may start alerting on them.

## Replies from the ticket

A ticket opened by an output carries the hunt id (`{hunt_id}`). When the analyst
answers in the ticket, have the ticket system post the reply back:

```
POST /api/tickets/reply
Authorization: Bearer <token from tickets.token_env>
{"hunt_id": "...", "text": "...", "author": "jdoe"}      (or "lead_id": 12)
```

| Reply | What happens |
|---|---|
| `/resume` | resumes the hunt if it is paused |
| `/hunt <hypothesis>` | starts a follow-up hunt with the first hunt's record as context (origin `followup:<id>`); its result goes out like any hunt |
| anything else | a question about the hunt, answered in the background like **Ask Actaeon** (read-only tool calls, cited evidence) |

Every reply and every answer is a comment on the lead. An answer is also sent to
each output whose `when` lists `reply` (`all` does not include replies), with the
extra template fields `{reply} {reply_author} {answer}`:

```yaml
tickets:
  token_env: TICKET_REPLY_TOKEN     # in .env; valid on /api/tickets/reply only, acts as operator
outputs:
  - name: ticket-answer
    type: mcp_tool
    when: [reply]
    connector: cases
    tool: add_comment               # must be allowed like any write tool
    arguments: {case: "{hunt_id}", text: "{answer}"}
```

Without a token, logged-in operators can call the same endpoint.

## Checking

`actaeon outputs` lists them. `actaeon outputs test <name>` sends a clearly
labelled sample. Each output that runs is recorded on the hunt as an `output`
step, with OK or the error. A failing output never stops a hunt.

## Alert cases

The same outputs (email, webhook, `mcp_tool`) can send triaged alert cases. Use the case events in `when`:
`case_true_positive`, `case_false_positive`, `case_benign`, `case_needs_analyst`, `case_logs_missing`,
`case_action_proposed`, `case_all`. `min_severity` (0-100) skips lower cases. Template fields: `case_id, time,
title, verdict, confidence, severity, summary, alerts, findings, entities, attack, fix, actions, link`.
A hunt output keeps its hunt events; one output can list both kinds.
