# Response actions

The AI proposes; a person approves. Nothing changes in your environment because a model said so.

## Tiers

| Tier | What | How |
|---|---|---|
| 0 | Observe | The verdict and the case page |
| 1 | Notify | [Outputs](outputs.md): email, webhook, ticket |
| 2 | Contain (reversible) | Actions in `soc.response.actions`, proposed on true positives, run only after approval |
| 3 | Destructive | Never. Deleting, wiping, purging, dropping, formatting, uninstalling, shutting down or rebooting is refused in config and at call time |

## Modes

```yaml
soc:
  response:
    enabled: false     # default: actions are recommendations; approving one records it with the exact call to run by hand
    dry_run: true      # with enabled: true, approving records what would be sent, without sending it
    two_person: false  # true: two different people must approve
```

Only `enabled: true` with `dry_run: false` sends anything. `actaeon doctor` warns when actions are
live.

## Defining actions

```yaml
connectors:
  - name: endpoint-mcp
    roles: [endpoint, response]          # the response role is required to run actions
    transport: http
    url: https://edr-mcp.example.internal/mcp
    auth: {type: bearer, token_env: EDR_MCP_TOKEN}

soc:
  response:
    enabled: true
    dry_run: true
    actions:
      - name: isolate_host
        description: Cut the host off the network (reversible)
        connector: endpoint-mcp
        tool: isolate_host
        entity: host                          # the target must be a host entity of the case
        arguments: {hostname: "{target}"}      # {target} and {case_id} are filled in
        undo: {tool: release_host, arguments: {hostname: "{target}"}, kind: reversible}
      - name: disable_user
        connector: identity-mcp
        tool: disable_account
        entity: user
        arguments: {user: "{target}"}
        undo: {tool: enable_account, arguments: {user: "{target}"}, kind: compensating}   # sessions already ended stay ended
```

## What is enforced

- The investigation never sees response tools: response and ticketing roles are not offered to
  the model, and the read-only policy blocks response-like tool names on every other path.
- A proposal must name a configured action, a target that is an entity of the case of the right
  kind, and come with a `true_positive` verdict.
- Targets with shell or quoting characters are refused.
- Running an action (`ConnectorHub.call_action`) needs a named approver, a connector with the
  `response` role, a tool not on its deny list and not destructive. It is not retried, so a state
  change cannot run twice by accident.
- With `two_person`, the same person cannot approve twice.
- Every attempt, allowed or blocked, goes to the hash-chained audit log with the approvers' names.
- Approvals are not offered over MCP: another agent cannot approve its own request.
- Undo calls the action's `undo` tool (also audited). `undo.kind` says what it is worth:
  `reversible` puts things back as they were (release a host); `compensating` is a follow-up that does
  not restore everything (re-enabling an account does not bring back the sessions it ended). The case
  shows which before anyone approves.
- An approval is bound to what was reviewed: the stored call (never edited after it is proposed) and
  the case as it was then. When new alerts join the case or it is investigated again, a pending proposal
  goes stale and must be proposed again.

Analysts can also propose an action themselves from the case page; it still needs approval.

## The demo

`actaeon demo` includes a pretend response connector (`actaeon bridge demo-response`) that only
changes a dictionary in memory, with live mode on, so the whole flow can be tried safely.
