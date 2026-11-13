# Access: roles, groups and data sources

Everything here is part of the open-source code; there is no separate edition.

## Roles

| Role | Can |
|---|---|
| viewer | read hunts, leads, reports, intel and coverage |
| operator | everything a viewer can, plus start hunts, sweeps and replays, chat, work leads, add intel and notes |
| admin | everything, plus settings, connectors, models, users, audit log and backups |

## Roles from your identity provider's groups

```yaml
auth:
  mode: oidc                         # or proxy
  oidc:
    groups_claim: groups             # the ID-token / userinfo claim that lists the user's groups
  proxy_groups_header: X-Forwarded-Groups   # proxy mode: header with the groups, comma separated
  group_roles:
    soc-admins: admin
    soc-analysts: operator
    security-auditors: viewer
  default_role: viewer               # people in none of the groups above
  require_group_role: false          # true: refuse people in none of the groups above
```

The role comes from, in order: a named account's `role`, `auth.roles` (per user), the highest role
of the user's groups in `auth.group_roles`, then `auth.default_role`. With OIDC, the groups are read
at sign-in; sign out and in again after a change in the identity provider. In proxy mode they are
read on every request, so only let the proxy set that header. Named accounts (`basic` and `local`
login) can list `groups:` in `auth.users`.

Ask your identity provider to put the groups in the token. Some providers send group IDs rather
than names: use whatever value arrives as the key in `group_roles`. `GET /api/me` shows the role,
groups and data sources Actaeon sees for you.

## Who may use a data source

Give a connector an `access` list to limit who may use it:

```yaml
connectors:
  - name: mail
    roles: [email]
    access: [insider-threat, "role:admin", "user:jdoe"]
```

Entries are group names, `role:<role>` (that role or higher) or `user:<name>`. A connector with no
`access` is open to everyone, and admins may use every connector.

For people outside the list:

- Hunts they start never see the connector: its tools are not offered to the model, and a call to
  it is refused and written to the audit log.
- Any hunt that **read** the connector becomes *restricted*. Only people allowed to use every
  restricted connector the hunt read can list or open it, its lead, chat, reports, exports and
  detection drafts. It is left out of other people's hunt memory, and the hunt page shows which
  sources made it restricted.
- With any access limits in place, assistant conversations are visible only to the person who
  had them (admins see all).
- Outputs do not send restricted hunts unless the output has `include_restricted: true`.

Hunts started by a person run with that person's access, and so do the second-look check and chat
on them. Scheduled work (replays, sweeps, autopilot, web intel) has no person behind it
and uses every connector; what it finds in a restricted source is restricted like any other hunt.

The tokens for `/mcp` and `/api/tickets/reply` act with their own role (`mcp.token_role`; operator
for tickets) and the groups in `mcp.token_groups` / `tickets.token_groups`, not as the person who
wrote the ticket. Give the ticket token the groups of the team whose hunts it should reach.

## What this does not do

- It does not replace permissions on the source. Use a separate, read-only service account per
  connector, scoped on the source to what Actaeon should read.
- Analyst notes in memory are not restricted: people write them, so keep sensitive detail out of
  notes about restricted work.
- Counts in the coverage view include only hunts you can see; the audit log (admin only) shows
  every call.
