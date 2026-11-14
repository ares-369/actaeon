# Entities across hunts

Every finished hunt records the entities its findings relied on: hosts, users, processes, IP addresses,
domains, URLs, hashes and email addresses. The **Entities** page (also `GET /api/entities` and
`actaeon entities`) shows each one with the hunts it appeared in.

## What is recorded

Only what a conclusion leaned on: the host, user, process, source and destination fields of the results a
finding cites, plus indicators named in the finding text. Raw results are not indexed wholesale, so an IP
that merely appeared in a large search result is not here. Drift findings record their host.

Each record keeps the hunt, its outcome, whether it was handed to an analyst, and the evidence ids. A
record from a restricted hunt is shown only to people who may see that hunt (see [access.md](access.md)).

## Recurring entities

One hunt that ends "inconclusive" or "benign" is easy to set aside. The same host in three of them in two
weeks is worth a look. An entity is marked **recurring** when it appears in at least `recurring_hunts`
hunts in the last `window_days` days, and at least one of them is unresolved (inconclusive, or handed to an
analyst):

```yaml
entities:
  recurring_hunts: 3
  window_days: 14
```

`actaeon entities --recurring` lists them; the Entities page has a filter for them.

## In new hunts

When a new hypothesis names a known entity (for example a host name), the hunt is told that entity's
history: how many hunts relied on it and how they ended. It is context, not evidence: the hunt still has
to find its own.

```bash
actaeon entities                          # all, recurring first
actaeon entities --type host --recurring
actaeon entities WS07                     # one entity's history
```
