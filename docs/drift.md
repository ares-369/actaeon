# Inventory drift

Drift answers one question without a model: **what is new on each host since the last look?** A new
listening port, local account, running service or process that nobody expected is a classic sign of
persistence or access, and it is still visible in the host inventory when logs have been cleared.

## Setting it up

Point it at a current-state inventory source: a search-index bridge started with `--snapshot`, or any
connector that has `search` and `top_values` tools. For each kind of item, say which field names the
host and which fields together identify one item:

```yaml
drift:
  interval_minutes: 0          # > 0: run on a schedule (e.g. 360 for every six hours)
  escalate: false              # true: start a model hunt for the new items (needs a model)
  targets:
    - name: listening-ports
      label: listening ports
      connector: inventory
      index: "inventory-ports-*"
      host_field: host.name
      item_fields: [source.port, network.transport, process.name]
      query: "interface.state:listening"
    - name: local-users
      connector: inventory
      index: "inventory-users-*"
      host_field: host.name
      item_fields: [user.name, user.id]
    - name: running-services
      connector: inventory
      index: "inventory-services-*"
      host_field: host.name
      item_fields: [service.name]
      ignore: ["^Windows Update"]   # regexes on the item text; matches are never reported
```

Use the field names your inventory has (`actaeon connectors check` and the bridge's `get_fields` show
them).

## Running it

```bash
actaeon drift              # every target
actaeon drift run local-users
actaeon drift status       # hosts and items stored per target
```

Also `POST /api/drift/run {"name": "..."}`, `GET /api/drift`, and the **Inventory drift** section of the
Library page.

## What a run does

1. Lists the hosts (`top_values` on `host_field`, up to 200).
2. Reads each host's items (`search`, up to 500 per host, only the fields named above).
3. Compares them with what was stored last time.

- The **first run** records a baseline and reports nothing.
- After that, each item that was not there before on that host is a **finding**, citing the result it
  came from. A host seen for the first time is one finding, with its items as its baseline. Items that
  disappeared are counted in the summary.
- A run with findings is stored as a hunt (origin `drift:<name>`, outcome `inconclusive`) and handed to
  an analyst, so a lead opens. A run with nothing new ends as `no_results`.
- A host whose items were cut off (more than 500, or a very large result) is listed as **incomplete** and
  not compared, and a host that could not be read is listed too. Both lower the confidence and send the
  run to an analyst. Missing data is never reported as "nothing new".
- If the inventory cannot be read at all, the run ends as `logs_missing`.

Every call goes through the connector policy, the per-person access rules and the audit log, like a hunt.
With `drift.escalate: true` and a model configured, a run with findings also starts a model hunt that
gets the list of new items as context.

## Limits

- The inventory is only as fresh as its last scan; a host that is switched off keeps its old items.
- Drift sees what the inventory records. A process that starts and exits between two scans is not there.
- New is not the same as malicious: software updates and planned changes show up too. Use `ignore` for
  known churn, and record planned changes in `environment.notes`.
