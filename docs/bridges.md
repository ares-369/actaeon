# Bridges

A bridge is a small MCP server, built into Actaeon, for a source that has no MCP
server of its own. A connector starts it with `command: actaeon` and
`args: [bridge, <kind>, ...]`. Credentials reach the bridge only through the
connector's `env:`:

| Variable | Use |
|---|---|
| `BRIDGE_TOKEN` | `Authorization: Bearer ...` |
| `BRIDGE_API_KEY` | API key, sent in `BRIDGE_API_KEY_HEADER` (default `Authorization`), with optional `BRIDGE_API_KEY_PREFIX` |
| `BRIDGE_USERNAME` / `BRIDGE_PASSWORD` | HTTP Basic |

Every bridge accepts `--insecure` (skip TLS checks, lab only) and `--ca-bundle`.

## search-index

For any index that speaks the common `_search` JSON API.

```yaml
- name: logs
  roles: [log_search]
  transport: stdio
  command: actaeon
  args: [bridge, search-index, --url, "${LOGS_URL}", --index, "events-*", --time-field, "@timestamp"]
  env: { BRIDGE_USERNAME: "${LOGS_USER}", BRIDGE_PASSWORD: "${LOGS_PASS}" }
  dialect: "query_string (Lucene)"
```

Tools: `list_indices`, `get_fields`, `search`, `count`, `top_values` (most common
or rarest values, for stacking).

Limits: only `_cat/indices`, `_mapping`, `_search` and `_count` are called;
indices must match an `--index` pattern; every query has a time range
(default the last 24 h, at most `--max-days`, default 30); hits are capped at
`--max-size` (default 500); scripts are refused.

## taxii

For a STIX/TAXII 2.1 API root.

```yaml
- name: intel
  roles: [intel]
  transport: stdio
  command: actaeon
  args: [bridge, taxii, --url, "${TAXII_ROOT}"]
  env: { BRIDGE_USERNAME: "${TAXII_USER}", BRIDGE_PASSWORD: "${TAXII_PASS}" }
```

Tools: `list_collections`, `get_objects`, `get_object`, `find_indicator`.
`find_indicator` pages through indicators (at most `--max-pages`) and matches
the value as a substring of the STIX pattern or name, so it can return near
matches and is slow on very large collections.

## openapi

Turns an OpenAPI 3 document into tools.

```yaml
- name: assets
  roles: [asset]
  transport: stdio
  command: actaeon
  args: [bridge, openapi, --spec, "${ASSET_API}/openapi.json", --include, "get*", --include, "list*"]
  env: { BRIDGE_TOKEN: "${ASSET_TOKEN}" }
```

- Every `GET` operation becomes a tool, filtered by `--include`/`--exclude`
  (globs on operationId or path).
- A `POST` operation is exposed only when named with `--allow-post <operationId>`.
  This is for APIs whose searches are POST requests. Name only operations that read.
- `PUT`, `PATCH` and `DELETE` are never exposed.
- Path values are URL-encoded, so a value cannot change the path.
- At most `--max-tools` (default 150) operations; narrow large specs with `--include`.

The connector's own read-only policy still applies on top of all of this.

## SQL (`actaeon bridge sql`)

Read-only queries over a SQLite file, MySQL/MariaDB or PostgreSQL.

```yaml
connectors:
  - name: case-db
    roles: [log_search]
    transport: stdio
    command: actaeon
    args: [bridge, sql, --url, "sqlite:///data/logs.db", --max-rows, "200"]
    # MySQL/PostgreSQL: --url mysql://reader@db.internal/logs ; password in env BRIDGE_PASSWORD
```

Tools: `list_tables`, `describe_table` (optional sample rows), `query` (one statement).

Guards: one statement only, it must start with SELECT, WITH, SHOW, DESCRIBE or EXPLAIN,
and write keywords are refused even inside a WITH. SQLite opens the file read-only with
an authorizer that denies anything but reads. MySQL and PostgreSQL sessions are set to
read-only transactions with a statement timeout. Rows are capped and long values cut.
`--table` (repeatable) limits which tables can be read. MySQL needs `pymysql` and
PostgreSQL `psycopg`; neither is installed by default. Use a read-only account anyway.

### Snapshot (inventory) mode

Add `--snapshot` to the search-index bridge for current-state indices that have no per-event
timestamp (host inventory: running processes, listening ports, local users, installed packages).
Searches are not time-bounded; `first_seen` is unavailable. Everything else (query, count,
top_values, get_fields, index allowlist, caps) works the same. Example (host inventory indices):

```yaml
  - name: inventory
    roles: [endpoint, asset, identity]
    transport: stdio
    command: actaeon
    args: [bridge, search-index, --snapshot, --url, "https://indexer:9200",
           --index, "inventory-processes-*", --index, "inventory-ports-*"]
```

This gives a hunter visibility into where dropped implants, backdoor ports, persistence and
new accounts appear, even when no alert fired.
