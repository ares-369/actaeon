# Actaeon as an MCP server

Other agents, assistants or tools can use Actaeon through MCP.

## stdio

```json
{"command": "actaeon", "args": ["mcp"], "env": {"ACTAEON_HOME": "/path/to/actaeon-home"}}
```

The client starts Actaeon. Hunts run inside that process, so a hunt stops if the
client closes it.

## HTTP

`POST /mcp` on the running web server takes JSON-RPC messages and returns JSON.
It sits behind the normal login. For clients that can't log in, set a bearer
token that works on `/mcp` only:

```yaml
mcp:
  token_env: ACTAEON_MCP_TOKEN   # the value goes in .env
  token_role: operator           # viewer | operator | admin
```

The token does not open the rest of the API.

## Tools

| Tool | Role | What it does |
|---|---|---|
| `list_hunts`, `get_hunt`, `hunt_report` | viewer | read hunts, verdicts, evidence and reports |
| `lookup_intel`, `list_advisories`, `list_saved_hunts`, `list_starters`, `coverage` | viewer | read intel, the library and coverage |
| `decode_command` | viewer | decode an obfuscated command line (runs nothing) |
| `start_hunt`, `stop_hunt` | operator | start a hunt (returns an id at once) or stop one |
| `run_replay`, `run_sweep` | operator | replay a saved hunt, or sweep intel, without a model |
| `add_intel` | operator, and `mcp.allow_intel_writes: true` | add indicators or extract them from text |

`mcp.expose` limits which tools are offered. Hunts started over MCP use the same
read-only connectors, validator and limits as any other hunt. Their origin is
recorded as `mcp`.

Results that include data from your sources (`get_hunt` with
`include_results`, `hunt_report`) keep the untrusted-data markers. A client
should treat that content as data, not instructions.
