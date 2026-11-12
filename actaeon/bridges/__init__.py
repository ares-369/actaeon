"""Generic bridges: MCP servers for sources that have no MCP server of their own.

Each bridge runs as a stdio MCP server started by a connector, for example::

    connectors:
      - name: logs
        roles: [log_search]
        transport: stdio
        command: actaeon
        args: [bridge, search-index, --url, "${LOGS_URL}", --index, "events-*"]
        env: {BRIDGE_USERNAME: "${LOGS_USER}", BRIDGE_PASSWORD: "${LOGS_PASS}"}

All bridges are read-only by construction: they only expose read operations.
"""

KINDS = ("search-index", "taxii", "openapi")
