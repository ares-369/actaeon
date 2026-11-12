# Actaeon

Actaeon is an open-source AI threat hunter that is in early development. You give it a
hypothesis and it plans a hunt, queries your data sources, follows pivots, and writes
a verdict that cites its evidence and maps to MITRE ATT&CK.

It talks to every data source through the Model Context Protocol (MCP). You add each source
as a connector and tag it with a role: log search, endpoint, identity, email, asset, network,
cloud or intel. You can also add intel yourself (paste IOCs or an advisory, import
files, pull feeds) into a built-in store that hunts read like any other intel source.
The hunt engine asks for a role, never a specific product. Tools are
read-only by default, and every tool call is written to an audit log.

> Status: pre-alpha. Built so far: foundation (config, model providers, auth, job engine,
> web server), the connector hub, generic bridges, a local intel store, the hunt engine, and the hunt library
> with replays, intel sweeps and memory, and a web UI with reports and a coverage view.
> See [docs/connectors.md](docs/connectors.md) and [docs/bridges.md](docs/bridges.md) and [docs/intel.md](docs/intel.md) and [docs/hunting.md](docs/hunting.md) and [docs/library.md](docs/library.md).

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
actaeon init          # writes config.yaml and .env
actaeon serve         # http://127.0.0.1:8601
```

## Models

Each step of a hunt uses a model role (`planner`, `analyst`, `reporter`). Each role can use
a different provider: local Ollama, Anthropic, Gemini, OpenAI, Azure OpenAI or any
OpenAI-compatible endpoint. Change them under **Models** in the UI or in `config.yaml`.
Keys go in `.env`. Cloud SDKs are optional extras (`pip install 'actaeon[all]'`).

## Authentication

`auth.mode` can be `none` (loopback only), `basic`, `local`, `oidc` or `proxy`, with
viewer, operator and admin roles. Actaeon will not start if it would listen on a
network address with no login.

## Roadmap

1. Foundation (done)
2. Connector hub (done): MCP over stdio and HTTP, role tags, allow/deny lists, audit log
3. Generic bridges (done) for sources without their own MCP server (search index, STIX/TAXII, REST/OpenAPI)
4. Hunt engine (done): hypothesis, plan, queries, pivots, a verdict with cited evidence, step limits)
5. Hunt library, scheduled replays, intel-driven hunts, memory (done)
6. UI, reports, coverage view (done)
7. Actaeon as an MCP server
8. Demo mode, known limitations, threat model

## Development

```bash
ruff check actaeon tests && pytest -q
```

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
