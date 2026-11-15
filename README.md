# Actaeon

[![CI](https://github.com/ares-369/actaeon/actions/workflows/ci.yml/badge.svg)](https://github.com/ares-369/actaeon/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.10–3.12](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](pyproject.toml)
[![PyPI](https://img.shields.io/pypi/v/actaeon.svg)](https://pypi.org/project/actaeon/)
[![Release](https://img.shields.io/github/v/release/ares-369/actaeon?include_prereleases&sort=semver)](https://github.com/ares-369/actaeon/releases)

**An open-source AI threat hunter.** You give it a hypothesis ("an Office app started encoded
PowerShell this week"). Actaeon plans the hunt, queries your own data sources, follows pivots, and
writes a verdict that cites its evidence and maps to MITRE ATT&CK. When it cannot be sure, it hands
the hunt to a person instead of guessing.

It does not replace your SIEM or EDR. It works on top of them, reading what they already collect.

- **Read-only by default.** It searches and reads. Response actions (isolate, quarantine, delete,
  disable, ...) are always blocked; the only writes are ones an admin explicitly allows, such as
  opening a case.
- **Works with what you already run.** Every data source is reached through the Model Context
  Protocol (MCP), so it is not tied to any product. It ships with bridges for search-index APIs,
  read-only SQL databases, STIX/TAXII 2.1 servers and REST/OpenAPI services, and works with any
  other MCP server.
- **Your choice of model.** A cloud model or one on your own hardware; each role (planner, analyst,
  reporter) can use a different one.
- **Fully open source.** Apache-2.0. Every feature is in this repository. There is no paid
  edition, no licence key and no telemetry.

> **Beta, solo-maintained.** It has been tested in one home lab and on public and synthetic
> benchmarks, but not yet in production. It runs on one machine with SQLite by default, with
> PostgreSQL and separate worker processes as options. Treat verdicts as leads to verify, expect
> rough edges, and please [open an issue](https://github.com/ares-369/actaeon/issues) when something
> is wrong. Read [known limitations](docs/known-limitations.md) before relying on it.

![actaeon demo: scripted offline run against synthetic data](docs/demo.gif)

*The offline demo: synthetic data and a scripted run, no model. It shows the workflow, not detection
quality. Rebuild it with `scripts/make_demo_gif.py`.*

![A finished hunt: verdict, findings with the evidence they cite, ATT&CK techniques](docs/screenshots/hunt.png)

| Investigation graph | Entities across hunts |
|---|---|
| ![Investigation graph](docs/screenshots/graph.png) | ![Entities](docs/screenshots/entities.png) |
| **Leads** | **ATT&CK coverage** |
| ![Leads](docs/screenshots/leads.png) | ![Coverage](docs/screenshots/coverage.png) |

## Try it in a minute

```bash
pipx install actaeon                          # or: pip install actaeon
actaeon demo --offline --run                  # synthetic data, scripted run (no AI, no keys)
ACTAEON_HOME=~/.actaeon-demo actaeon serve    # open http://127.0.0.1:8611
```

From a checkout instead:

```bash
git clone https://github.com/ares-369/actaeon.git && cd actaeon
python -m venv .venv && . .venv/bin/activate && pip install -e .
actaeon demo --offline --run                  # synthetic data, scripted run (no AI, no keys)
ACTAEON_HOME=~/.actaeon-demo actaeon serve    # open http://127.0.0.1:8611
```

Or with Docker, no Python needed (nothing is kept when it stops):

```bash
git clone https://github.com/ares-369/actaeon.git && cd actaeon
docker compose --profile demo up demo         # open http://127.0.0.1:8611
```

The demo has a planted attack and a harmless look-alike, and all of its data is labelled SAMPLE.
See [docs/demo.md](docs/demo.md).

Screenshots are from this demo; `scripts/make_screenshots.py` rebuilds them.

## How a hunt works

1. **Plan.** The planner model turns the hypothesis into steps, and asks for data by *role*
   (log search, endpoint, identity, email, asset, network, cloud, intel). It never asks for a product.
2. **Query.** The analyst model calls connector tools. Before each call a validator requires a time
   range (when the tool takes one), caps result sizes, checks field names where the source lists them, and
   refuses write and code patterns. Calls are paced and time-limited.
3. **Pivot.** The model follows what it finds to the same host, user or destination, in other
   sources and in intel. When a threat rests on thin evidence, it is asked to corroborate it first.
4. **Verdict.** The outcome is one of `threat`, `no_results`, `telemetry_found_benign`, `logs_missing`
   or `inconclusive`. Claims that do not cite a successful result are dropped, and claims whose
   values do not appear in the cited evidence lower the confidence. Missing data is reported as
   missing, never as clean.
5. **Second look.** A threat verdict gets a separate pass that tries to prove it wrong; if that pass
   cannot confirm it, the confidence is capped and the hunt goes to a person.
6. **Hand-off.** When it cannot answer, a "needs analyst" lead opens. The lead says what was
   searched, what was missing and what to check next.

```mermaid
flowchart TD
    H["Hypothesis<br/>(analyst, hunt pack, advisory, autopilot)"] --> P["Planner model<br/>asks for data by role"]
    P --> A["Analyst model<br/>chooses the next tool call"]
    A --> V["Query validator<br/>time range, result caps, field names, no writes"]
    V --> G["Connector policy<br/>read-only tools, per-person access, pacing, time limit"]
    G --> C["MCP connectors and bridges<br/>your SIEM, EDR, identity, intel, ..."]
    C --> W["Untrusted-data wrapper<br/>random markers, prompt-injection scan"]
    W --> A
    G -. every call .-> L[("Hash-chained audit log")]
    A --> X["Verdict checks<br/>cited evidence, values present, missing data = missing"]
    X --> S["Second look on threats"]
    S --> O["Verdict, lead or hand-off,<br/>Sigma draft, outputs"]
```

## What is included

| Area | What you get |
|---|---|
| Hunting | Hypothesis hunts, saved hunts with scheduled replays, advisory-driven hunts, threat-actor and campaign hunts, an intel sweep over the indicator ledger |
| Entities across hunts | Every host, user, IP, domain and hash that findings relied on, with its history; entities that keep turning up in unresolved hunts are flagged as recurring ([entities](docs/entities.md)) |
| Inventory drift | What is new on each host since the last snapshot (listening ports, accounts, services, processes), with no model; new items open a lead ([drift](docs/drift.md)) |
| Hunt library | 65 ATT&CK-mapped hypotheses as one YAML file per hunt, a validator, and your own private packs alongside ([hunt packs](docs/hunt-packs.md)) |
| Sources | Any MCP server, plus built-in bridges for search indices, read-only SQL, STIX/TAXII 2.1 and REST/OpenAPI services. Each connector can carry query notes and examples in its own query language. `actaeon connectors check` tests a connector, and a one-file template helps you write your own |
| Intel | A local indicator and advisory store with first/last-seen tracking. Paste IOCs, import files, PDFs or URLs, or pull feeds. Export as STIX 2.1, or push a hunt's indicators to a TAXII 2.1 collection |
| Analyst work | Leads with assignment, status, resolution and history; chat on a finished hunt; feedback on findings; a timeline and an investigation graph (user, host, process, destination, intel match, each link tied to its evidence); an offline decoder for obfuscated command lines (base64, `-EncodedCommand`, gzip, hex, char codes, concatenation) that never runs them (`actaeon decode`, also a tool hunts can use) |
| Detection | Draft rules from a hunt (Sigma, plus the native queries that found data), optionally converted to each connector's query language with pySigma, and a backtest of how often they would have fired |
| Outputs | Email, webhook, or a write tool you explicitly allow (such as opening a case). A reply in the ticket can continue the hunt |
| Reports | Markdown, CSV and JSON; PDF and Word with the `reports` extra; an ATT&CK coverage view |
| Access | `basic`, `local`, OIDC single sign-on or a trusted proxy; viewer, operator and admin roles, mapped from your identity provider's groups; per-source limits so only some people can query (and see hunts over) sensitive sources ([access](docs/access.md)). All of it is free |
| Interfaces | Web UI, CLI, REST API, and Actaeon itself as an MCP server |
| Hunting depth and upkeep | Quick / standard / deep profiles (calls, token cap, second look), hunts that resume after a restart, and retention of old hunts |
| Running it | pip, Docker / compose (non-root, read-only filesystem) or systemd. Runs with no internet access, with local models ([air-gapped](docs/air-gapped.md)) |

## Safety model

Actaeon reads attacker-controlled text (command lines, user agents, emails), so the controls are
in code, not only in prompts:

- **Read-only by default.** Write-like tools are blocked. Response and destructive actions are
  always blocked, whatever the configuration says.
- **Query guard.** Queries need a time window when the tool takes one. Result sizes, time per query,
  tool calls and runtime per hunt are capped, and tokens per hunt can be. Each connector is
  rate-limited. Leading wildcards, which force the index to scan every value, are refused on log indices.
- **Untrusted data.** Every tool result is wrapped in random markers and treated as data. Text in
  the logs that matches known prompt-injection patterns becomes a high-severity lead of its own.
- **Evidence checks.** A claim that cites nothing real is dropped, and the verdict is downgraded.
- **Memory only from people.** Models and data sources cannot write memory. "Benign" notes expire
  (90 days by default), so one wrong call cannot hide activity for good.
- **Audit.** Every tool call, including blocked ones, goes to an append-only, hash-chained log.
  `actaeon audit verify` checks it.
- **Privacy.** Personal data can be masked before a prompt reaches a cloud model.

Details: [docs/threat-model.md](docs/threat-model.md), [docs/connectors.md](docs/connectors.md),
[docs/privacy.md](docs/privacy.md).

## Results so far

| Test | Result |
|---|---|
| Lab benchmark on a frozen week of real SIEM data (11 labelled cases) | gemini-3.8-flash: 10 to 11 / 11 over four runs, all 5 threats found, no false positives |
| Same lab cases, other models | gemini-3.1-pro-preview 9 / 11 (3 of 5 threats; its second look talked it out of 2, which went to an analyst), gemini-3.1-flash-lite 8 / 11 (2 of 5 threats); no false positives |
| ExCyTIn-Bench sample (80 public investigation questions) | mean reward 0.512, 40 / 80 fully correct |
| Field test: implant planted where no detection rule covered it | found from host inventory with no alert behind it |
| Tokens per hunt on the lab data (gemini-3.8-flash) | about 210k to 250k input, more than half served from the provider's cache; about 4k output; about 20 model calls |

The samples are small, the lab cases were written by someone who knew the answers, and only Gemini models
have been measured. Read them as "it checks and clears correctly", not as proof that it finds every attacker.
`actaeon bench --model <provider/model>` runs the built-in demo cases (or your own) with any model,
and `benchmarks/` has the runners for the lab and ExCyTIn tests. Results from other models are
welcome. Details, failures included, are in
[docs/benchmarks.md](docs/benchmarks.md) and [docs/field-test-2026-11.md](docs/field-test-2026-11.md).

## Install

**From PyPI (3.10+)**

```bash
pipx install actaeon         # or: pip install actaeon ; add extras with 'actaeon[all]'
actaeon init                 # config.yaml, .env and data/ in ~/.actaeon (ACTAEON_HOME to change)
actaeon serve                # http://127.0.0.1:8601
```

**From a checkout**

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[all]'      # or just -e . ; extras add cloud SDKs, PDF/Word reports, Sigma
actaeon init                 # writes config.yaml and .env (SQLite; add --database postgres to choose PostgreSQL)
actaeon serve                # http://127.0.0.1:8601
```

**PostgreSQL and separate workers (optional)**

```bash
pip install -e '.[postgres]'
actaeon init --database postgres --db-url 'postgresql://actaeon:PASSWORD@db-host:5432/actaeon'
actaeon serve                # with jobs.mode: queue in config.yaml, the server only records jobs
actaeon worker               # run one or more of these, on this or other machines
```

**Docker**

```bash
docker compose up -d         # http://127.0.0.1:8601, data in ./actaeon-data
```

**Linux service (systemd)**

```bash
sudo bash scripts/install.sh all
```

Actaeon refuses to start on a network address without a login. See [docs/deploy.md](docs/deploy.md).

## Set it up for your environment

1. **Models.** Pick a provider for each role (`planner`, `analyst`, `reporter`): Ollama,
   Anthropic, Gemini, OpenAI, Azure OpenAI or any OpenAI-compatible server. Run
   `actaeon models test` to check them. See [docs/models.md](docs/models.md).
2. **Connectors.** Add your sources as MCP connectors with roles. Use read-only service accounts.
   Run `actaeon connectors test` to check them. See [docs/connectors.md](docs/connectors.md) and
   [docs/bridges.md](docs/bridges.md).
3. **Environment profile.** Describe what runs here, what matters most and what is normal, so hunts
   fit your estate. See [docs/company-setup.md](docs/company-setup.md).
4. **Check.** `actaeon doctor`.

Keep your organisation's setup in a private configuration folder (`actaeon init --company DIR`),
not in this repository.

## Documentation

| Topic | Doc |
|---|---|
| Hunting, limits, verdicts, chat | [docs/hunting.md](docs/hunting.md) |
| Saved hunts, schedules, sweeps, memory | [docs/library.md](docs/library.md) |
| Inventory drift | [docs/drift.md](docs/drift.md) |
| Entities across hunts | [docs/entities.md](docs/entities.md) |
| Hunt packs (writing and sharing hypotheses) | [docs/hunt-packs.md](docs/hunt-packs.md) |
| Connectors and bridges | [docs/connectors.md](docs/connectors.md), [docs/bridges.md](docs/bridges.md) |
| Intel store and feeds | [docs/intel.md](docs/intel.md) |
| Autonomy: web intel and autopilot | [docs/autonomy.md](docs/autonomy.md) |
| Outputs and ticket replies | [docs/outputs.md](docs/outputs.md) |
| Models and providers | [docs/models.md](docs/models.md) |
| Running with a local model (set-up and measured results) | [docs/local-models.md](docs/local-models.md) |
| Privacy masking | [docs/privacy.md](docs/privacy.md) |
| Organisation setup, roles and access | [docs/company-setup.md](docs/company-setup.md), [docs/access.md](docs/access.md) |
| Deployment, air-gapped networks | [docs/deploy.md](docs/deploy.md), [docs/air-gapped.md](docs/air-gapped.md) |
| Actaeon as an MCP server | [docs/mcp-server.md](docs/mcp-server.md) |
| Benchmarks | [docs/benchmarks.md](docs/benchmarks.md) |
| Threat model, limitations | [docs/threat-model.md](docs/threat-model.md), [docs/known-limitations.md](docs/known-limitations.md) |

## What it is not (yet)

- **Not a SIEM or SOAR.** It sits beside them as a read-only investigator, and takes no response
  actions.
- **Not clustered by default.** It uses SQLite on one machine, with nothing else to install.
  PostgreSQL is an install-time option for several machines; it is new and has not run in
  production yet.
- **Measured with a few models only.** Three Gemini models and two small local models were scored; other providers have no measured
  results yet. Small local models were not good enough to hunt in testing (on a 4 GB GPU a 7B model found 0 and
  a 4B reasoning model 1 of the 4 planted threats in the demo cases; [docs/local-models.md](docs/local-models.md)).
- **Not proven in production yet.**

## Contributing

Bug reports, hunt hypotheses ([hunt packs](docs/hunt-packs.md)), connectors and benchmark runs
with other models are all welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) for how to report
a vulnerability.

```bash
pip install -e '.[dev]'
ruff check actaeon tests benchmarks scripts && node --check actaeon/static/app.js && pytest -q
```

## License

Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE), [DISCLAIMER.md](DISCLAIMER.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). All features are in this repository, under this licence.
