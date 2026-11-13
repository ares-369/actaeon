# Deploying

## Docker (simplest)

On any Linux VM with Docker:

```bash
git clone <this repo> actaeon && cd actaeon
docker compose up -d                       # builds the image and starts it
docker compose exec actaeon actaeon models test
```

Then open http://127.0.0.1:8601. On first start, `./actaeon-data/` is created
with `config.yaml` and `.env`. Edit them there and run `docker compose restart`.

The container:
- runs as a non-root user (uid 10001) with a read-only root filesystem, no Linux
  capabilities and `no-new-privileges`;
- keeps everything (config, `.env`, databases, audit log, Excel outputs) in the
  `/data` volume;
- publishes the port on the host's loopback only. For remote use, put a reverse
  proxy with a login in front (`auth.mode: proxy` or `oidc`), or set `auth.mode` to
  `local` or `oidc` and publish the port deliberately;
- has a health check (`/healthz`).

Secrets: put them in `actaeon-data/.env`, or inject them as environment variables
from your secret manager (Key Vault, Secret Manager and so on). Actaeon reads only
environment variables and `.env`.

Build with only the extras you need: `docker build --build-arg EXTRAS="gemini,excel" -t actaeon .`

## Network: what Actaeon needs to reach

| Direction | To | Why |
|---|---|---|
| out 443 | your model provider (or AI gateway) | model calls |
| out 443 | each HTTP connector's MCP server, or the sources the bridges talk to | searches and lookups |
| out 443 | intel feeds and web sources you list | intel pulls |
| out 587/465 | your mail relay | email output (if used) |
| in 8601 | from the reverse proxy only | the UI, API and `/mcp` |

Deny everything else. Stdio connectors run inside the container, so their
targets count as Actaeon's outbound traffic.

## Separate workers (queue mode)

By default the web server runs hunts on its own threads. For heavier use, let it only
record jobs and run them in worker processes:

```yaml
jobs:
  mode: queue
  stale_after_sec: 600     # a running job with no heartbeat for this long is marked interrupted
```

```bash
actaeon serve                                  # UI and API; queues jobs
actaeon worker --concurrency 3                 # run as many workers as you like
actaeon worker --concurrency 1 --scheduler     # one of them (or the server) runs the schedules
```

- A worker runs each job as the person who started it (their role, groups and data-source access).
- Stop and pause in the UI reach the worker through the database.
- On SIGTERM a worker takes no new jobs and finishes the ones it has.
- Only one process schedules at a time: the first to hold `<data>/scheduler.lock`.
- All processes must use the same data folder on the same machine (SQLite). Several machines need
  a shared database, which is planned (PostgreSQL), not built.

With compose, uncomment the `worker` service in `docker-compose.yml`.

## Without Docker

```bash
python -m venv /opt/actaeon/venv && /opt/actaeon/venv/bin/pip install '.[all]'
ACTAEON_HOME=/var/lib/actaeon /opt/actaeon/venv/bin/actaeon init
ACTAEON_HOME=/var/lib/actaeon /opt/actaeon/venv/bin/actaeon serve
```

Run it as a service user under your init system, and keep `/var/lib/actaeon/.env`
readable only by that user.
