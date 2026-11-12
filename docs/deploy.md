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

## Without Docker

```bash
python -m venv /opt/actaeon/venv && /opt/actaeon/venv/bin/pip install '.[all]'
ACTAEON_HOME=/var/lib/actaeon /opt/actaeon/venv/bin/actaeon init
ACTAEON_HOME=/var/lib/actaeon /opt/actaeon/venv/bin/actaeon serve
```

Run it as a service user under your init system, and keep `/var/lib/actaeon/.env`
readable only by that user.
