# Running without internet access

Actaeon can run on a network with no route to the internet. Nothing in it reports usage or
checks for updates, the UI loads no external files (icons and fonts are bundled), and the ATT&CK
data ships with the package. Tests check this: `tests/test_airgap.py` runs the offline demo and
the UI with every outbound connection refused and fails if anything tries one.

## What to bring in

On a machine with internet access:

```bash
git clone <this repository> actaeon
pip wheel -w wheels './actaeon[all]'             # Actaeon and every dependency as wheels
docker build -t actaeon:local actaeon && docker save actaeon:local -o actaeon.tar   # if you use the container
```

On the isolated host:

```bash
pip install --no-index --find-links wheels 'actaeon[all]'
# or
docker load -i actaeon.tar      # docker-compose.yml already uses image actaeon:local
```

## Models

Use a model server inside the network: the `ollama` provider, or `openai_compatible` pointing at
any OpenAI-compatible server (for example vLLM or llama.cpp). Small models hunt poorly (see
[known limitations](known-limitations.md)); give the `analyst` role the strongest model you can
run. Run `actaeon models test` to check each role.

## Features that reach outside, and are off by default

| Feature | Setting | Default |
|---|---|---|
| Web intel (news and advisory pages) | `intel.web.sources`, `intel.web.interval_minutes` | none, 0 |
| Web lookups during hunts | `intel.web.tools` | false |
| Feed pulls | `intel.feeds` | none |
| Advisory import from a URL | used only when you give a URL | - |
| Cloud model providers | `llm.roles` | local Ollama |
| Outputs (email, webhook, TAXII) | `outputs` | none |
| Single sign-on | `auth.mode: oidc` | off |

Everything else Actaeon reaches is what you configure: your connectors and your model server.

## Intel without internet

Import files you carry in (`actaeon intel import file.json --format stix`, csv, text), point a
`taxii` connector at an internal TAXII 2.1 server, or paste advisories in the UI. Export with
`actaeon intel export` to carry results out.
