# Connecting a model

Each step of a hunt uses a role: `planner`, `analyst` and `reporter`. Each role
gets a provider and a model, plus optional fallbacks. After any change, run:

```bash
actaeon models test      # or Settings > Models > Test models in the UI
```

It sends one tiny prompt to every role and prints OK, the time taken, or the exact error.

Install the extra for a cloud provider once: `pip install 'actaeon[gemini]'`
(or `[anthropic]`, `[openai]`, `[all]`).

## Gemini

Pick the block that matches how you were given access.

**API key (AI Studio):**
```yaml
llm:
  providers:
    gemini: { auth: api_key, default_model: "<model>" }
```
`.env`: `GEMINI_API_KEY=...`

**Vertex AI with a service-account key file:**
```yaml
    gemini: { auth: vertex, project: "<gcp-project>", location: "global",
              credentials_file: "/etc/actaeon/sa.json", default_model: "<model>" }
```

**Vertex AI with workload identity federation** (no key file; for example, running on
another cloud): use the credential configuration file your cloud team generates as
`credentials_file`. It is the same setting.

**Vertex AI from a VM or container that already has a Google identity**, or after
`gcloud auth application-default login`:
```yaml
    gemini: { auth: vertex, project: "<gcp-project>", default_model: "<model>" }
```
No file or key is needed.

**Vertex AI express mode (API key):**
```yaml
    gemini: { auth: vertex_api_key, default_model: "<model>" }
```
`.env`: `GEMINI_API_KEY=...`

**Through an AI gateway or proxy:** add `base_url` and, if the gateway needs them,
`headers`:
```yaml
    gemini: { auth: vertex, project: "<p>", base_url: "https://ai-gateway.internal/",
              headers: { X-Gateway-Key: "${AI_GATEWAY_KEY}" } }
```

`auth: auto` (the default) uses Vertex AI when a project is set, and the API key otherwise.

## Other providers

| Provider | Config | Secret in `.env` |
|---|---|---|
| `anthropic` | `default_model` | `ANTHROPIC_API_KEY` |
| `openai` | `default_model` | `OPENAI_API_KEY` |
| `azure_openai` | `base_url` (your resource), `api_version`, deployment as model | `AZURE_OPENAI_API_KEY` |
| `openai_compatible` | `base_url` (vLLM, LM Studio, a gateway, ...), `default_model` | `OPENAI_COMPAT_API_KEY` |
| `ollama` | `base_url`, `default_model` | none |
| `cli` | `command` with `{model}` and `{prompt}` (a signed-in model CLI) | none |

## Roles and fallbacks

```yaml
llm:
  roles:
    planner:  { provider: gemini, model: "<fast model>" }
    analyst:  { provider: gemini, model: "<strong model>",
                fallback: [{ provider: gemini, model: "<fast model>" }, { provider: ollama, model: "" }] }
    reporter: { provider: gemini, model: "<fast model>" }
```

The analyst does most of the work; give it the strongest model you can. Small
local models (7B class) plan and query poorly. When a model fails with a quota or
rate-limit error, the next fallback is used, and the failing model is skipped for
an hour.

Prompts to cloud providers are masked by default. See [privacy.md](privacy.md).
