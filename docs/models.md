# Connecting a model

Each step of a hunt uses a role: `planner`, `analyst` and `reporter`. Each role
gets a provider and a model, plus optional fallbacks. After any change, run:

```bash
actaeon models test      # or Settings > Models > Test models in the UI
```

It sends one tiny prompt to every role and prints `OK`, the time taken, or the
exact error.

Install the extra for a cloud provider once: `pip install 'actaeon[all]'`
(or `[anthropic]`, `[gemini]`, `[openai]`).

## Supported providers

| Provider | Config (`llm.providers.<name>`) | Secret in `.env` |
|---|---|---|
| `ollama` | `base_url` (default `http://localhost:11434`), `default_model` | none |
| `anthropic` | `default_model` | `ANTHROPIC_API_KEY` |
| `openai` | `default_model` | `OPENAI_API_KEY` |
| `azure_openai` | `base_url` (your resource), `api_version`, deployment as model | `AZURE_OPENAI_API_KEY` |
| `gemini` | `auth` (`auto`, `api_key`, `vertex`, `vertex_api_key`), `default_model` | `GEMINI_API_KEY` (or Vertex ADC) |
| `openai_compatible` | `base_url` (vLLM, LM Studio, a gateway, ...), `default_model` | `OPENAI_COMPAT_API_KEY` |
| `cli` | `command` with `{model}` and `{prompt}` (a signed-in model CLI) | none |

### Provider notes

- **Local models (`ollama` / `openai_compatible`)**: no data leaves your network.
  Small 7B models plan and query poorly; use a larger model for `analyst` if
  running locally. Set-up, the `num_ctx` setting and measured results:
  [local-models.md](local-models.md).
- **Vertex AI (`gemini` with `auth: vertex`)**: set `project` and `location`
  (default `global`), and either `credentials_file`, workload identity, or
  `gcloud auth application-default login`. Add `base_url` and `headers` if
  routing through an AI gateway.

## Roles and fallbacks

```yaml
llm:
  roles:
    planner:  { provider: openai, model: "<fast model>" }
    analyst:  { provider: anthropic, model: "<strong model>",
                fallback: [{ provider: ollama, model: "<local model>" }] }
    reporter: { provider: openai, model: "<fast model>" }
```

The `analyst` role does most of the work; give it the strongest model you have.
When a model hits a quota or rate-limit error, Actaeon tries the next fallback
and skips the failing model for an hour.

Prompts to cloud providers are masked by default. See [privacy.md](privacy.md).

## Native tool calling

Claude, Gemini and OpenAI-compatible providers offer the hunt actions as native tools. If the model or gateway rejects tools, Actaeon retries the same request without them and uses the JSON action protocol. Set `native_tools: false` on a provider to always use the JSON protocol.

## Token usage

Every hunt records, per model, the model calls and the tokens: input, the part of the input the
provider served from its prompt cache (Gemini, Claude and OpenAI-compatible providers report it),
and output (with any thinking tokens). The hunt page, the reports and `actaeon bench` show them.
Gemini's thinking can be limited with `thinking_budget` or `thinking_level` on the provider.
