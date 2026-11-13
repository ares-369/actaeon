# Autonomy: web intel, autopilot and CLI models

Actaeon can run without anyone starting hunts:

```
web intel sources --> new advisories --> advisory hunts (auto_hunt)
intel store + coverage gaps + follow-ups + environment --> autopilot --> hypotheses --> hunts
```

Every autonomous hunt uses the same read-only connectors, validator, field
guard, limits and verdict checks as a hunt you start yourself. Its origin is
recorded (`advisory:<id>`, `autopilot:<source>`). Findings still need an analyst.

## Web intel

```yaml
intel:
  web:
    interval_minutes: 60          # pull on a schedule (0 = by hand)
    auto_hunt: true               # hunt each new advisory that is relevant here (see below)
    sources:
      - name: advisories
        url: "https://example.org/advisories.xml"   # RSS or Atom
        keywords: [ransomware, powershell]          # optional filter
        max_items: 10
      - name: research-page
        url: "https://example.org/research/"
        kind: page                                  # re-read when the page changes
```

### Only hunt what matters here (relevance)

A general security news feed is mostly about software you do not run. Before a new
advisory is hunted, Actaeon decides whether it is relevant to this environment:

1. **Terms.** The advisory must mention something you run: `environment.platforms`,
   `environment.products` and `intel.web.relevance.terms`, matched as whole words.
   No match means not relevant, and no model is asked.
2. **Model check.** For a match, the reporter model reads your environment profile and
   the advisory and answers whether the affected product, version or technique applies
   here, with a score, a one-line reason and a hunt hypothesis written for this
   environment. Scores under `min_score` count as not relevant.

```yaml
environment:
  platforms: [linux]
  products: ["<web server>", "<ssh server>", "<database>"]   # what you run, by name; the more complete, the better
intel:
  web:
    auto_hunt: true
    max_hunts_per_pull: 3                   # cost cap; the rest are recorded as relevant but not hunted
    relevance:
      model: true                           # false: the term match alone decides
      min_score: 50
      terms: []                             # extra words that make an item worth a look
```

Every decision is kept on the advisory (the intel ledger), relevant or not: the
score, the reason, the matched terms and the hunt it started. The Intel page shows
it next to each advisory. With no terms configured, the older rule applies: hunt
advisories that list indicators or techniques.

`actaeon intel web [--hunt]`, `POST /api/intel/web/pull`, or the UI. The article
behind each feed item is fetched and stored as an advisory: indicators,
techniques and CVEs are extracted and the source is tagged `web:<name>`. Items
are remembered by link, so each is added once. All fetches use the import
guard: http(s) only, no private addresses, redirects checked, size cap.

## Web lookups during a hunt

`intel.web.tools: true` adds a built-in `web` connector (role `intel`) with
`fetch_page` and, if `intel.web.search_url` is set, `search_web` (any search
service with a JSON API, such as a self-hosted metasearch). Queries and URLs are
refused if they contain an internal IP, an email address, or anything in
`privacy.terms` or `privacy.patterns`, because whatever goes to the web leaves
your network. Page content is untrusted data, like any tool output.

## Autopilot

```yaml
autopilot:
  interval_minutes: 720      # 0 = only by hand
  max_hunts_per_run: 3
  max_hunts_per_day: 12
  avoid_repeat_days: 7
```

`actaeon autopilot [--dry-run]`, `POST /api/autopilot {"dry_run": true}`, or the
UI's Suggest button. The planner model gets new unhunted advisories (as
untrusted data), coverage gaps, next steps from recent `threat` verdicts, the
environment profile and the connected roles, and proposes specific, testable
hypotheses. Each one is checked: it must use connected roles only and must not
be too similar to a hunt from the last `avoid_repeat_days`. Rejected ones are
listed with the reason. Advisory-based hypotheses get the advisory text as context.

## CLI models (subscriptions)

The `cli` provider runs a model command-line client you are signed in to on
the machine, once per model call:

```yaml
llm:
  providers:
    cli:
      command: ["/path/to/model-cli", "--model", "{model}", "-p={prompt}"]
      timeout_sec: 180
  roles:
    analyst:
      provider: cli
      model: strong-model
      fallback: [{provider: cli, model: fast-model}, {provider: ollama, model: ""}]
```

- The prompt is one argument (no shell), capped at `max_prompt_bytes`. Older
  large results are trimmed to fit.
- The client runs in an empty scratch folder. Put the client's most restricted
  mode (read-only or plan) in the command.
- `cli` is masked by default (see docs/privacy.md), because such clients usually
  send prompts to a cloud service.
- **Fallbacks** work for every provider: when a model fails with a quota or rate
  limit error, the next one in `fallback` is tried, and the exhausted model is
  skipped for an hour.
