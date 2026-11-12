# Intel

Actaeon has its own intel store, so you can hunt with intel you add yourself, even
with no intel platform. Hunts reach it through the built-in `local-intel`
connector (role `intel`). The connector is read-only: you add intel in the UI,
API or CLI, never through MCP. You can also add other intel sources as normal
connectors (for example the `taxii` bridge); the hunt engine uses every
connector with the `intel` role.

## Adding intel

- **Paste:** indicators or free text such as an advisory or an email. IPs, IPv6,
  domains, URLs, emails, MD5/SHA-1/SHA-256, CVEs and ATT&CK technique IDs are
  extracted. Defanged values (`hxxp`, `[.]`, `(.)`, `[@]`) are handled. The host
  of each URL and the domain of each email are added too. Use Preview first:
  extraction is pattern-based and can miss values or pick up wrong ones.
- **Advisory:** give the text a title and it is kept as an advisory with its
  techniques and CVEs, and its indicators are tagged `advisory:<id>`.
- **Import an advisory from a URL, PDF or HTML file:** `actaeon intel advisory --url https://...`,
  `actaeon intel advisory report.pdf`, or the Import box in the UI. PDF needs the `pdf` extra.
  URLs that resolve to private addresses are refused unless `intel.allow_private_urls: true`.
- **Import a file:** `text`, `csv`, `stix` (2.x bundle) or `json`.
- **Feeds:** URLs under `intel.feeds` in `config.yaml`, pulled on demand.

Advisories pulled from the web or imported from a URL or file keep domains, URLs
and emails only if the text defanged them (`hxxp`, `[.]`), because plain links in
advisories are usually references. The publisher's own domain is never kept.
IPs, hashes, CVEs and techniques are kept as usual. Links that were left out are
listed in `skipped_links`. Pasted text is kept as you give it.

Each indicator has a confidence (0-100), tags, a source, an optional expiry and
a ledger: `first_seen`, `last_seen` and `seen_count`. Adding a value again
updates it (higher confidence wins, tags and sources merge) instead of making a
copy. Deactivated or expired indicators are left out of lists.

## Threat actors

An actor profile holds a name, aliases, a description, ATT&CK techniques, tools
and malware, and indicators. Indicators come from any text you give it, and are
tagged `actor:<name>`. Saving the same actor again merges the new details.

**Hunt this actor** (UI, `POST /api/intel/actors/<name>/hunt`, or
`actaeon hunt --actor NAME`) runs a campaign:
1. a sweep of every indicator tagged to the actor (any confidence), with
   executed / blocked / passive triage;
2. a model hunt for the actor's techniques and tools, with the profile as context.

Autopilot also proposes hunts for actors that have not been hunted recently.

```bash
actaeon intel actor add "Sample Bear" --alias SB-1 --technique T1566.001 --tool LoaderX --indicators report.txt
actaeon intel actor list
actaeon hunt --actor "Sample Bear"
```

## CLI

```bash
actaeon intel add 203.0.113.9 evil.example --confidence 80 --tag c2
actaeon intel paste notes.txt                       # or pipe text on stdin
actaeon intel advisory report.txt --title "Campaign X" --confidence 70
actaeon intel import iocs.csv --format csv --value-field indicator
actaeon intel import bundle.json --format stix
actaeon intel pull                                   # all feeds, or name one
actaeon intel lookup www.evil.example                # also shows parent-domain matches
actaeon intel list --type domain
actaeon intel stats
```

## Feeds

```yaml
intel:
  local: true            # set false to drop the built-in connector
  feeds:
    - name: exploited-cves
      url: "https://example.org/known_exploited.json"
      format: json
      list_key: vulnerabilities   # dot path to the list
      value_field: cveID
      type: cve                   # optional; guessed per value otherwise
      confidence: 90
      tags: [exploited]
      ttl_days: 90                # optional expiry
      token_env: FEED_TOKEN       # optional bearer token from .env
      max_items: 50000
```

Values that are not recognised as indicators are skipped and counted.

## Tools hunts see

`lookup`, `list_indicators` (by type, tag, confidence, `changed_since`),
`list_advisories`, `get_advisory`, `extract_indicators` (does not save) and
`intel_stats`.
