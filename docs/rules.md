# Rule library

The rule library keeps your detection rules (Sigma) in Actaeon, tests them against sample events, puts each one
through a review step, and shows which ATT&CK techniques your rules cover and where the gaps are. A model can
draft a rule for a gap; a person decides whether it is ready.

Actaeon never deploys a rule into your log platform. Rules leave as a zip of Sigma files, their tests and (where a
connector has a `sigma:` block) the converted queries, for your own review and deployment process.

It is off by default:

```yaml
rules:
  enabled: true
  min_real_tests: 1              # real events a rule must catch before it can be marked ready
  min_no_match_tests: 1          # events it must not catch
  allow_self_approval: false     # true: the last editor may also mark a rule ready (one-person teams)
  field_map: {}                  # Sigma field -> your field names, e.g. {Image: ["data.win.eventdata.image"]}
  priorities: []                 # ATT&CK techniques you want rules for, e.g. [T1059.001, T1003.001]
  draft_samples: true            # model drafts come with example events (marked synthetic)
```

## Status

```
draft -> testing -> ready -> retired
```

- **draft**: new, imported, or drafted by a model.
- **testing**: submitted for review. Tests are run and checked.
- **ready**: approved by a person. Only these count as coverage and are exported by default.
- **retired**: kept for history; does not count.

Editing a rule saves a new version. Editing a ready rule sends it back to testing and clears the approval.

A rule can be marked ready only when all of these hold:

1. The checks find no errors (valid YAML, a condition, no value that matches anything, a condition that does
   more than exclude).
2. It has at least `min_real_tests` **real** events it must match. Events written by hand or by a model are
   marked synthetic and never count here.
3. It has at least `min_no_match_tests` events it must not match.
4. The tests were run for the current version and all pass.
5. The person approving is not the last editor (unless `allow_self_approval: true`).

## Tests

A test is one event (a JSON object) and whether the rule must or must not match it. Tests run locally with
Actaeon's own Sigma matcher, so no log platform is needed and nothing is queried.

The matcher covers single-event rules: field maps, lists, keywords, wildcards, the modifiers `contains`,
`startswith`, `endswith`, `all`, `re` (with `i`, `m`, `s`), `cidr`, `exists`, `base64`, `base64offset`,
`wide`/`utf16*`, `windash`, `lt`/`lte`/`gt`/`gte`, `cased`, and conditions with `and`, `or`, `not`, brackets,
`1 of`, `all of` and `them`. Correlation rules, aggregations (`| count()`), `fieldref` and `expand` are reported
as "cannot test locally"; such a rule cannot be marked ready.

Field names: a rule field is looked up as written, then through `rules.field_map`, then case-insensitively,
then by the last part of a dotted name, so `CommandLine` finds `data.win.eventdata.commandLine`. Each result
shows which event field matched, so a wrong mapping is visible.

Where real events come from:

- **A hunt that found a threat**: "Add to the rule library" on the hunt's detection draft creates the rule and
  adds the events behind the hunt's findings as real "must match" tests.
- **By hand**: paste an event from your log platform on the rule page (origin "real event from logs").

"Convert and count matches" on a rule converts it with pySigma for every connector with a `sigma:` block and
counts how often it would have matched over the last 14 days (needs a `count` tool on the connector). This is
the noise check against your real data; the local tests are the logic check.

## Checks

Errors block the ready status: invalid YAML, a missing title/logsource/detection/condition, a value that matches
anything (`'*'`), a condition that only excludes.

Warnings are advice: no level, description, falsepositives or ATT&CK tag; keyword-only rules; very short
`contains` values; fields never seen in your data (from stored hunt and triage results); and the same detection
logic as another rule.

## Coverage and gaps

The Coverage tab lists ATT&CK techniques with their rules by status, and why each matters:

- a hunt found a threat with that technique
- a hunt found data for it (benign)
- a true-positive alert case was tagged with it
- it is on `rules.priorities`

A **gap** is a technique with a reason and no ready rule. "Covered" means at least one ready rule is tagged with
the technique; it does not prove every way of doing the technique is caught.

## Drafting with a model

"Draft" on a gap (or a technique id typed in) asks the reporter model for a rule. It is given the technique's
name, tactics, data sources and platforms, your `environment:` profile, field names seen in your data, events from
hunts that found the technique, the titles of rules you already have for it, and any notes or advisory you paste.
Prompts go through the same privacy masking as hunts.

The draft is a normal draft rule with the model's example events attached as synthetic tests. Add at least one
real event before it can be marked ready.

## Import and export

- Web UI: paste one rule (Add) or several YAML documents separated by `---` (Import).
- CLI: `actaeon rules import PATH` takes a file or a folder (for example a checkout of a public Sigma rule
  repository). New ids become drafts; known ids get a new version if the text changed.
- Export: the zip from the Rules page or `actaeon rules export --out rules.zip [--status ready,testing]` holds
  `<status>/<title>_<id>.yml`, `.tests.json` and converted queries, plus `INDEX.txt` with versions and approvers.

## Command line

```
actaeon rules list [--status S]
actaeon rules show ID
actaeon rules test ID | --all       # exit code 1 when a test fails
actaeon rules lint ID
actaeon rules coverage
actaeon rules draft T1059.001 [--context @advisory.txt]
actaeon rules import PATH
actaeon rules export --out rules.zip [--status ready]
```

`actaeon rules test --all` suits a scheduled check or CI on an exported rule set.

## MCP

Read-only tools: `list_rules`, `get_rule`, `rule_coverage`. There is no tool to approve a rule.

## API

`GET/POST /api/rules`, `GET/POST /api/rules/<id>`, `POST /api/rules/<id>/status` (`submit`, `approve`, `back`,
`retire`, `reopen`), `POST /api/rules/<id>/tests`, `POST /api/rules/<id>/run`, `POST /api/rules/<id>/convert`,
`GET /api/rules/coverage`, `POST /api/rules/draft`, `POST /api/rules/from-hunt/<hunt id>`,
`POST /api/rules/import`, `GET /api/rules/export.zip`. Viewers can read; operators and admins can change.
