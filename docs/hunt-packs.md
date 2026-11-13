# Hunt packs

Hunt hypotheses live as one YAML file per hunt. The built-in pack is in
[`actaeon/hunts/`](../actaeon/hunts), one folder per ATT&CK tactic. They appear in the UI under
**Library**, in `actaeon library starters`, through the MCP tool `list_starters`, and in the
coverage view.

```yaml
id: encoded-powershell-from-office          # lowercase letters, digits, '-'; same as the file name
name: Encoded PowerShell from Office
hypothesis: "An Office application started PowerShell with an encoded or hidden command line in the last 7 days."
attack: [T1059.001, T1204.002]              # current ATT&CK Enterprise technique IDs
roles: [endpoint, log_search]               # connector roles the hunt needs
author: Your name                           # optional from here on
platforms: [windows]                        # windows | linux | macos | cloud | network | identity | saas | containers
references: ["https://..."]                 # https links only
notes: "What normal looks like here, common false positives"
```

A hunt is a hypothesis, not a query: the model writes the queries for your data through your
connectors. So hunts carry no query language and no product names, and one hunt works for every
team.

## Your own packs

Keep private hunts in your own folder and point Actaeon at it:

```yaml
hunt:
  library_dirs: ["/etc/actaeon/hunts"]
```

Files there are added to the built-in pack; a file with the same `id` replaces the built-in one.
Invalid files are skipped (run the validator to see why).

## Checking files

```bash
actaeon library validate                 # the built-in pack
actaeon library validate ./my-hunts      # a folder
actaeon library validate my-hunt.yaml    # one file
```

The validator checks the required fields, the id and file name, that every ATT&CK ID is a
current technique (revoked IDs are reported with their replacement), the roles and platforms, and
that references are https links. It exits 1 on any problem, so it can run in CI.

## Contributing a hunt

1. Add `actaeon/hunts/<tactic>/<id>.yaml`, with the tactic of the first technique.
2. Write the hypothesis as something a person could test: what happened, where, and over what
   time window. Avoid names of products or companies.
3. Run `actaeon library validate` and `pytest -q tests/test_packs.py`.
4. In the pull request, say how you tested it (for example a lab where the behaviour was
   simulated) and what normal activity can look like it.
