# Demo

Try Actaeon with no real data sources:

```bash
actaeon demo --offline --run       # scripted run, no model needed
ACTAEON_HOME=~/.actaeon-demo actaeon serve    # http://127.0.0.1:8611
```

The demo home has:

- a `demo-logs` connector that serves synthetic events (`actaeon bridge demo`).
  Every event carries `sample: "SAMPLE DATA - not real"`, and only
  documentation IP ranges and `.example` domains are used;
- a sample advisory in the intel store;
- a sample memory note about a benign admin script;
- an environment profile describing the sample hosts;
- a banner on every UI page saying the data is synthetic.

The sample story: on `DEMO-WS07`, Word starts encoded PowerShell. The script
downloads from `update-check.example` (203.0.113.66), creates a scheduled task
and beacons every 30 minutes. A nightly admin script on `DEMO-ADM01` also uses
encoded PowerShell and is benign, a false lead the hunt has to tell apart.

**`--offline` is not AI.** It uses a scripted demo provider that replays a fixed
investigation, so you can see the pipeline (plan, validator, connector hub,
evidence ids, verdict checks, report, sweep) with no model installed. Every
scripted reply is marked `[scripted demo]`, and the hunt record names the
provider as `demo`.

To see a real model hunt the sample data, leave out `--offline`, point the
`llm` section of `~/.actaeon-demo/config.yaml` at your model, then run
`actaeon hunt "..."` with `ACTAEON_HOME` set, or use the UI. Results depend
heavily on the model.

The demo bridge understands only a small part of query_string syntax
(`field:value`, wildcards, quotes, `AND`/`OR`/`NOT`, parentheses).
