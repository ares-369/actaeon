# Benchmarks

Actaeon includes a scored hunting benchmark (`actaeon bench`) that runs labelled
hypotheses through the real hunt engine and checks each verdict against expected
outcomes, reporting overall accuracy plus threat precision and recall.

## Running the built-in demo benchmark

The built-in suite uses the synthetic demo data (`actaeon/demo/data.py`,
8 labelled cases covering both true-positive threats and benign/absent
scenarios):

```bash
actaeon demo --dir /tmp/actaeon-bench --offline
ACTAEON_HOME=/tmp/actaeon-bench actaeon bench
```

Each run writes a timestamped JSON report under `data/bench-*.json` with
per-case outcomes, confidence, tool-call counts, runtime, and summary metrics.

## Running against your own data

Create a YAML file of labelled hypotheses:

```yaml
- id: my-case
  hypothesis: "An Office application started PowerShell with an encoded command in the last 7 days."
  expect: [threat]

- id: clean-case
  hypothesis: "A scheduled task named TestLabUpdate ran on LAB-01 in the last 7 days."
  expect: [telemetry_found_benign, no_results]
```

Then run:

```bash
actaeon bench --cases my-cases.yaml
```

## Notes on interpreting scores

- Results depend heavily on the model assigned to the `analyst` role and on the
  quality of your connector query guides.
- A handful of synthetic cases is a regression smoke check, not a measure of
  real-world detection coverage.
- Always inspect cited evidence (`E1`, `E2`, ...) rather than relying on a
  verdict label alone.
