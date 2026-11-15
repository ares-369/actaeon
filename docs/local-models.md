# Running with a local model

Actaeon can run on a model on your own hardware through Ollama (or any OpenAI-compatible server), so
no data leaves your network. This page covers the set-up, and what a small local model did on the
built-in demo cases. Short version: the set-up works and the safety checks hold, but a 7B model on a
4 GB GPU did not find the planted attacks. Use the biggest model you can run for the `analyst` role.

## Set-up

```yaml
llm:
  roles:
    planner:  { provider: ollama, model: "qwen2.5-coder:7b" }
    analyst:  { provider: ollama, model: "qwen2.5-coder:7b" }
    reporter: { provider: ollama, model: "qwen2.5-coder:7b" }
  providers:
    ollama:
      base_url: "http://<ollama-host>:11434"
      num_ctx: 8192        # context window asked of Ollama
      timeout_sec: 300     # slow GPUs need time per call
hunt:
  prompt_mode: compact     # shorter tool descriptions and results
```

Then `actaeon models test`, and try `actaeon bench --model ollama/<model>` on the demo data (set up with
`actaeon demo --offline`) before pointing it at real sources.

Things that matter with local models:

- **Context window.** Ollama's own default is 2,048 to 4,096 tokens, and it drops the start of a longer
  prompt without an error, so the model loses its instructions. Actaeon asks for `num_ctx` (default 8192)
  and reports a prompt that still fills the window as an error. More context needs more GPU memory.
- **Compact prompts** (`hunt.prompt_mode: compact`, or the `quick` profile) keep each call small.
- **Time.** On a laptop GPU every model call takes tens of seconds; a hunt takes minutes.
- **Mixed roles.** You can keep `planner` and `reporter` local and give `analyst` a stronger model, or
  the reverse; see [models.md](models.md).

## Measured: qwen2.5-coder:7b on a 4 GB laptop GPU

Hardware: an RTX 3050 laptop GPU (4 GB), the Q4_K_M model with 17 of its 29 layers on the GPU and the
rest on the CPU, `num_ctx` 8192, `prompt_mode: compact`. The 8 built-in demo cases (4 planted threats,
1 harmless look-alike, 3 with nothing to find), one run each, 2026-11-15.

| Run | Correct | Threats found (of 4) | False positives | Input tokens per hunt | Time per hunt |
|---|---|---|---|---|---|
| 1: context window, broaden-once nudge, demo ranges | 3 / 8 | 0 | 0 | 28k | 2.7 min |
| 2: plus the two verdict checks and rounded times | 3 / 8 | 0 | 0 | 66k | 7.4 min |

The 3 correct answers in run 1 were the cases with nothing to find, so they say little. What went wrong
in run 1, read from the stored tool calls:

- **Guessed values.** It searched for `*EncodedCommand*` where the data has `-enc`, or added filters on
  values it had never seen, got no hits and stopped.
- **Contradicting itself.** On the scheduled-task case it found the event and wrote "a scheduled task that
  runs a hidden PowerShell script was found", but gave the outcome `no_results`.
- **Wrong reasoning about intel.** On the beacon case it found the destination in the intel store and
  called it benign because it matched a known advisory.

What changed in Actaeon because of these runs (an earlier, unscored attempt found the first three), for
every model:

- the Ollama context window (`num_ctx`), as above;
- when every search matched nothing, the model is asked once to search more broadly before `no_results`;
- a `no_results` whose findings cite matching results becomes `inconclusive` and goes to an analyst;
- a `benign` verdict while an intel lookup matched goes to an analyst;
- the demo data source and the bridges accept what search indexes accept: ranges such as
  `@timestamp:[now-7d TO now]` and rounded times such as `now-7d/d`.

The two verdict checks do not make a small model find threats; they make its mistakes end with a person
instead of being closed as harmless. In run 2 neither fired, because the model never cited a result that
matched: it missed the evidence altogether. The broaden-once nudge fired twice without changing an
outcome. Run 2 was also slower and used more tokens than run 1, on the same cases: the same model varies
a lot from run to run, so one run of 8 cases is a rough sign, not a score.

## Not measured

Larger local models (14B, 32B or 70B) were not tested here; the hardware cannot hold them. Results from
other models are welcome: run `actaeon bench --model ollama/<model> --markdown` and open an issue with
the row and the JSON report (see [benchmarks.md](benchmarks.md)).
