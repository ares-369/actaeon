# Privacy: masking data sent to cloud models

When a model role uses a cloud provider, Actaeon masks personal data in every
prompt and puts the real values back in the model's replies.

- Each hunt has its own mapping, and the same value always gets the same
  placeholder (`EMAIL_1`, `IP_2`, `USER_3`, `TERM_1`, `CUSTOM_1`). The model can
  still pivot on a value.
- Replies are unmasked before Actaeon acts on them, so tool calls go to your
  sources with the real values. The values never appear in a prompt.
- Each hunt records how many values were masked, by type, as a step.

```yaml
privacy:
  mask_for: [anthropic, gemini, openai, azure_openai, openai_compatible]  # [] turns masking off
  types: [email, ipv4, ipv6, user]
  terms: ["Example Corp", "corp.example"]     # always masked, case-insensitive
  patterns: ['\bWS-\d{4,}\b']                 # extra regexes, e.g. host naming schemes
  keep_public_ips: false                      # true = only private IPs are masked
```

`ollama` is not in the list by default, because it runs where you run it. If your
`openai_compatible` endpoint is local, you can take it out of the list.

Limits, be aware of them:

- It is pattern-based. A username is found only when it is labelled (`user`,
  `username`, `account`, `upn`, `owner` and similar keys). A bare name in free
  text is not caught, and nor is a hostname, unless you add a pattern for it.
- Hashes, domains and URLs are not masked by default, because hunting needs
  them. Put internal domains under `terms`.
- Masking covers what Actaeon sends. What your own sources log is up to them.
