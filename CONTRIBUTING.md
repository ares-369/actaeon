# Contributing

Thanks for taking a look. Actaeon is early, and issues with clear steps to
reproduce help the most.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ruff check actaeon tests benchmarks scripts && node --check actaeon/static/app.js && pytest -q
actaeon demo --offline --run      # quick end-to-end check
```

Guidelines:

- Keep hunts read-only. New connector or bridge code must not add write paths.
- Treat everything from a data source, an intel feed or a model as untrusted.
- No product or vendor names in code, UI or docs; describe roles and protocols.
- Add tests with each change, and keep the UI free of `innerHTML`.
- Keep the tone modest: state what was tested and what was not.
