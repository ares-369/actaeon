"""``actaeon init --company DIR``: a private configuration folder for an organisation.

Keep this folder in a private repository. It holds everything specific to your
environment (connectors, query notes, outputs, environment profile), so the
Actaeon code stays generic and you can upgrade it without merging your changes.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import yaml

from .paths import PKG_DIR, REPO_ROOT

README = """# Actaeon configuration (private)

This folder configures Actaeon for this organisation. Keep it in a private repository.
Never commit `.env`.

| File | What |
|---|---|
| `config.yaml` | connectors, models, outputs, environment profile, schedules |
| `.env` | secrets (copy `.env.example`; inject from your secret manager in production) |
| `notes/` | query notes per connector: fields, syntax and examples for your log platforms |
| `docker-compose.override.yml` | runs Actaeon with this folder mounted |

Check everything with:

    ACTAEON_HOME=$PWD actaeon doctor            # add --models to test model calls
    ACTAEON_HOME=$PWD actaeon outputs test soc-mail

Run:

    ACTAEON_HOME=$PWD actaeon serve             # or docker compose up -d
"""

OVERRIDE = """# Use with the Actaeon repository's docker-compose.yml:
#   docker compose -f docker-compose.yml -f /path/to/this/folder/docker-compose.override.yml up -d
services:
  actaeon:
    volumes:
      - {dir}:/data
"""


def _example() -> dict:
    for p in (REPO_ROOT / "config.example.yaml", PKG_DIR / "config.example.yaml"):
        if p.is_file():
            return yaml.safe_load(p.read_text())
    raise FileNotFoundError("config.example.yaml is missing")


def init_company(target: str, *, name: str = "") -> list[str]:
    root = Path(target).expanduser().resolve()
    if (root / "config.yaml").exists():
        raise FileExistsError(f"{root}/config.yaml already exists")
    (root / "notes").mkdir(parents=True, exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    cfg = _example()
    cfg["actaeon"].update(instance_name=name or "Actaeon", data_dir="", external_url="https://actaeon.example.internal")
    cfg["auth"].update(mode="oidc", default_role="viewer",
                       roles={"soc-lead@example.org": "admin", "analyst@example.org": "operator"})
    cfg["llm"]["roles"] = {
        "planner": {"provider": "gemini", "model": "<fast model>"},
        "analyst": {"provider": "gemini", "model": "<strongest model you can use>",
                    "fallback": [{"provider": "gemini", "model": "<fast model>"}]},
        "reporter": {"provider": "gemini", "model": "<fast model>"}}
    cfg["llm"]["providers"]["gemini"].update(auth="vertex", project="<gcp-project>", location="global")
    cfg["privacy"].update(terms=["<company name>", "<internal domain>"], patterns=[r"\b<HOST-NAMING-REGEX>\b"])
    cfg["environment"] = {"summary": "<one paragraph: what you run, where the important data is>",
                          "platforms": ["windows", "linux", "cloud"], "crown_jewels": ["<system>"],
                          "not_present": ["<technology you do not use>"], "notes": []}
    cfg["hunt"].update(verify=True, prompt_mode="full")
    cfg["intel"]["sweep"].update(interval_minutes=1440, triage="model")
    cfg["outputs"] = [
        {"name": "soc-mail", "type": "email", "when": ["threat"], "smtp_host": "<mail relay>", "smtp_port": 587,
         "username_env": "SMTP_USER", "password_env": "SMTP_PASSWORD", "from": "actaeon@<domain>",
         "to": ["<soc mailbox>"], "to_critical": ["<soc leads>"]}]
    cfg["connectors"] = [{
        "name": "logs", "roles": ["log_search", "endpoint", "network", "identity"], "transport": "http",
        "url": "https://<your log platform's MCP server>/mcp",
        "auth": {"type": "oauth_client_credentials", "token_url": "https://<idp>/oauth2/token",
                 "client_id": "<client id>", "client_secret_env": "LOGS_CLIENT_SECRET"},
        "dialect": "<query language name>", "query_notes_file": str(root / "notes" / "logs.md"),
        "tools": {"deny": ["*contain*", "*isolate*", "*delete*", "*response*"]}}]
    (root / "config.yaml").write_text("# Actaeon configuration for this organisation. Replace every <...>.\n"
                                      + yaml.safe_dump(cfg, sort_keys=False))
    (root / ".env.example").write_text(
        "ACTAEON_SECRET_KEY=\nOIDC_CLIENT_SECRET=\nLOGS_CLIENT_SECRET=\nSMTP_USER=\nSMTP_PASSWORD=\n"
        "# Vertex AI: no key needed when the host has a Google identity; otherwise set credentials_file\n")
    env = root / ".env"
    if not env.exists():
        env.write_text(f"ACTAEON_SECRET_KEY={secrets.token_hex(32)}\n")
        env.chmod(0o600)
    tpl = REPO_ROOT / "docs" / "templates" / "query-notes.md"
    (root / "notes" / "logs.md").write_text(tpl.read_text() if tpl.exists() else "# Query notes\n")
    (root / "README.md").write_text(README)
    (root / "docker-compose.override.yml").write_text(OVERRIDE.format(dir=root))
    (root / ".gitignore").write_text(".env\ndata/\n")
    return [str(p.relative_to(root)) for p in sorted(root.rglob("*")) if p.is_file()]
