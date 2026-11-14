"""``actaeon doctor``: check a deployment end to end and say what to fix.

Each check returns OK, WARN or FAIL with a hint. Network checks (connector probes)
run unless ``offline``; model checks only with ``models=True`` because they cost
a model call per role.
"""

from __future__ import annotations

import importlib.util
import os
import shutil


def _has(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError):
        return False


def run(cfg=None, *, offline: bool = False, models: bool = False) -> list[dict]:
    out: list[dict] = []

    def add(level, area, msg, hint=""):
        out.append({"level": level, "area": area, "message": msg, "hint": hint})

    from .config import get_config
    try:
        cfg = cfg or get_config(reload=True)
    except Exception as exc:
        add("FAIL", "config", f"config.yaml does not load: {exc}", "fix the file; see config.example.yaml")
        return out
    add("OK", "config", f"loaded {cfg.path}")

    # data folder
    try:
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        probe = cfg.data_dir / ".doctor"
        probe.write_text("x")
        probe.unlink()
        free = shutil.disk_usage(cfg.data_dir).free // (1024 * 1024)
        add("OK" if free > 500 else "WARN", "data", f"{cfg.data_dir} writable, {free} MB free",
            "" if free > 500 else "less than 500 MB free")
    except OSError as exc:
        add("FAIL", "data", f"{cfg.data_dir} is not writable: {exc}", "fix permissions or actaeon.data_dir")

    # storage
    from . import db
    if db.is_pg():
        try:
            with db.connect(cfg.data_dir / "doctor.sqlite") as c:
                ver = c.execute("SHOW server_version").fetchone()[0]
            add("OK", "storage", f"PostgreSQL {ver}, schema {db._settings['schema']}")
        except Exception as exc:
            add("FAIL", "storage", f"PostgreSQL: {str(exc)[:200]}",
                "check ACTAEON_DB_URL / database.url, and pip install 'actaeon[postgres]'")
    else:
        add("OK", "storage", "SQLite in the data folder")
    jm = ((cfg.raw or {}).get("jobs") or {}).get("mode", "local")
    if jm == "queue" and not db.is_pg():
        add("OK", "jobs", "queue mode on SQLite: workers must run on this machine, with this data folder")

    # auth posture
    from .server import startup_security_check
    errors, warnings = startup_security_check(cfg)
    for e in errors:
        add("FAIL", "auth", e)
    for w in warnings:
        add("WARN", "auth", w)
    if cfg.auth.mode in ("local", "oidc") and not cfg.auth.secret_key:
        add("WARN", "auth", "ACTAEON_SECRET_KEY is not set; sessions end on every restart", "set it in .env")
    if cfg.auth.mode == "none":
        add("WARN" if cfg.bind_host not in ("127.0.0.1", "localhost", "::1") else "OK", "auth",
            "no login (auth.mode none); fine for a single user on this machine only",
            "use oidc or proxy for a team")
    else:
        add("OK", "auth", f"auth.mode {cfg.auth.mode}, {len(cfg.auth.users)} named account(s)")
    if cfg.auth.mode == "oidc" and not _has("authlib"):
        add("FAIL", "auth", "auth.mode oidc needs the oidc extra", "pip install 'actaeon[oidc]'")

    # models: extras, privacy
    roles = {r: cfg.role_cfg(r) for r in ("planner", "analyst", "reporter")}
    used = {rc.get("provider", "ollama") for rc in roles.values()} | {
        f.get("provider") for rc in roles.values() for f in rc.get("fallback") or []}
    need = {"gemini": "google.genai", "anthropic": "anthropic", "openai": "openai", "azure_openai": "openai",
            "openai_compatible": "openai"}
    for p in sorted(x for x in used if x):
        mod = need.get(p)
        if mod and not _has(mod):
            extra = {"azure_openai": "openai", "openai_compatible": "openai"}.get(p, p)
            add("FAIL", "models", f"provider {p} is used but its SDK is not installed", f"pip install 'actaeon[{extra}]'")
    priv = (cfg.raw or {}).get("privacy") or {}
    mask_for = priv.get("mask_for", ["anthropic", "gemini", "openai", "azure_openai", "openai_compatible", "cli"])
    cloud = [p for p in used if p and p not in ("ollama", "demo")]
    unmasked = [p for p in cloud if p not in mask_for]
    if unmasked:
        add("WARN", "privacy", f"prompts to {', '.join(unmasked)} are not masked", "add them to privacy.mask_for")
    if cloud and not priv.get("terms"):
        add("WARN", "privacy", "no privacy.terms set; internal domain and company names would reach the cloud model",
            "list them under privacy.terms")
    if roles["analyst"].get("provider", "ollama") == "ollama":
        add("WARN", "models", "the analyst role uses a local model; small models hunt poorly",
            "use the strongest model you can for the analyst (docs/models.md)")
    if models:
        from .cli import test_models
        for r in test_models(cfg):
            add("OK" if r["ok"] else "FAIL", "models", f"{r['role']}: {r['provider']}/{r['model']} "
                + (f"answered in {r['ms']} ms" if r["ok"] else r["error"]))
    else:
        add("OK", "models", "model calls not tested (run with --models)")

    # connectors
    from .connectors import get_hub
    from .connectors.spec import DATA_ROLES
    hub = get_hub(cfg, reload=True)
    data = [s for s in hub.specs.values() if s.enabled and set(s.roles) & set(DATA_ROLES)]
    if not data:
        add("FAIL", "connectors", "no data connector: hunts cannot search anything", "add one under connectors:")
    for s in hub.specs.values():
        if not s.enabled:
            continue
        if set(s.roles) & set(DATA_ROLES) and not (s.query_notes or s.query_examples):
            add("WARN", "connectors", f"{s.name}: no query notes or examples",
                "add query_notes_file (docs/templates/query-notes.md); it is the biggest accuracy gain")
        if offline:
            continue
        r = hub.test(s.name)
        add("OK" if r["ok"] else "FAIL", "connectors",
            f"{s.name}: " + (f"{r['allowed']}/{r['tools']} tools allowed" + (f", {r['probe']} read OK" if r.get('probe')
                                                                              else "") if r["ok"] else r["error"]))
    hub.close()

    # outputs
    outs = (cfg.raw or {}).get("outputs") or []
    for o in outs:
        if o["type"] == "email":
            missing = [e for e in (o.get("username_env"), o.get("password_env")) if e and not os.getenv(e)]
            add("WARN" if missing else "OK", "outputs", f"{o['name']}: email to {len(o.get('to') or [])} recipient(s)"
                + (f"; env not set: {', '.join(missing)}" if missing else ""), "actaeon outputs test " + o["name"])
        else:
            add("OK", "outputs", f"{o['name']}: {o['type']}")
    if not outs:
        add("WARN", "outputs", "no outputs: threats are only visible in the UI", "add an email output under outputs:")
    if not _has("reportlab") or not _has("docx"):
        add("WARN", "reports", "PDF/Word reports need the reports extra", "pip install 'actaeon[reports]'")

    # intel and schedules
    intel = cfg.intel or {}
    n_sources = len((intel.get("web") or {}).get("sources") or []) + len(intel.get("feeds") or [])
    add("OK" if n_sources else "WARN", "intel", f"{n_sources} intel feed(s)/web source(s)",
        "" if n_sources else "add intel.feeds or intel.web.sources")
    sched = {"sweep": (intel.get("sweep") or {}).get("interval_minutes", 0),
             "web intel": (intel.get("web") or {}).get("interval_minutes", 0),
             "autopilot": ((cfg.raw or {}).get("autopilot") or {}).get("interval_minutes", 0)}
    add("OK", "schedule", ", ".join(f"{k}: {'every ' + str(v) + ' min' if v else 'manual'}" for k, v in sched.items()))
    return out
