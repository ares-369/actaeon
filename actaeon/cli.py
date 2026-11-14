"""Command line entry point: ``actaeon [serve|init|version|models|hash-password]``."""

from __future__ import annotations

import argparse
import getpass
import secrets
import shutil
import sys
from pathlib import Path

from . import __version__
from .paths import PKG_DIR, REPO_ROOT, home_dir


def _example_config() -> Path:
    for p in (REPO_ROOT / "config.example.yaml", PKG_DIR / "config.example.yaml"):
        if p.is_file():
            return p
    raise FileNotFoundError("config.example.yaml is missing from this install")


def cmd_init(force: bool = False, database: str = "sqlite", db_url: str = "") -> int:
    home = home_dir()
    home.mkdir(parents=True, exist_ok=True)
    (home / "data").mkdir(exist_ok=True)
    cfg = home / "config.yaml"
    if cfg.exists() and not force:
        print(f"{cfg} already exists (use --force to overwrite)")
    else:
        shutil.copyfile(_example_config(), cfg)
        print(f"wrote {cfg}")
    env = home / ".env"
    if not env.exists():
        env.write_text(f"ACTAEON_SECRET_KEY={secrets.token_hex(32)}\n")
        env.chmod(0o600)
        print(f"wrote {env}")
    if database == "postgres":
        return _init_postgres(env, db_url)
    print("storage: SQLite in the data folder (nothing else to install)")
    return 0


def _init_postgres(env: Path, db_url: str) -> int:
    """Store the PostgreSQL URL in .env (it holds the password) and check that it connects."""
    import os

    from . import db
    db_url = db_url or os.getenv("ACTAEON_DB_URL", "")
    if not db_url:
        if not sys.stdin.isatty():
            print("--database postgres needs --db-url postgresql://user:password@host:5432/dbname")
            return 2
        db_url = getpass.getpass("PostgreSQL URL (postgresql://user:password@host:5432/dbname): ").strip()
    try:
        db.configure(db_url)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    lines = [ln for ln in env.read_text().splitlines() if not ln.startswith("ACTAEON_DB_URL=")]
    env.write_text("\n".join([*lines, f"ACTAEON_DB_URL={db_url}"]) + "\n")
    env.chmod(0o600)
    print(f"storage: PostgreSQL (URL saved in {env})")
    try:
        with db.connect(home_dir() / "data" / "check.sqlite") as c:
            c.execute("SELECT 1")
        print("connected OK; tables are created on first start")
        return 0
    except Exception as exc:
        print(f"could not connect yet: {str(exc)[:300]}")
        print("fix the URL in .env (or install the extra: pip install 'actaeon[postgres]') and run actaeon doctor")
        return 1


def cmd_models() -> int:
    from .config import LLM_ROLES, get_config
    cfg = get_config()
    for role in LLM_ROLES:
        rc = cfg.role_cfg(role)
        print(f"{role:9} {rc.get('provider', 'ollama'):18} {rc.get('model') or '(provider default)'}")
    return 0


def cmd_login(name: str | None, manual: bool) -> int:
    from .config import get_config
    from .connectors.oauth import OAuthError, login
    from .connectors.spec import parse_connectors
    cfg = get_config()
    specs = {s.name: s for s in parse_connectors(list(cfg.connectors))}
    if not name or name not in specs:
        print("usage: actaeon connectors login <name> (an HTTP connector with auth: {type: oauth})")
        return 2
    if specs[name].auth.get("type") != "oauth":
        print(f"{name} does not use auth type oauth")
        return 2
    try:
        r = login(specs[name], cfg.data_dir, ask=input if manual else None)
    except OAuthError as exc:
        print(f"sign-in failed: {exc}")
        return 1
    print(f"signed in ({r.get('scope') or 'default scope'}); token saved under data/oauth/")
    return 0


def cmd_connectors(action: str, name: str | None) -> int:
    from .connectors import get_hub
    hub = get_hub()
    if action == "list":
        for s in hub.specs.values():
            state = "on " if s.enabled else "off"
            print(f"{state} {s.name:20} {s.transport:6} {','.join(s.roles)}")
        if not hub.specs:
            print("no connectors configured (see connectors: in config.yaml)")
        return 0
    names = [name] if name else list(hub.specs)
    rc = 0
    for n in names:
        if n not in hub.specs:
            print(f"unknown connector {n}")
            return 1
        if action == "check":
            from .connectors.contract import check
            res = check(hub, n)
            print(f"== {n}")
            for r in res:
                print(f"  {r['level']:4}  {r['check']}" + (f": {r['detail']}" if r["detail"] else ""))
            rc |= 1 if any(r["level"] == "FAIL" for r in res) else 0
        elif action == "test":
            r = hub.test(n)
            print(f"{n}: " + (f"ok, {r['allowed']}/{r['tools']} tools allowed, {r['ms']} ms" if r["ok"]
                              else f"FAILED: {r['error']}"))
            rc |= 0 if r["ok"] else 1
        else:
            for t in hub.tools(n):
                print(f"{n:16} {'allow' if t['allowed'] else 'BLOCK'} {t['name']:32} {t['reason']}")
    hub.close()
    return rc


def cmd_intel(a) -> int:
    import json as _json

    from .config import get_config
    from .intel import IntelStore
    from .intel.feeds import import_file, pull_feed
    cfg = get_config()
    store = IntelStore(cfg.data_dir / "intel.sqlite")
    kw = {}
    if hasattr(a, "confidence"):
        kw = {"confidence": a.confidence, "tags": a.tag}
    if a.action == "add":
        res = []
        for v in a.values:
            try:
                res.append(store.add(v, a.type, source=a.source or "manual", ttl_days=a.ttl_days, **kw))
            except ValueError as exc:
                print(f"skip: {exc}")
        out = res
    elif a.action == "paste":
        text = Path(a.file).read_text() if a.file else sys.stdin.read()
        r = store.add_text(text, source=a.source or "paste", ttl_days=a.ttl_days, **kw)
        out = {k: r[k] for k in ("found", "new", "updated")}
    elif a.action == "advisory":
        from .intel.fetch import fetch_url, read_file
        if a.url and not a.file:
            doc = fetch_url(a.url, allow_private=bool(cfg.intel.get("allow_private_urls", False)))
        elif a.file:
            doc = read_file(a.file)
        else:
            doc = {"title": "", "text": sys.stdin.read()}
        title = a.title or doc.get("title") or "Untitled advisory"
        out = store.add_advisory(title, doc["text"], source=a.source or "advisory", url=a.url or doc.get("url", ""),
                                 strict_links=bool(a.url or a.file), **kw)
    elif a.action == "import":
        out = import_file(store, a.file, a.format, kind=a.type, value_field=a.value_field, list_key=a.list_key,
                          extract=a.extract, ttl_days=a.ttl_days, **({"source": a.source} if a.source else {}), **kw)
    elif a.action == "pull":
        feeds = [f for f in cfg.intel.get("feeds") or [] if not a.name or f.get("name") == a.name]
        if not feeds:
            print("no matching feeds under intel.feeds in config.yaml")
            return 1
        out = []
        for f in feeds:
            try:
                out.append(pull_feed(store, f))
            except Exception as exc:
                out.append({"source": f.get("name"), "error": str(exc)[:200]})
    elif a.action == "actor":
        if a.op == "list":
            for r in store.actors():
                print(f"{r['slug']:24} {r['name']:30} techniques {len(r['techniques'])}  tools {len(r['tools'])}  "
                      f"indicators {r['indicator_count']}")
            return 0
        if not a.name:
            print("a name is required")
            return 2
        if a.op == "show":
            out = store.actor(a.name) or {"error": "no such actor"}
            if "indicators" in out:
                out["indicators"] = [f"{i['type']} {i['value']}" for i in out["indicators"]]
        else:
            text = Path(a.indicators).read_text(errors="replace") if a.indicators else ""
            out = store.save_actor(a.name, aliases=a.alias, description=a.description, techniques=a.technique,
                                   tools=a.tool, indicators_text=text, confidence=kw.get("confidence", 70))
            out["indicators"] = len(out.get("indicators") or [])
    elif a.action == "web":
        from .hunt.service import run_web_intel
        jobs = None
        if a.hunt:
            from .jobs import JobManager
            jobs = JobManager(cfg.data_dir / "actaeon.sqlite")
        out = run_web_intel(cfg, jobs=jobs, only=a.name)
        out.pop("id", None)
        if jobs and out["hunts"]:
            print(f"started {len(out['hunts'])} hunt(s); waiting for them to finish...")
            jobs.pool.shutdown(wait=True)
    elif a.action == "export":
        from .intel.stix import export_store
        b = export_store(store, tag=a.tag[0] if a.tag else None, min_confidence=a.min_confidence,
                         changed_since=a.since or None, producer_name=a.producer)
        text = _json.dumps(b, indent=1)
        if a.output:
            Path(a.output).write_text(text)
            print(f"wrote {len(b['objects'])} STIX objects to {a.output}")
        else:
            print(text)
        return 0
    elif a.action == "lookup":
        out = store.lookup(a.value)
    elif a.action == "list":
        for r in store.list(kind=a.type, limit=a.limit):
            print(f"{r['type']:9} {r['value']:60} conf={r['confidence']:<3} seen={r['seen_count']} {r['source']}")
        return 0
    else:
        out = store.stats()
    print(_json.dumps(out, indent=2))
    return 0


def _print_verdict(v: dict) -> None:
    print(f"\nverdict: {v['outcome']} (confidence {v['confidence']})\n{v['summary']}")
    for f in v.get("findings") or []:
        print(f"  - {f['claim']} [{', '.join(f['evidence'])}]")
    for f in v.get("unsupported_claims") or []:
        print(f"  ? (no evidence) {f['claim']}")
    if v.get("attack"):
        print("ATT&CK: " + ", ".join(v["attack"]))
    for c in v.get("checks") or []:
        print(f"check: {c}")


def store_slug(name: str) -> str:
    from .intel.store import IntelStore
    return IntelStore.slug(name)


def cmd_hunt(a) -> int:
    import json as _json

    from .config import get_config
    from .hunt.service import store_for
    cfg = get_config()
    store = store_for(cfg)
    if a.list:
        for h in store.list(limit=30):
            print(f"{h['id']}  {h['created']}  {h['status']:8} {h['outcome'] or ''!s:22} {h['hypothesis'][:70]}")
        return 0
    if a.show:
        h = store.get(a.show)
        if not h:
            print("no such hunt")
            return 1
        if a.json:
            print(_json.dumps(h, indent=2))
            return 0
        print(f"{h['hypothesis']}\nstatus {h['status']}")
        for s in h["steps"]:
            if s["kind"] == "call":
                print(f"E{s['n']} {'ok ' if s['ok'] else 'ERR'} {s['connector']}.{s['tool']} {_json.dumps(s['arguments'])[:150]}")
            elif s["kind"] in ("blocked", "note"):
                print(f"   {s['kind']}: {s['note'][:150]}")
        if h.get("verdict"):
            _print_verdict(h["verdict"])
        return 0
    context, origin = "", "manual"
    if a.actor:
        from .hunt.service import actor_campaign
        from .jobs import JobManager
        jobs = JobManager(cfg.data_dir / "actaeon.sqlite")
        r = actor_campaign(cfg, jobs, a.actor, actor="cli")
        print(f"campaign for {r['actor']}: hunt {r['hunt_id']}" + (" and an indicator sweep" if r["sweep_job"] else ""))
        jobs.pool.shutdown(wait=True)
        h = store.get(r["hunt_id"])
        _print_verdict(h["verdict"])
        for s in store.list(limit=20, origin=f"actor:{store_slug(a.actor)}"):
            if s["id"] != h["id"]:
                print(f"\nsweep {s['id']}: {s['outcome']}: {(s['verdict'] or {}).get('summary', '')}")
        return 0
    if a.advisory:
        from .hunt.service import advisory_hunt
        a.hypothesis, context = advisory_hunt(cfg, a.advisory)
        origin = f"advisory:{a.advisory}"
        print(f"hypothesis: {a.hypothesis}")
    if not a.hypothesis:
        print("give a hypothesis, --advisory ID, --show ID or --list")
        return 2

    def ev(e):
        if e["type"] == "plan":
            p = e["plan"]
            print(f"plan: {p['summary']}  ATT&CK {', '.join(p['attack']) or '-'}")
            for s in p["steps"]:
                print(f"  [{s['role']}] {s['goal']}")
            if p.get("missing_roles"):
                print(f"  no connector for: {', '.join(p['missing_roles'])}")
        elif e["type"] == "step":
            print(f"E{e['n']} {'ok ' if e['ok'] else 'ERR'} {e['tool']}", flush=True)
    from .hunt.service import run_hunt
    h = run_hunt(cfg, a.hypothesis, origin=origin, context=context, on_event=ev, max_steps=a.max_steps)
    _print_verdict(h["verdict"])
    print(f"\nhunt id {h['id']} (actaeon hunt --show {h['id']})")
    return 0


def cmd_phase5(a) -> int:
    import json as _json

    from .config import get_config
    from .hunt import service as hs
    from .hunt.library import starters
    cfg = get_config()
    if a.cmd == "sweep":
        h = hs.run_sweep(cfg, full=a.full, actor="cli")
        _print_verdict(h["verdict"])
        print(f"\nhunt id {h['id']}")
        return 0
    if a.cmd == "note":
        mem = hs.memory_for(cfg)
        if a.list or not a.text:
            for n in mem.notes():
                state = "   " if n["active"] else ("EXP" if n.get("expired") else "OFF")
                print(f"{n['id']:4} {state} {n['text'][:100]} {n['tags']}"
                      + (f" until {n['expires'][:10]}" if n.get("expires") else ""))
            return 0
        print(_json.dumps(mem.add_note(a.text, author="cli", tags=a.tag, expires_days=a.expires_days)))
        return 0
    lib = hs.library_for(cfg)
    if a.action == "starters":
        for s in starters(cfg):
            print(f"- {s['name']} [{', '.join(s['attack'])}]\n    {s['hypothesis']}")
        return 0
    if a.action == "list":
        for s in lib.list():
            every = f"every {s['interval_minutes']}m" if s["interval_minutes"] else "manual"
            print(f"{s['id']:4} {every:12} last={s['last_run'] or '-'} hits={s['last_hits']} {s['name'][:60]}")
        return 0
    if not a.id:
        print("an id is required")
        return 2
    if a.action == "save":
        h = hs.store_for(cfg).get(a.id)
        if not h:
            print("no such hunt")
            return 1
        r = lib.save_from_hunt(h, name=a.name, interval_minutes=a.every, escalate=a.escalate)
        print(f"saved as {r['id']} with {len(r['calls'])} call(s)")
        for w in r["warnings"]:
            print(f"warning: {w}")
        return 0
    if a.action == "delete":
        return 0 if lib.delete(int(a.id)) else 1
    h = hs.run_replay(cfg, int(a.id), actor="cli")
    _print_verdict(h["verdict"])
    return 0


def cmd_demo(a) -> int:
    import os

    from .demo.setup import DEMO_HYPOTHESIS, init_demo
    home = Path(a.dir or Path.home() / ".actaeon-demo").expanduser()
    info = init_demo(home, offline=a.offline, port=a.port)
    print(f"Demo home: {info['home']}  (all data in it is synthetic and labelled SAMPLE)")
    if not a.offline:
        print("Models: the demo uses the model settings from config.example.yaml (Ollama on localhost).")
        print("        Edit the llm section of the demo config.yaml, or rerun with --offline for a scripted run.")
    else:
        print("Models: --offline uses a scripted demo run. It is NOT an AI model.")
    if a.run:
        os.environ["ACTAEON_HOME"] = str(home)
        os.environ.pop("ACTAEON_CONFIG", None)
        os.chdir(home)
        from . import config as _c
        from .connectors import hub as _hub
        _c._CONFIG, _hub._HUB = None, None
        from .providers import get_llm
        get_llm(reload=True)
        cfg = _c.get_config(reload=True)
        from .hunt.service import run_hunt, run_sweep
        h = run_hunt(cfg, DEMO_HYPOTHESIS, origin="demo",
                     on_event=lambda e: print(f"  E{e['n']} {'ok ' if e['ok'] else 'ERR'} {e['tool']}")
                     if e["type"] == "step" else None)
        _print_verdict(h["verdict"])
        s = run_sweep(cfg, full=True, actor="demo")
        print(f"\nIntel sweep: {s['verdict']['summary']}")
        _hub.get_hub().close()
    print(f"\nOpen the UI:  ACTAEON_HOME={home} actaeon serve   ->  http://127.0.0.1:{a.port}")
    return 0


def test_models(cfg) -> list[dict]:
    """Send one tiny prompt to each role's model (with its fallbacks) and report."""
    import time as _t

    from .config import LLM_ROLES
    from .hunt.service import privacy_llm
    from .providers import get_llm
    llm = privacy_llm(cfg, get_llm(reload=True))
    out = []
    for role in LLM_ROLES:
        t0 = _t.monotonic()
        b = llm.for_role(role)
        res = b.chat([{"role": "system", "content": "You are a connectivity check."},
                      {"role": "user", "content": 'Reply with exactly {"ok": true}'}], max_tokens=50)
        out.append({"role": role, "provider": b.provider.name, "model": res.model or b.model, "ok": not res.error,
                    "ms": int((_t.monotonic() - t0) * 1000), "error": (res.error or "")[:400],
                    "reply": (res.text or "")[:80]})
    return out


def cmd_models_test() -> int:
    from .config import get_config
    rc = 0
    for r in test_models(get_config()):
        if r["ok"]:
            print(f"OK   {r['role']:9} {r['provider']}/{r['model']}  {r['ms']} ms  reply: {r['reply']}")
        else:
            rc = 1
            print(f"FAIL {r['role']:9} {r['provider']}/{r['model']}  {r['error']}")
    return rc


def cmd_sigma(a) -> int:
    import json

    from .hunt.sigma_convert import SigmaConvertError, available, convert, convert_for, targets
    if a.action == "backends":
        print(json.dumps(available(), indent=2))
        return 0
    if not a.file:
        print("usage: actaeon sigma convert RULE.yml [--backend ID --pipeline P]")
        return 2
    rule = Path(a.file).read_text()
    if a.backend:
        try:
            for q in convert(rule, backend=a.backend, pipelines=a.pipeline, fmt=a.format):
                print(q)
        except SigmaConvertError as exc:
            print(f"error: {exc}")
            return 1
        return 0
    from .config import get_config
    tg = targets(get_config())
    if not tg:
        print("no connector has a sigma: block; use --backend, or see docs/detection.md")
        return 1
    rows = convert_for(rule, tg)
    for r in rows:
        print(f"== {r['connector']} ({r['backend']})")
        print("\n".join(r.get("queries") or []) or f"error: {r.get('error')}")
    return 1 if any(r.get("error") for r in rows) else 0


def cmd_validate_pack(path: str | None) -> int:
    """Check hunt-pack YAML files (a folder or one file; default: the built-in pack)."""
    from pathlib import Path

    import yaml

    from .hunt.packs import PackError, builtin_dir, load_dir, validate
    target = Path(path) if path else builtin_dir()
    if not target.exists():
        print(f"FAIL {target} does not exist")
        return 1
    try:
        if target.is_file():
            validate(yaml.safe_load(target.read_text(encoding="utf-8")), filename=target.name)
            n = 1
        else:
            n = len(load_dir(target))
    except (PackError, yaml.YAMLError, OSError) as exc:
        print(f"FAIL {exc}")
        return 1
    print(f"OK {n} hunt(s) in {target}")
    return 0


def cli_main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="actaeon", description="Open-source AI threat hunter (MCP connectors).")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="run the web UI and API (default)")
    p_init = sub.add_parser("init", help="create config.yaml and .env in the Actaeon home folder")
    p_init.add_argument("--force", action="store_true")
    p_init.add_argument("--company", metavar="DIR", help="create a private configuration folder for an organisation")
    p_init.add_argument("--name", default="", help="instance name for --company")
    p_init.add_argument("--database", choices=["sqlite", "postgres"], default="sqlite",
                        help="storage: sqlite (default, nothing to install) or postgres (needs actaeon[postgres])")
    p_init.add_argument("--db-url", default="", help="postgres: postgresql://user:password@host:5432/dbname")
    p_doc = sub.add_parser("doctor", help="check the whole setup and say what to fix")
    p_doc.add_argument("--offline", action="store_true", help="skip connector probes")
    p_doc.add_argument("--models", action="store_true", help="also send one test prompt to each model role")
    sub.add_parser("version")
    p_models = sub.add_parser("models", help="show the model for each role; 'models test' checks each one answers")
    p_models.add_argument("action", nargs="?", choices=["show", "test"], default="show")
    sub.add_parser("hash-password", help="print a password hash for auth.password_hash")
    p_con = sub.add_parser("connectors", help="list, test or show tools of MCP connectors")
    p_con.add_argument("action", choices=["list", "test", "check", "tools", "login"], nargs="?", default="list")
    p_con.add_argument("name", nargs="?")
    p_con.add_argument("--manual", action="store_true", help="login: paste the redirect URL instead of a local listener")
    p_sg = sub.add_parser("sigma", help="Sigma conversion: list installed pySigma backends, or convert a rule file")
    p_sg.add_argument("action", choices=["backends", "convert"])
    p_sg.add_argument("file", nargs="?", help="convert: a Sigma rule YAML file")
    p_sg.add_argument("--backend", default="", help="convert with this backend instead of the connectors' sigma: blocks")
    p_sg.add_argument("--pipeline", action="append", default=[])
    p_sg.add_argument("--format", default="default")
    p_aud = sub.add_parser("audit", help="check the audit log's hash chain")
    p_aud.add_argument("action", choices=["verify"], nargs="?", default="verify")
    p_br = sub.add_parser("bridge", help="run a generic bridge as a stdio MCP server")
    br = p_br.add_subparsers(dest="kind", required=True)
    from .bridges import demo as demo_bridge
    from .bridges import local_intel, local_tools, openapi, search_index, sql, taxii
    from .bridges import web as web_bridge
    bridges = {"search-index": search_index, "taxii": taxii, "openapi": openapi, "local-intel": local_intel,
               "local-tools": local_tools, "demo": demo_bridge, "web": web_bridge, "sql": sql}
    for kind, mod in bridges.items():
        mod.add_args(br.add_parser(kind))
    p_in = sub.add_parser("intel", help="add, import, pull and look up intel in the local store")
    isub = p_in.add_subparsers(dest="action", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--source", default="")
    common.add_argument("--confidence", type=int, default=50)
    common.add_argument("--tag", action="append", default=[])
    common.add_argument("--ttl-days", type=int, default=None)
    x = isub.add_parser("add", parents=[common], help="add indicator values")
    x.add_argument("values", nargs="+")
    x.add_argument("--type", default=None)
    x = isub.add_parser("paste", parents=[common], help="extract indicators from text on stdin or a file")
    x.add_argument("file", nargs="?")
    x = isub.add_parser("advisory", parents=[common], help="add an advisory (text/HTML/PDF file, --url, or stdin)")
    x.add_argument("file", nargs="?")
    x.add_argument("--title", default="")
    x.add_argument("--url", default="")
    x = isub.add_parser("import", parents=[common], help="import a file (text/csv/stix/json)")
    x.add_argument("file")
    x.add_argument("--format", default="text")
    x.add_argument("--type", default=None)
    x.add_argument("--value-field", default="")
    x.add_argument("--list-key", default="")
    x.add_argument("--extract", action="store_true")
    x = isub.add_parser("export", help="export indicators as a STIX 2.1 bundle")
    x.add_argument("--tag", action="append", default=[], help="only indicators with this tag")
    x.add_argument("--min-confidence", type=int, default=0)
    x.add_argument("--since", default="", help="only indicators changed since this ISO time")
    x.add_argument("--producer", default="Actaeon", help="name of the producing identity")
    x.add_argument("-o", "--output", default="", help="write to a file instead of stdout")
    x = isub.add_parser("pull", help="pull configured feeds (intel.feeds)")
    x.add_argument("name", nargs="?")
    x = isub.add_parser("actor", help="threat actor profiles: actor list | actor add NAME ... | actor show NAME")
    x.add_argument("op", choices=["list", "add", "show"])
    x.add_argument("name", nargs="?")
    x.add_argument("--alias", action="append", default=[])
    x.add_argument("--technique", action="append", default=[])
    x.add_argument("--tool", action="append", default=[])
    x.add_argument("--description", default="")
    x.add_argument("--indicators", default="", help="file with indicators or report text (defanged values are fine)")
    x = isub.add_parser("web", help="pull web intel sources now (intel.web.sources)")
    x.add_argument("name", nargs="?")
    x.add_argument("--hunt", action="store_true", help="also start advisory hunts for new advisories")
    x = isub.add_parser("lookup")
    x.add_argument("value")
    x = isub.add_parser("list")
    x.add_argument("--type", default=None)
    x.add_argument("--limit", type=int, default=50)
    isub.add_parser("stats")
    p_h = sub.add_parser("hunt", help="run a hunt now and print each step, or show a past hunt")
    p_h.add_argument("hypothesis", nargs="?")
    p_h.add_argument("--max-steps", type=int, default=None)
    p_h.add_argument("--show", metavar="HUNT_ID")
    p_h.add_argument("--list", action="store_true")
    p_h.add_argument("--json", action="store_true")
    p_h.add_argument("--advisory", type=int, metavar="ID", help="hunt the activity in a stored advisory")
    p_h.add_argument("--actor", metavar="NAME", help="campaign: sweep an actor's indicators and hunt its techniques")
    p_lib = sub.add_parser("library", help="saved hunts: list, save a finished hunt, replay, starters; "
                                           "validate hunt-pack files")
    p_lib.add_argument("action", choices=["list", "save", "run", "starters", "delete", "validate"])
    p_lib.add_argument("id", nargs="?")
    p_lib.add_argument("--name", default="")
    p_lib.add_argument("--every", type=int, default=0, help="replay interval in minutes (0 = manual)")
    p_lib.add_argument("--escalate", action="store_true", help="start a full hunt when a replay finds matches")
    sub.add_parser("mcp", help="serve Actaeon itself as an MCP server on stdio")
    p_w = sub.add_parser("worker", help="run queued jobs (needs jobs.mode: queue)")
    p_w.add_argument("--concurrency", type=int, default=2, help="jobs at once (default 2)")
    p_w.add_argument("--scheduler", action="store_true", help="also run the scheduler (one process gets the lock)")
    p_demo = sub.add_parser("demo", help="set up a demo with labelled sample data (and optionally run a hunt)")
    p_demo.add_argument("--dir", default="", help="demo home (default ~/.actaeon-demo)")
    p_demo.add_argument("--offline", action="store_true", help="use a scripted run instead of a model (not AI)")
    p_demo.add_argument("--run", action="store_true", help="run the demo hunt and a sweep now")
    p_demo.add_argument("--port", type=int, default=8611)
    p_dec = sub.add_parser("decode", help="decode an obfuscated command line (argument or stdin); runs nothing")
    p_dec.add_argument("text", nargs="?")
    p_ap = sub.add_parser("autopilot", help="propose hypotheses from intel, coverage and follow-ups, and hunt them")
    p_ap.add_argument("--dry-run", action="store_true", help="only propose; start nothing")
    p_b = sub.add_parser("bench", help="run the scored hunting benchmark (demo cases or your own YAML)")
    p_b.add_argument("--cases", default="", help="YAML file of cases (default: built-in demo cases)")
    p_b.add_argument("--only", action="append", default=[], help="case id to run (repeatable)")
    p_b.add_argument("--max-steps", type=int, default=None)
    p_b.add_argument("--workers", type=int, default=1, help="cases run in parallel (default 1)")
    p_b.add_argument("--model", default="", help="provider/model for every role, e.g. ollama/qwen3:32b "
                                                 "(no fallbacks, so the score is that model's)")
    p_b.add_argument("--role-model", action="append", default=[], metavar="ROLE=PROVIDER/MODEL",
                     help="override one role, e.g. analyst=anthropic/<model> (repeatable)")
    p_b.add_argument("--markdown", action="store_true", help="also print a results-table row for docs/benchmarks.md")
    p_out = sub.add_parser("outputs", help="list outputs, or send a sample result to one: outputs test NAME")
    p_out.add_argument("action", nargs="?", choices=["list", "test"], default="list")
    p_out.add_argument("name", nargs="?")
    p_u = sub.add_parser("users", help="named accounts for basic/local login: users list | add NAME | remove NAME")
    p_u.add_argument("op", choices=["list", "add", "remove"])
    p_u.add_argument("name", nargs="?")
    p_u.add_argument("--role", default="operator", choices=["viewer", "operator", "admin"])
    p_u.add_argument("--full-name", default="")
    p_u.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    p_r = sub.add_parser("report", help="write a report: report hunt ID | lead ID | summary [--days N]")
    p_r.add_argument("kind", choices=["hunt", "lead", "summary"])
    p_r.add_argument("id", nargs="?")
    p_r.add_argument("--format", default="pdf", choices=["pdf", "docx", "md"])
    p_r.add_argument("--days", type=int, default=7)
    p_r.add_argument("-o", "--output", default="")
    p_sw = sub.add_parser("sweep", help="search logs for new or changed intel indicators (no model)")
    p_sw.add_argument("--full", action="store_true", help="sweep every indicator, not only changed ones")
    p_note = sub.add_parser("note", help="add an analyst note to hunt memory")
    p_note.add_argument("text", nargs="?")
    p_note.add_argument("--tag", action="append", default=[])
    p_note.add_argument("--list", action="store_true")
    p_note.add_argument("--expires-days", type=int, default=0, help="stop using the note after N days (0 = never)")
    a = ap.parse_args(argv)

    if a.cmd == "version":
        print(__version__)
        return
    if a.cmd == "init":
        if a.company:
            from .company import init_company
            files = init_company(a.company, name=a.name)
            print(f"created {a.company}:\n  " + "\n  ".join(files))
            print("next: fill in every <...> in config.yaml, then: ACTAEON_HOME=" + a.company + " actaeon doctor")
            return
        sys.exit(cmd_init(a.force, database=a.database, db_url=a.db_url))
    if a.cmd == "doctor":
        from .doctor import run as run_doctor
        rows = run_doctor(offline=a.offline, models=a.models)
        for r in rows:
            print(f"{r['level']:4} {r['area']:10} {r['message']}" + (f"\n{'':16}-> {r['hint']}" if r["hint"] else ""))
        fails = sum(r["level"] == "FAIL" for r in rows)
        warns = sum(r["level"] == "WARN" for r in rows)
        print(f"\n{fails} problem(s), {warns} warning(s)")
        sys.exit(1 if fails else 0)
    if a.cmd == "models":
        sys.exit(cmd_models_test() if a.action == "test" else cmd_models())
    if a.cmd == "bridge":
        bridges[a.kind].run(a)
        return
    if a.cmd == "hunt":
        sys.exit(cmd_hunt(a))
    if a.cmd == "intel":
        sys.exit(cmd_intel(a))
    if a.cmd == "demo":
        sys.exit(cmd_demo(a))
    if a.cmd == "autopilot":
        import json as _json

        from .config import get_config
        from .hunt.service import run_autopilot
        from .jobs import JobManager
        cfg = get_config()
        jobs = JobManager(cfg.data_dir / "actaeon.sqlite")
        r = run_autopilot(cfg, jobs, dry_run=a.dry_run)
        for h in r["hypotheses"]:
            print(f"- [{h['source']}] {h['hypothesis']}\n    why: {h['why']}  ATT&CK {', '.join(h['attack']) or '-'}")
        for h in r["rejected"]:
            print(f"  skipped: {h['hypothesis'][:100]} ({h['rejected']})")
        if r["started"]:
            print(f"started {len(r['started'])} hunt(s); waiting for them to finish...")
            jobs.pool.shutdown(wait=True)
            from .hunt.service import store_for
            for s in r["started"]:
                h = store_for(cfg).get(s["hunt_id"], with_steps=False)
                print(f"  {h['id']} {h['status']} {h['outcome']}: {h['hypothesis'][:90]}")
        print(_json.dumps({"room_today": r["room_today"], "dry_run": r["dry_run"]}))
        return
    if a.cmd == "bench":
        from .bench import load_cases
        from .bench import run as run_bench
        from .config import get_config
        cases = [c for c in load_cases(a.cases or None) if not a.only or c["id"] in a.only]

        def show(r):
            mark = "PASS" if r["correct"] else "FAIL"
            print(f"{mark} {r['id']:18} got {r['outcome']!s:22} want {'/'.join(r['expect']):30} "
                  f"conf {r['confidence']} calls {r['calls']} blocked {r['blocked']} {r['seconds']}s "
                  f"tok {r.get('tokens_in', 0)}/{r.get('tokens_out', 0)}", flush=True)
        try:
            out = run_bench(get_config(), cases, max_steps=a.max_steps, on_case=show, workers=max(1, a.workers),
                            model=a.model, role_models=a.role_model)
        except ValueError as exc:
            print(f"error: {exc}")
            sys.exit(2)
        print(out["score"])
        if a.markdown:
            from .bench import markdown_row
            print(markdown_row(out))
        print(f"saved {out['file']}")
        return
    if a.cmd == "outputs":
        from .config import get_config
        from .outputs import dispatch
        cfg = get_config()
        outs = (cfg.raw or {}).get("outputs") or []
        if a.action == "list" or not a.name:
            for o in outs:
                print(f"{o['name']:20} {o['type']:9} when {','.join(o.get('when') or ['threat'])}")
            if not outs:
                print("no outputs configured (outputs: in config.yaml)")
            return
        sample = {"id": "sample000000", "hypothesis": "SAMPLE: test message from actaeon outputs test",
                  "origin": "test", "status": "done", "outcome": "threat",
                  "verdict": {"outcome": "threat", "confidence": 50, "needs_review": True,
                              "summary": "This is a test of the output. It is not a real finding.",
                              "findings": [{"claim": "SAMPLE finding", "evidence": ["E1"]}], "attack": []},
                  "steps": []}
        for r in dispatch(cfg, sample, only=a.name):
            print(("OK   " if r["ok"] else "FAIL ") + f"{r['name']}: {r['detail']}")
        return
    if a.cmd == "report":
        from .config import get_config
        from .hunt import service as hs
        from .reporting import hunt_doc, lead_doc, render, summary_doc
        cfg = get_config()
        if a.kind == "summary":
            doc, name = summary_doc(cfg, a.days), f"actaeon-summary-{a.days}d"
        elif a.kind == "hunt":
            h = hs.store_for(cfg).get(str(a.id))
            if not h:
                sys.exit("no such hunt")
            doc, name = hunt_doc(h, lead=hs.leads_for(cfg).by_hunt(h["id"])), f"hunt-{h['id']}"
        else:
            c = hs.leads_for(cfg).get(int(a.id or 0))
            if not c:
                sys.exit("no such lead")
            doc, name = lead_doc(c, hs.store_for(cfg).get(c["hunt_id"])), f"lead-{c['id']}"
        out = Path(a.output or f"{name}.{a.format}")
        out.write_bytes(render(doc, a.format))
        print(f"wrote {out}")
        return
    if a.cmd == "users":
        from .config import get_config, set_user
        cfg = get_config()
        if a.op == "list" or not a.name:
            for n, u in sorted(cfg.auth.users.items()):
                print(f"{n:24} {u.get('role', '?'):9} {u.get('name', '')}")
            if cfg.auth.mode in ("basic", "local"):
                print(f"{cfg.auth.username:24} {cfg.auth.default_role:9} (auth.username account)")
            return
        if a.op == "remove":
            set_user(a.name, remove=True)
            print(f"removed {a.name}")
            return
        from .auth import hash_password
        pw = sys.stdin.readline().rstrip("\n") if a.password_stdin else getpass.getpass(f"Password for {a.name}: ")
        if len(pw) < 10:
            print("use at least 10 characters")
            sys.exit(2)
        set_user(a.name, password_hash=hash_password(pw), role=a.role, name=a.full_name)
        print(f"saved {a.name} ({a.role}); restart the server to apply")
        return
    if a.cmd == "mcp":
        from .mcp_server import run as run_mcp
        run_mcp()
        return
    if a.cmd == "decode":
        import json as _json

        from .decode import decode
        print(_json.dumps(decode(a.text if a.text else sys.stdin.read()), indent=2))
        return
    if a.cmd == "library" and a.action == "validate":
        sys.exit(cmd_validate_pack(a.id))
    if a.cmd in ("library", "sweep", "note"):
        sys.exit(cmd_phase5(a))
    if a.cmd == "connectors":
        if a.action == "login":
            sys.exit(cmd_login(a.name, a.manual))
        sys.exit(cmd_connectors(a.action, a.name))
    if a.cmd == "worker":
        from .worker import main as worker_main
        try:
            worker_main(concurrency=a.concurrency, scheduler=a.scheduler)
        except ValueError as exc:
            print(f"error: {exc}")
            sys.exit(2)
        return
    if a.cmd == "sigma":
        sys.exit(cmd_sigma(a))
    if a.cmd == "audit":
        import json

        from .config import get_config
        from .connectors.audit import AuditLog
        res = AuditLog(get_config().data_dir / "audit.sqlite").verify()
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["ok"] else 1)
    if a.cmd == "hash-password":
        from .auth import hash_password
        print(hash_password(getpass.getpass("Password: ")))
        return
    from .server import main
    main()
