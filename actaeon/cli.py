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


def cmd_init(force: bool = False) -> int:
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
    return 0


def cmd_models() -> int:
    from .config import LLM_ROLES, get_config
    cfg = get_config()
    for role in LLM_ROLES:
        rc = cfg.role_cfg(role)
        print(f"{role:9} {rc.get('provider', 'ollama'):18} {rc.get('model') or '(provider default)'}")
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
        if action == "test":
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
        text = Path(a.file).read_text() if a.file else sys.stdin.read()
        out = store.add_advisory(a.title, text, source=a.source or "advisory", url=a.url, **kw)
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


def cmd_hunt(a) -> int:
    import json as _json

    from .config import get_config
    from .hunt.service import make_engine, store_for
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
    if not a.hypothesis:
        print("give a hypothesis, --show ID or --list")
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
    eng = make_engine(cfg, on_event=ev, max_steps=a.max_steps)
    h = eng.run(a.hypothesis)
    _print_verdict(h["verdict"])
    print(f"\nhunt id {h['id']} (actaeon hunt --show {h['id']})")
    return 0


def cli_main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="actaeon", description="Open-source AI threat hunter (MCP connectors).")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="run the web UI and API (default)")
    p_init = sub.add_parser("init", help="create config.yaml and .env in the Actaeon home folder")
    p_init.add_argument("--force", action="store_true")
    sub.add_parser("version")
    sub.add_parser("models", help="show the model used for each role")
    sub.add_parser("hash-password", help="print a password hash for auth.password_hash")
    p_con = sub.add_parser("connectors", help="list, test or show tools of MCP connectors")
    p_con.add_argument("action", choices=["list", "test", "tools"], nargs="?", default="list")
    p_con.add_argument("name", nargs="?")
    p_br = sub.add_parser("bridge", help="run a generic bridge as a stdio MCP server")
    br = p_br.add_subparsers(dest="kind", required=True)
    from .bridges import local_intel, openapi, search_index, taxii
    bridges = {"search-index": search_index, "taxii": taxii, "openapi": openapi, "local-intel": local_intel}
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
    x = isub.add_parser("advisory", parents=[common], help="add an advisory (text file or stdin)")
    x.add_argument("file", nargs="?")
    x.add_argument("--title", required=True)
    x.add_argument("--url", default="")
    x = isub.add_parser("import", parents=[common], help="import a file (text/csv/stix/json)")
    x.add_argument("file")
    x.add_argument("--format", default="text")
    x.add_argument("--type", default=None)
    x.add_argument("--value-field", default="")
    x.add_argument("--list-key", default="")
    x.add_argument("--extract", action="store_true")
    x = isub.add_parser("pull", help="pull configured feeds (intel.feeds)")
    x.add_argument("name", nargs="?")
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
    a = ap.parse_args(argv)

    if a.cmd == "version":
        print(__version__)
        return
    if a.cmd == "init":
        sys.exit(cmd_init(a.force))
    if a.cmd == "models":
        sys.exit(cmd_models())
    if a.cmd == "bridge":
        bridges[a.kind].run(a)
        return
    if a.cmd == "hunt":
        sys.exit(cmd_hunt(a))
    if a.cmd == "intel":
        sys.exit(cmd_intel(a))
    if a.cmd == "connectors":
        sys.exit(cmd_connectors(a.action, a.name))
    if a.cmd == "hash-password":
        from .auth import hash_password
        print(hash_password(getpass.getpass("Password: ")))
        return
    from .server import main
    main()
