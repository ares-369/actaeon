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


def cli_main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="actaeon", description="Open-source AI threat hunter (MCP connectors).")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="run the web UI and API (default)")
    p_init = sub.add_parser("init", help="create config.yaml and .env in the Actaeon home folder")
    p_init.add_argument("--force", action="store_true")
    sub.add_parser("version")
    sub.add_parser("models", help="show the model used for each role")
    sub.add_parser("hash-password", help="print a password hash for auth.password_hash")
    a = ap.parse_args(argv)

    if a.cmd == "version":
        print(__version__)
        return
    if a.cmd == "init":
        sys.exit(cmd_init(a.force))
    if a.cmd == "models":
        sys.exit(cmd_models())
    if a.cmd == "hash-password":
        from .auth import hash_password
        print(hash_password(getpass.getpass("Password: ")))
        return
    from .server import main
    main()
