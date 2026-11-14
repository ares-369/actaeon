#!/usr/bin/env bash
set -euo pipefail

# Bare-Linux installer for Actaeon (/opt/actaeon + systemd).
# Usage: sudo bash scripts/install.sh [EXTRAS]   (e.g. "all", "gemini,reports", or "")
# Storage: SQLite by default (nothing else to install). For PostgreSQL:
#   sudo ACTAEON_DATABASE=postgres ACTAEON_DB_URL=postgresql://user:pass@host/db bash scripts/install.sh
# Run interactively without ACTAEON_DATABASE and it asks.

DIR="${ACTAEON_DIR:-/opt/actaeon}"
EXTRAS="${1:-}"
DATABASE="${ACTAEON_DATABASE:-}"
if [ -z "$DATABASE" ] && [ -t 0 ] && [ ! -f "$DIR/config.yaml" ]; then
  echo "Storage:"
  echo "  1) SQLite      - default, nothing else to install, one machine"
  echo "  2) PostgreSQL  - an existing PostgreSQL server; needed to run on several machines"
  read -r -p "Choose [1]: " choice
  [ "$choice" = "2" ] && DATABASE=postgres
fi
DATABASE="${DATABASE:-sqlite}"
if [ "$DATABASE" = "postgres" ]; then
  EXTRAS="${EXTRAS:+$EXTRAS,}postgres"
fi
SRC="$(cd "$(dirname "$0")/.." && pwd)"

id -u actaeon >/dev/null 2>&1 || useradd --system --home-dir "$DIR" --shell /usr/sbin/nologin actaeon
mkdir -p "$DIR/data"
python3 -m venv "$DIR/.venv"
"$DIR/.venv/bin/pip" install --upgrade pip
if [ -n "$EXTRAS" ]; then
  "$DIR/.venv/bin/pip" install "${SRC}[${EXTRAS}]"
else
  "$DIR/.venv/bin/pip" install "$SRC"
fi

if [ ! -f "$DIR/config.yaml" ]; then
  ACTAEON_HOME="$DIR" "$DIR/.venv/bin/actaeon" init --database "$DATABASE" || \
    echo "PostgreSQL is not reachable yet: fix ACTAEON_DB_URL in $DIR/.env, then run actaeon doctor"
fi

chown -R actaeon:actaeon "$DIR"
chmod 600 "$DIR/.env" 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
  cp "$SRC/deploy/actaeon.service" /etc/systemd/system/actaeon.service
  systemctl daemon-reload
  echo "Installed systemd unit. Edit $DIR/config.yaml and $DIR/.env, then run:"
  echo "  sudo systemctl enable --now actaeon"
else
  echo "Installed into $DIR. Run: ACTAEON_HOME=$DIR $DIR/.venv/bin/actaeon serve"
fi
