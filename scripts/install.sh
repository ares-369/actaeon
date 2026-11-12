#!/usr/bin/env bash
set -euo pipefail

# Bare-Linux installer for Actaeon (/opt/actaeon + systemd).
# Usage: sudo bash scripts/install.sh [EXTRAS]   (e.g. "all", "gemini,excel", or "")

DIR="${ACTAEON_DIR:-/opt/actaeon}"
EXTRAS="${1:-}"
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
  ACTAEON_HOME="$DIR" "$DIR/.venv/bin/actaeon" init
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
