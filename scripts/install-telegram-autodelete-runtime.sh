#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEST="$HOME/.local/libexec/fedora-telegram-history"
VENV="$DEST/venv"
CFG_DIR="$HOME/.config/fedora-telegram-autodelete"
DATA_DIR="$HOME/.local/share/fedora-telegram-autodelete"

mkdir -p "$DEST" "$CFG_DIR" "$DATA_DIR" "$HOME/.config/systemd/user" "$HOME/.cache/fedora-telegram-history"
chmod 700 "$DEST" "$CFG_DIR" "$DATA_DIR" "$HOME/.cache/fedora-telegram-history"

if [[ ! -x "$VENV/bin/python" ]]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --disable-pip-version-check 'Telethon>=1.36,<2'

install -m 0644 "$ROOT/scripts/telegram_autodelete_archiver.py" "$DEST/telegram_autodelete_archiver.py"
if [[ ! -e "$CFG_DIR/collector.env" ]]; then
  install -m 0600 "$ROOT/config/telegram-autodelete-archive.env.example" "$CFG_DIR/collector.env"
fi
install -m 0600 "$ROOT/systemd/telegram-autodelete-archive.service" "$HOME/.config/systemd/user/telegram-autodelete-archive.service"
install -m 0644 "$ROOT/systemd/telegram-autodelete-archive.timer" "$HOME/.config/systemd/user/telegram-autodelete-archive.timer"

systemctl --user daemon-reload
printf 'Installed Telegram auto-delete archiver. Run discover/sync once before enabling the timer.\n'
