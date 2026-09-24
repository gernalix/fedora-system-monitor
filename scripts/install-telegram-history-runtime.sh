#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEST="$HOME/.local/libexec/fedora-telegram-history"
VENV="$DEST/venv"
mkdir -p "$DEST"
chmod 700 "$DEST"
install -m 0644 "$ROOT/scripts/telegram_history_collector.py" "$DEST/telegram_history_collector.py"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --disable-pip-version-check 'Telethon>=1.36,<2'
mkdir -p "$HOME/.config/fedora-telegram-history" "$HOME/.config/systemd/user" "$HOME/.local/share/fedora-telegram-history" "$HOME/.cache/fedora-telegram-history"
chmod 700 "$HOME/.config/fedora-telegram-history" "$HOME/.local/share/fedora-telegram-history" "$HOME/.cache/fedora-telegram-history"
if [[ -d "$HOME/projects/telegram-notification-history" ]]; then
    chmod 700 "$HOME/projects/telegram-notification-history"
fi
if [[ ! -e "$HOME/.config/fedora-telegram-history/collector.env" ]]; then
    install -m 0600 "$ROOT/config/telegram-notification-history.env.example" "$HOME/.config/fedora-telegram-history/collector.env"
fi
install -m 0600 "$ROOT/systemd/telegram-notification-history.service" "$HOME/.config/systemd/user/telegram-notification-history.service"
install -m 0644 "$ROOT/systemd/telegram-notification-history.timer" "$HOME/.config/systemd/user/telegram-notification-history.timer"
systemctl --user daemon-reload
systemctl --user disable --now telegram-notification-history.timer >/dev/null 2>&1 || true
printf 'Installed collector runtime and disabled user timer. Configure the local env and run the explicit login command before enabling the timer.\n'
