#!/usr/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [[ -n $(git -C "$ROOT" status --porcelain) ]]; then
    printf 'Refusing deployment from dirty task checkout: %s\n' "$ROOT" >&2
    exit 1
fi
TARGET="$HOME/.local/libexec/fedora-system-monitor-kuma-pn/fedora_system_monitor"
UNITS="$HOME/.config/systemd/user"
STATE="$HOME/.local/state/fedora-system-monitor"
install -d -m 0755 "$TARGET/capsules" "$UNITS"
install -d -m 0700 "$STATE"
install -m 0644 "$ROOT/src/fedora_system_monitor/__init__.py" "$TARGET/__init__.py"
install -m 0644 "$ROOT/src/fedora_system_monitor/capsules/__init__.py" "$TARGET/capsules/__init__.py"
install -m 0644 "$ROOT/src/fedora_system_monitor/capsules/kuma_pn_monitor.py" "$TARGET/capsules/kuma_pn_monitor.py"
for name in fedora-system-monitor-kuma-pn.service fedora-system-monitor-kuma-pn.timer; do
    systemd-analyze verify "$ROOT/systemd/user/$name"
    install -m 0644 "$ROOT/systemd/user/$name" "$UNITS/$name"
done
systemctl --user daemon-reload
systemctl --user enable --now fedora-system-monitor-kuma-pn.timer
systemctl --user start fedora-system-monitor-kuma-pn.service
printf 'Kuma incident monitor installed from commit %s\n' "$(git -C "$ROOT" rev-parse HEAD)"
