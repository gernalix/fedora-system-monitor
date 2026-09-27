#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'Kuma C2 bridge deployment requires a Git checkout: %s\n' "$ROOT" >&2
    exit 1
fi
if [[ -n $(git -C "$ROOT" status --porcelain) ]]; then
    printf 'Refusing to deploy bridge units from a dirty checkout.\n' >&2
    git -C "$ROOT" status --short >&2
    exit 1
fi

UNIT_DIR="$HOME/.config/systemd/user"
install -d -m 0755 "$UNIT_DIR"
install -d -m 0700 "$HOME/.local/state/fedora-system-monitor-kuma-c2-bridge"
for unit in fedora-system-monitor-kuma-c2-bridge.service fedora-system-monitor-kuma-c2-bridge.timer; do
    systemd-analyze verify "$ROOT/systemd/user/$unit"
    install -m 0644 "$ROOT/systemd/user/$unit" "$UNIT_DIR/$unit"
done
systemctl --user daemon-reload
systemctl --user enable --now fedora-system-monitor-kuma-c2-bridge.timer
printf 'Enabled Kuma C2 bridge timer from %s\n' "$(git -C "$ROOT" rev-parse --short HEAD)"
