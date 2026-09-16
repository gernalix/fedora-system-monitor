#!/bin/bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [[ ! -d "$ROOT/.git" ]]; then
    printf 'Systemd unit deploy requires a Git checkout: %s\n' "$ROOT" >&2
    exit 1
fi
if [[ -n $(git -C "$ROOT" status --porcelain) ]]; then
    printf 'Refusing to deploy systemd units from a dirty checkout.\n' >&2
    git -C "$ROOT" status --short >&2
    exit 1
fi
REVISION=$(git -C "$ROOT" rev-parse HEAD)

if [[ $# -lt 1 ]]; then
    printf 'Usage: %s <fedora-system-monitor-*.service|timer|path> [...]\n' "$0" >&2
    exit 2
fi

units=()
for requested in "$@"; do
    unit=$(basename "$requested")
    case "$unit" in
        fedora-system-monitor-*.service|fedora-system-monitor-*.timer|fedora-system-monitor-*.path) ;;
        *)
            printf 'Refusing non-Fedora-System-Monitor unit: %s\n' "$requested" >&2
            exit 2
            ;;
    esac
    source="$ROOT/systemd/$unit"
    if [[ ! -f "$source" ]]; then
        printf 'Unit not found in checkout: %s\n' "$source" >&2
        exit 2
    fi
    systemd-analyze verify "$source"
    units+=("$unit")
done

for unit in "${units[@]}"; do
    install -m 0644 "$ROOT/systemd/$unit" "/etc/systemd/system/$unit"
done

if command -v restorecon >/dev/null; then
    for unit in "${units[@]}"; do
        restorecon -F "/etc/systemd/system/$unit" || true
    done
fi
systemctl daemon-reload

for unit in "${units[@]}"; do
    systemd-analyze verify "/etc/systemd/system/$unit"
done

printf 'Fedora System Monitor systemd units deployed from %s:' "$REVISION"
printf ' %s' "${units[@]}"
printf '\n'
