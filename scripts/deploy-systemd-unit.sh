#!/bin/bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

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

printf 'Fedora System Monitor systemd units deployed:'
printf ' %s' "${units[@]}"
printf '\n'
