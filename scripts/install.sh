#!/bin/bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LIB_PARENT=/usr/local/libexec
LIB=$LIB_PARENT/fedora-system-monitor
ETC=/etc/fedora-system-monitor
STATE=/var/lib/fedora-system-monitor
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

install -d -m 0755 "$LIB_PARENT"
install -d -m 0750 -o root -g daniele "$ETC" "$STATE" "$STATE/backups" "$STATE/install-backups"

if [[ -f "$STATE/monitor.sqlite3" ]]; then
    DB_SOURCE="$STATE/monitor.sqlite3" DB_TARGET="$STATE/install-backups/monitor-$STAMP.sqlite3" /usr/bin/python3 - <<'PY'
import os
import sqlite3

source = sqlite3.connect(os.environ["DB_SOURCE"])
target = sqlite3.connect(os.environ["DB_TARGET"])
with target:
    source.backup(target)
source.close()
target.close()
PY
    chmod 0640 "$STATE/install-backups/monitor-$STAMP.sqlite3"
    chown root:daniele "$STATE/install-backups/monitor-$STAMP.sqlite3"
fi

if [[ -f "$ETC/config.toml" ]]; then
    install -m 0640 -o root -g daniele "$ETC/config.toml" "$STATE/install-backups/config-$STAMP.toml"
fi

if find "$ROOT/src/fedora_system_monitor" -type l -print -quit | grep -q .; then
    printf 'Refusing to install symlinks from the source package.\n' >&2
    exit 1
fi

STAGE=$(mktemp -d "$LIB_PARENT/.fedora-system-monitor.XXXXXX")
cleanup() { [[ -z ${STAGE:-} ]] || rm -rf "$STAGE"; }
trap cleanup EXIT
install -d -m 0755 "$STAGE/fedora_system_monitor"
while IFS= read -r -d '' source; do
    relative=${source#"$ROOT/src/fedora_system_monitor/"}
    install -d -m 0755 "$STAGE/fedora_system_monitor/$(dirname "$relative")"
    install -m 0644 -o root -g root "$source" "$STAGE/fedora_system_monitor/$relative"
done < <(find "$ROOT/src/fedora_system_monitor" -type f -name '*.py' -print0)
/usr/bin/python3 -m compileall -q "$STAGE/fedora_system_monitor"
chown -R root:root "$STAGE"
find "$STAGE" -type d -exec chmod 0755 '{}' +
find "$STAGE" -type f -exec chmod 0644 '{}' +
if find "$STAGE" \( ! -user root -o -perm /022 \) -print -quit | grep -q .; then
    printf 'Unsafe ownership or mode in staged runtime.\n' >&2
    exit 1
fi
OLD="$LIB_PARENT/.fedora-system-monitor.old-$STAMP"
if [[ -e "$LIB" ]]; then
    mv "$LIB" "$OLD"
fi
mv "$STAGE" "$LIB"
STAGE=
rm -rf "$OLD"
install -m 0755 "$ROOT/packaging/fedora-system-monitor" /usr/local/bin/fedora-system-monitor

if [[ ! -f "$ETC/config.toml" ]]; then
    install -m 0640 -o root -g daniele "$ROOT/config/fedora-system-monitor.toml" "$ETC/config.toml"
fi
install -m 0644 "$ROOT/config/fedora-system-monitor.toml" "$ETC/config.toml.distribution"
if [[ ! -f "$ETC/uptime-kuma.toml" ]]; then
    install -m 0600 -o root -g root "$ROOT/config/uptime-kuma.toml.example" "$ETC/uptime-kuma.toml"
fi

install -m 0644 "$ROOT/systemd/"*.service "$ROOT/systemd/"*.timer "$ROOT/systemd/"*.path /etc/systemd/system/
install -d -m 0755 /etc/systemd/system/fedora-system-monitor-collect@daily.service.d
install -m 0644 "$ROOT/systemd/fedora-system-monitor-collect@daily.service.d/10-nvme-capability.conf" /etc/systemd/system/fedora-system-monitor-collect@daily.service.d/
install -m 0644 "$ROOT/udev/90-fedora-system-monitor.rules" /etc/udev/rules.d/90-fedora-system-monitor.rules
install -d -m 0755 /etc/NetworkManager/dispatcher.d /usr/lib/systemd/system-sleep
install -m 0755 "$ROOT/hooks/NetworkManager/90-fedora-system-monitor" /etc/NetworkManager/dispatcher.d/90-fedora-system-monitor
install -m 0755 "$ROOT/hooks/system-sleep/fedora-system-monitor" /usr/lib/systemd/system-sleep/fedora-system-monitor

command -v restorecon >/dev/null && restorecon -RF /usr/local/libexec/fedora-system-monitor /usr/local/bin/fedora-system-monitor /etc/systemd/system /etc/udev/rules.d /etc/NetworkManager/dispatcher.d /usr/lib/systemd/system-sleep /var/lib/fedora-system-monitor || true
systemctl daemon-reload
udevadm control --reload-rules

systemd-analyze verify /etc/systemd/system/fedora-system-monitor-*.service /etc/systemd/system/fedora-system-monitor-*.timer /etc/systemd/system/fedora-system-monitor-*.path

/usr/local/bin/fedora-system-monitor config-check
/usr/local/bin/fedora-system-monitor db-check
chown root:daniele "$STATE"/monitor.sqlite3*
chmod 0640 "$STATE"/monitor.sqlite3*
/usr/local/bin/fedora-system-monitor backfill --since-hours 168

systemctl enable fedora-system-monitor-events.service
systemctl restart fedora-system-monitor-events.service
systemctl enable --now fedora-system-monitor-fast.timer fedora-system-monitor-hourly.timer fedora-system-monitor-daily.timer fedora-system-monitor-weekly.timer
systemctl enable --now fedora-system-monitor-software.path
systemctl enable --now fedora-system-monitor-lifecycle.service

/usr/local/bin/fedora-system-monitor collect minute

mapfile -t old_db_backups < <(find "$STATE/install-backups" -maxdepth 1 -type f -name 'monitor-*.sqlite3' -printf '%T@ %p\n' | sort -rn | cut -d' ' -f2-)
for old in "${old_db_backups[@]:10}"; do rm -f -- "$old"; done
mapfile -t old_config_backups < <(find "$STATE/install-backups" -maxdepth 1 -type f -name 'config-*.toml' -printf '%T@ %p\n' | sort -rn | cut -d' ' -f2-)
for old in "${old_config_backups[@]:10}"; do rm -f -- "$old"; done

printf 'Fedora System Monitor installed and active.\n'
