#!/bin/bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

PURGE=false
if [[ ${1:-} == "--purge-data" ]]; then
    PURGE=true
fi

systemctl disable --now fedora-system-monitor-fast.timer fedora-system-monitor-hourly.timer fedora-system-monitor-daily.timer fedora-system-monitor-weekly.timer fedora-system-monitor-context.timer fedora-system-monitor-software.path fedora-system-monitor-events.service 2>/dev/null || true
systemctl disable fedora-system-monitor-lifecycle.service 2>/dev/null || true
systemctl stop fedora-system-monitor-lifecycle.service 'fedora-system-monitor-collect@*.service' 'fedora-system-monitor-device-*@*.service' 2>/dev/null || true
rm -f /etc/systemd/system/fedora-system-monitor-*.service /etc/systemd/system/fedora-system-monitor-*.timer /etc/systemd/system/fedora-system-monitor-*.path
rm -rf /etc/systemd/system/fedora-system-monitor-collect@daily.service.d
rm -f /etc/udev/rules.d/90-fedora-system-monitor.rules /etc/NetworkManager/dispatcher.d/90-fedora-system-monitor /usr/lib/systemd/system-sleep/fedora-system-monitor
rm -rf /usr/local/libexec/fedora-system-monitor
rm -f /usr/local/bin/fedora-system-monitor
systemctl daemon-reload
udevadm control --reload-rules
rm -rf /run/fedora-system-monitor

if $PURGE; then
    rm -rf /var/lib/fedora-system-monitor /etc/fedora-system-monitor
else
    printf 'Data and configuration preserved under /var/lib/fedora-system-monitor and /etc/fedora-system-monitor.\n'
fi
