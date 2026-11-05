"""Reconcile read-only incidents only against the same filesystem identity."""
from __future__ import annotations

import json
import re
from pathlib import Path

from fedora_system_monitor.capsules.alerting import AlertSignal
from fedora_system_monitor.capsules.command import run_command

_UUID = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
_LIFECYCLE = re.compile(r"EXT4-fs \(([^)]+)\): (unmounting|mounted) filesystem (" + _UUID + r")(.*)")


def recovered_uuid(details, entries, boot):
    """Bind the incident to its immediate unmount, then require a later rw mount.

    A reused sdX name, a missing device or a quiet journal cannot establish
    recovery. Legacy incidents contain no UUID; the kernel's unmount record
    within five seconds of the original remount supplies that identity.
    """
    identity = details.get("journal_identity") or {}
    incident_boot = identity.get("boot_id") or details.get("boot_id")
    cursor = identity.get("cursor") or details.get("journal_cursor")
    try:
        incident_mono = int(identity.get("monotonic") or details.get("monotonic_usec"))
    except (TypeError, ValueError):
        return None
    if incident_boot != boot or not cursor:
        return None
    device = details.get("kernel_device")
    uuid = None
    recovered = False
    for entry in sorted(entries, key=lambda item: int(item.get("__MONOTONIC_TIMESTAMP", 0))):
        if entry.get("_BOOT_ID") != boot:
            continue
        mono = int(entry.get("__MONOTONIC_TIMESTAMP", 0))
        if mono <= incident_mono:
            continue
        match = _LIFECYCLE.fullmatch(str(entry.get("MESSAGE", "")))
        if not match:
            continue
        node, action, observed_uuid, suffix = match.groups()
        if uuid is None:
            if node == device and action == "unmounting" and mono - incident_mono <= 5_000_000:
                uuid = observed_uuid.lower()
        elif observed_uuid.lower() == uuid:
            recovered = action == "mounted" and re.search(r"\br/w\b", suffix) is not None
    return uuid if recovered else None


def readonly_recoveries(db):
    rows = db.query("SELECT alert_key,category,name,severity,device_id,details_json FROM alerts "
                    "WHERE status='active' AND name IN ('filesystem_read_only','filesystem_remounted_read_only')")
    if not rows:
        return []
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    except OSError:
        return []
    mounts = run_command(["findmnt", "--json", "--list", "--output", "UUID,OPTIONS"], timeout=4, max_output=128_000)
    if not mounts.ok:
        return []
    try:
        mounted = json.loads(mounts.stdout)["filesystems"]
        writable = {str(item.get("uuid") or "").lower() for item in mounted
                    if "rw" in str(item.get("options") or "").split(",")
                    and "ro" not in str(item.get("options") or "").split(",")}
    except (ValueError, KeyError, TypeError):
        return []
    recoveries = []
    for row in rows:
        try:
            details = json.loads(row.get("details_json") or "{}")
            identity = details.get("journal_identity") or {}
            cursor = identity.get("cursor") or details.get("journal_cursor")
            if not cursor or (identity.get("boot_id") or details.get("boot_id")) != boot:
                continue
            journal = run_command(["journalctl", "--no-pager", "-q", "-o", "json", "_TRANSPORT=kernel",
                                   "_BOOT_ID=" + boot, "--after-cursor=" + cursor,
                                   "--grep=EXT4-fs.*(unmounting|mounted) filesystem"], timeout=5, max_output=1_000_000)
            if not journal.ok or len(journal.stdout.encode()) >= 1_000_000:
                continue
            uuid = recovered_uuid(details, [json.loads(line) for line in journal.stdout.splitlines()], boot)
        except (ValueError, TypeError, KeyError):
            continue
        if uuid and uuid in writable:
            recoveries.append(AlertSignal(
                key=row["alert_key"], category=row["category"], name=row["name"], severity=row["severity"],
                active=False, message="same filesystem mounted read-write after read-only incident",
                source="mount_reconciliation", device_id=row["device_id"] or "host",
                details={"recovery_source": "same_uuid_later_rw_mount", "filesystem_uuid": uuid},
            ))
    return recoveries
