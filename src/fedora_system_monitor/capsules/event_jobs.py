"""Event-driven health signals owned by the Fedora monitoring controller."""

from __future__ import annotations

import subprocess
from pathlib import Path

from fedora_system_monitor.capsules.notifications import configured_push_keys, send_named_heartbeat

T7_KEY = "event_t7_restic"
T7_UUID_LINK = Path("/dev/disk/by-uuid/4c75ac03-4c73-43f8-afd9-f90db49a74fc")
T7_BACKUP_RECORD = Path("/var/lib/t7-restic-backup/last-backup.json")


def _backup_unit() -> dict[str, str]:
    output = subprocess.run(
        ["systemctl", "show", "t7-restic-backup.service", "--property=ActiveState,Result,ExecMainStatus"],
        text=True, capture_output=True, timeout=8, check=True,
    ).stdout
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def t7_backup_health(
    device: Path = T7_UUID_LINK,
    record: Path = T7_BACKUP_RECORD,
) -> tuple[bool, str]:
    """Require a successful backup only for a present T7 attachment event."""
    try:
        state = _backup_unit()
        result = state.get("Result")
        exit_status = int(state.get("ExecMainStatus", "1"))
        if result not in {"", "success"} or exit_status != 0:
            return False, f"T7 backup failed: result={result or 'unknown'} exit={exit_status}"
        if not device.exists():
            return True, "T7 disconnected; no backup expected"
        if state.get("ActiveState") == "activating":
            return True, "T7 connected; backup running"
        if not record.is_file() or record.stat().st_mtime < device.lstat().st_ctime - 5:
            return False, "T7 connected; no completed backup for this attachment"
        return True, "T7 connected; backup completed for this attachment"
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return False, f"T7 health probe failed: {type(exc).__name__}"


def send_event_job_heartbeats(config: dict, *, ping_ms: int | None = None) -> list:
    if T7_KEY not in configured_push_keys(config):
        return []
    healthy, reason = t7_backup_health()
    return [send_named_heartbeat(config, T7_KEY, healthy=healthy, message=reason, ping_ms=ping_ms)]
