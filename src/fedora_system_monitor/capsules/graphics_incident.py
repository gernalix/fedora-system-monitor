"""GNOME/Mutter/Wayland incident detection and bounded forensic capture.

This capsule deliberately avoids command lines, environment variables, browser
URLs, core bytes, and arbitrary application logs.  It detects compositor loss
independently of the journal by watching the gnome-shell PID while an active
Wayland login session still exists.  Journal/coredump evidence is correlated to
the same incident identifier when it arrives shortly afterwards.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import threading
import time
from typing import Any, Callable, Mapping

from fedora_system_monitor.capsules.activitywatch import correlate_activitywatch
from fedora_system_monitor.capsules.config import redact_text


Event = dict[str, Any]

_STATE_ROOT = Path("/var/lib/fedora-system-monitor")
_RECENT_SECONDS = 180.0
_RECENT_LOCK = threading.Lock()
_RECENT_INCIDENT: tuple[float, str] | None = None
_MAX_OUTPUT = 96_000

_SHELL_ASSERT_RE = re.compile(
    r"(?:\bassertion\b.{0,240}\bfailed\b|\bassert(?:ion)?[_ :].{0,180}\bfailed\b)",
    re.IGNORECASE,
)
_SHELL_CRASH_RE = re.compile(
    r"\b(?:segmentation fault|segfault|aborted|fatal error|terminated by signal|core dumped)\b",
    re.IGNORECASE,
)
_AMDGPU_FAULT_RE = re.compile(
    r"(?:amdgpu.*(?:GPU reset|ring .* timeout|VM_L2_PROTECTION_FAULT|GPU fault|"
    r"failed to .*reset|MES .*failed)|drm.*amdgpu.*timed out|flip_done timed out)",
    re.IGNORECASE,
)
_FBCON_RE = re.compile(r"\bfbcon:.*(?:taking over console|switching to colour frame buffer)", re.IGNORECASE)


def _clean(value: object, limit: int = 720) -> str:
    text = str(redact_text(value)).replace("\x00", " ").replace("\r", " ").strip()
    return text[:limit]


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _event_time(entry: Mapping[str, object] | None) -> datetime:
    if entry:
        try:
            micros = int(str(entry.get("__REALTIME_TIMESTAMP") or ""))
            if micros > 0:
                return datetime.fromtimestamp(micros / 1_000_000, timezone.utc)
        except (TypeError, ValueError, OSError, OverflowError):
            pass
    return _now_utc()


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()[:64]
    except OSError:
        return ""


def _make_incident_id(when: datetime, seed: str) -> str:
    stamp = when.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    digest = hashlib.sha256(seed.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"gfx-{stamp}-{digest}"


def _register_incident(incident_id: str) -> str:
    global _RECENT_INCIDENT
    with _RECENT_LOCK:
        _RECENT_INCIDENT = (time.monotonic(), incident_id)
    return incident_id


def _recent_incident_id() -> str:
    global _RECENT_INCIDENT
    with _RECENT_LOCK:
        if _RECENT_INCIDENT is None:
            return ""
        seen, incident_id = _RECENT_INCIDENT
        if time.monotonic() - seen > _RECENT_SECONDS:
            _RECENT_INCIDENT = None
            return ""
        return incident_id


def _incident_id(entry: Mapping[str, object] | None, *, discriminator: str) -> str:
    recent = _recent_incident_id()
    if recent:
        return recent
    when = _event_time(entry)
    seed = ":".join(
        (
            str(entry.get("_BOOT_ID", "") if entry else _boot_id()),
            str(entry.get("__CURSOR", "") if entry else ""),
            str(entry.get("__REALTIME_TIMESTAMP", "") if entry else time.time_ns()),
            discriminator,
        )
    )
    return _register_incident(_make_incident_id(when, seed))


def _base_event(
    *,
    name: str,
    severity: str,
    source: str,
    details: Mapping[str, Any],
    outcome: str = "failed",
    dedup_key: str,
    dedup_window_seconds: int = 60,
) -> Event:
    return {
        "category": "graphics",
        "name": name,
        "severity": severity,
        "source": source,
        "device_id": "desktop-compositor",
        "details": dict(details),
        "outcome": outcome,
        "error_message": "desktop compositor failure" if outcome == "failed" else None,
        "dedup_key": dedup_key,
        "dedup_window_seconds": dedup_window_seconds,
    }


def _is_shell_source(entry: Mapping[str, object]) -> bool:
    identifier = str(entry.get("SYSLOG_IDENTIFIER") or "").lower()
    comm = str(entry.get("_COMM") or "").lower()
    unit = str(entry.get("_SYSTEMD_USER_UNIT") or "")
    return (
        identifier == "gnome-shell"
        or comm == "gnome-shell"
        or unit.startswith("org.gnome.Shell@")
    )


def classify_graphics_coredump(entry: Mapping[str, object]) -> Event | None:
    executable = Path(_clean(entry.get("COREDUMP_EXE") or entry.get("COREDUMP_COMM") or "", 320)).name
    if executable != "gnome-shell":
        return None
    incident_id = _incident_id(entry, discriminator="gnome-shell-coredump")
    signal = _clean(entry.get("COREDUMP_SIGNAL_NAME") or entry.get("COREDUMP_SIGNAL") or "unknown", 32)
    uid_text = _clean(entry.get("COREDUMP_UID") or entry.get("_UID") or "", 20)
    details: dict[str, Any] = {
        "incident_id": incident_id,
        "incident_type": "desktop_compositor_failure",
        "trigger": "gnome_shell_coredump",
        "component": "gnome-shell",
        "signal": signal,
        "uid": int(uid_text) if uid_text.isdigit() else None,
        "confidence": "high",
    }
    unit = _clean(entry.get("COREDUMP_UNIT") or entry.get("_SYSTEMD_USER_UNIT") or "", 180)
    if unit:
        details["unit"] = unit
    return _base_event(
        name="desktop_compositor_coredump",
        severity="critical",
        source="systemd-coredump",
        details=details,
        dedup_key=f"graphics:coredump:{incident_id}",
        dedup_window_seconds=0,
    )


def classify_gnome_journal(entry: Mapping[str, object], message: str) -> Event | None:
    if not _is_shell_source(entry):
        return None
    if _SHELL_CRASH_RE.search(message):
        incident_id = _incident_id(entry, discriminator="gnome-shell-exit")
        return _base_event(
            name="desktop_compositor_failure",
            severity="critical",
            source="gnome-shell",
            details={
                "incident_id": incident_id,
                "incident_type": "desktop_compositor_failure",
                "trigger": "gnome_shell_fatal_log",
                "component": "gnome-shell",
                "confidence": "high",
                "evidence": _clean(message),
            },
            dedup_key=f"graphics:failure:{incident_id}",
            dedup_window_seconds=0,
        )
    if _SHELL_ASSERT_RE.search(message):
        signature = _clean(message)
        return _base_event(
            name="desktop_compositor_assertion",
            severity="warning",
            source="gnome-shell",
            details={"component": "gnome-shell", "signature": signature},
            outcome="observed",
            dedup_key=f"graphics:assertion:{hashlib.sha256(signature.encode()).hexdigest()[:16]}",
            dedup_window_seconds=60,
        )
    return None


def classify_graphics_kernel(entry: Mapping[str, object], message: str) -> Event | None:
    del entry
    if _AMDGPU_FAULT_RE.search(message):
        signature = _clean(message)
        return _base_event(
            name="gpu_driver_fault",
            severity="critical",
            source="kernel",
            details={"driver": "amdgpu", "evidence": signature},
            dedup_key=f"graphics:amdgpu:{hashlib.sha256(signature.encode()).hexdigest()[:16]}",
            dedup_window_seconds=60,
        )
    if _FBCON_RE.search(message):
        return _base_event(
            name="framebuffer_console_takeover",
            severity="info",
            source="kernel",
            details={"evidence": _clean(message)},
            outcome="observed",
            dedup_key="graphics:fbcon-takeover",
            dedup_window_seconds=30,
        )
    return None


def build_compositor_transition_event(
    previous_pids: set[int],
    current_pids: set[int],
    *,
    when: datetime | None = None,
    boot_id: str = "",
) -> Event:
    when = (when or _now_utc()).astimezone(timezone.utc)
    trigger = "pid_disappeared" if not current_pids else "pid_changed"
    recent = _recent_incident_id()
    incident_id = recent or _register_incident(
        _make_incident_id(
            when,
            f"{boot_id}:{sorted(previous_pids)}:{sorted(current_pids)}:{when.timestamp()}",
        )
    )
    event = _base_event(
        name="desktop_compositor_failure",
        severity="critical",
        source="compositor-watch",
        details={
            "incident_id": incident_id,
            "incident_type": "desktop_compositor_failure",
            "trigger": trigger,
            "component": "gnome-shell",
            "confidence": "high",
            "previous_pids": sorted(previous_pids),
            "current_pids": sorted(current_pids),
        },
        dedup_key=f"graphics:failure:{incident_id}",
        dedup_window_seconds=0,
    )
    event["timestamp_utc"] = when.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return event


def _shell_pids(operator_user: str) -> set[int]:
    try:
        uid = pwd.getpwnam(operator_user).pw_uid
    except KeyError:
        return set()
    found: set[int] = set()
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            if proc.stat().st_uid != uid:
                continue
            if (proc / "comm").read_text(encoding="utf-8", errors="replace").strip() == "gnome-shell":
                found.add(int(proc.name))
        except (OSError, ValueError):
            continue
    return found


def _run(command: list[str], *, timeout: float = 2.0, max_output: int = _MAX_OUTPUT) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
        )
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": _clean(result.stdout, max_output),
            "stderr": _clean(result.stderr, min(max_output, 16_000)),
        }
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": _clean(type(exc).__name__, 80)}


def _active_wayland_session(operator_user: str) -> bool | None:
    sessions = _run(["loginctl", "list-sessions", "--no-legend", "--no-pager"], timeout=2)
    if not sessions.get("ok"):
        return None
    seen_user = False
    for line in str(sessions.get("stdout") or "").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] != operator_user:
            continue
        seen_user = True
        props = _run(
            [
                "loginctl",
                "show-session",
                parts[0],
                "--property=Active",
                "--property=Type",
                "--property=State",
            ],
            timeout=2,
        )
        values: dict[str, str] = {}
        for item in str(props.get("stdout") or "").splitlines():
            if "=" in item:
                key, value = item.split("=", 1)
                values[key] = value
        if (
            values.get("Active") == "yes"
            and values.get("Type") == "wayland"
            and values.get("State") in {"active", "online"}
        ):
            return True
    return False if seen_user else None


def _system_state_allows_incident() -> bool:
    result = _run(["systemctl", "is-system-running"], timeout=1)
    state = str(result.get("stdout") or "").strip().splitlines()
    return bool(state and state[0] in {"running", "degraded"})


def _graphics_sysfs() -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    for card in sorted(Path("/sys/class/drm").glob("card[0-9]*")):
        device = card / "device"
        row: dict[str, str] = {"card": card.name}
        for name in ("vendor", "device", "revision", "power/runtime_status", "gpu_busy_percent"):
            path = device / name
            try:
                row[name.replace("/", "_")] = _clean(path.read_text(encoding="utf-8", errors="replace"), 160)
            except OSError:
                continue
        devices.append(row)
    return devices


def _user_command(operator_user: str, command: list[str]) -> list[str] | None:
    try:
        uid = pwd.getpwnam(operator_user).pw_uid
    except KeyError:
        return None
    return [
        "runuser",
        "-u",
        operator_user,
        "--",
        "env",
        f"XDG_RUNTIME_DIR=/run/user/{uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
        *command,
    ]


def _forensic_payload(config: Mapping[str, object], event: Event) -> dict[str, Any]:
    monitor = config.get("monitor") if isinstance(config, Mapping) else {}
    operator_user = str(monitor.get("operator_user") or "daniele") if isinstance(monitor, Mapping) else "daniele"
    timestamp = str(event.get("timestamp_utc") or _now_utc().isoformat())
    try:
        event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        event_time = _now_utc()
    activity = correlate_activitywatch(
        event_time.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        window_seconds=600,
        timeout=0.8,
    )
    commands: dict[str, list[str]] = {
        "kernel": ["uname", "-a"],
        "graphics_packages": [
            "rpm",
            "-q",
            "gnome-shell",
            "mutter",
            "mesa-dri-drivers",
            "mesa-libEGL",
            "mesa-vulkan-drivers",
            "kernel-core",
            "linux-firmware",
        ],
        "processes": [
            "ps",
            "-eo",
            "pid=,ppid=,uid=,comm=,etimes=,%cpu=,%mem=",
            "--sort=-%cpu",
        ],
        "memory": ["free", "-b"],
        "recent_coredumps": ["coredumpctl", "list", "--no-pager", "--since=-5min"],
    }
    start = (event_time - timedelta(minutes=5)).isoformat(timespec="seconds")
    end = (event_time + timedelta(seconds=5)).isoformat(timespec="seconds")
    commands["graphics_journal"] = [
        "journalctl",
        "--since",
        start,
        "--until",
        end,
        "--no-pager",
        "--output=short-iso-precise",
        "_TRANSPORT=kernel",
        "+",
        "_COMM=gnome-shell",
        "+",
        "SYSLOG_IDENTIFIER=gnome-shell",
        "+",
        "_SYSTEMD_USER_UNIT=org.gnome.Shell@wayland.service",
        "+",
        "_SYSTEMD_USER_UNIT=chrome-codex-switcher.service",
    ]
    extension_cmd = _user_command(operator_user, ["gnome-extensions", "list", "--enabled"])
    ccs_extension_cmd = _user_command(
        operator_user,
        ["gnome-extensions", "info", "chrome-codex-switcher@gernalix.github.com"],
    )
    ccs_service_cmd = _user_command(
        operator_user,
        [
            "systemctl",
            "--user",
            "show",
            "chrome-codex-switcher.service",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=ExecMainPID",
            "--property=ExecMainStartTimestamp",
        ],
    )
    user_units_cmd = _user_command(
        operator_user,
        [
            "systemctl",
            "--user",
            "list-units",
            "--type=service",
            "--state=running,failed",
            "--no-legend",
            "--no-pager",
            "--plain",
        ],
    )
    if extension_cmd:
        commands["enabled_gnome_extensions"] = extension_cmd
    if ccs_extension_cmd:
        commands["chrome_codex_gnome_extension"] = ccs_extension_cmd
    if ccs_service_cmd:
        commands["chrome_codex_service"] = ccs_service_cmd
    if user_units_cmd:
        commands["user_services"] = user_units_cmd
    evidence = {
        name: _run(command, timeout=2.5, max_output=128_000 if name == "graphics_journal" else _MAX_OUTPUT)
        for name, command in commands.items()
    }
    return {
        "schema": "fedora-system-monitor.graphics-incident.v1",
        "incident_id": str(event.get("details", {}).get("incident_id") or ""),
        "event_timestamp_utc": event_time.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "captured_at_utc": _now_utc().isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "trigger": str(event.get("details", {}).get("trigger") or ""),
        "activitywatch": activity,
        "graphics_sysfs": _graphics_sysfs(),
        "evidence": evidence,
    }


def enrich_graphics_incident(config: Mapping[str, object], event: Event) -> Event:
    details = event.setdefault("details", {})
    incident_id = str(details.get("incident_id") or "")
    if not incident_id:
        return event
    payload = _forensic_payload(config, event)
    details["activitywatch"] = payload["activitywatch"]
    monitor = config.get("monitor") if isinstance(config, Mapping) else {}
    db_path = str(monitor.get("database_path") or "") if isinstance(monitor, Mapping) else ""
    state_root = Path(db_path).parent if db_path else _STATE_ROOT
    incident_dir = state_root / "incidents"
    filename = f"{incident_id}.json"
    try:
        incident_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        target = incident_dir / filename
        target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(target, 0o640)
        details["forensic_snapshot"] = {
            "captured": True,
            "file": f"incidents/{filename}",
            "schema": payload["schema"],
        }
    except OSError as exc:
        details["forensic_snapshot"] = {
            "captured": False,
            "error": _clean(type(exc).__name__, 80),
            "schema": payload["schema"],
        }
    return event


def stream_compositor_watch(
    config: Mapping[str, object],
    db: object,
    stop_event: object,
    on_event: Callable[[Event], object] | None = None,
    *,
    poll_interval: float = 2.0,
) -> int:
    monitor = config.get("monitor") if isinstance(config, Mapping) else {}
    operator_user = str(monitor.get("operator_user") or "daniele") if isinstance(monitor, Mapping) else "daniele"
    previous = _shell_pids(operator_user)
    matched = 0
    while not bool(getattr(stop_event, "is_set")()):
        if bool(getattr(stop_event, "wait")(max(0.25, poll_interval))):
            break
        current = _shell_pids(operator_user)
        if previous and current != previous:
            active = _active_wayland_session(operator_user)
            if active is True and _system_state_allows_incident():
                event = build_compositor_transition_event(
                    previous,
                    current,
                    boot_id=_boot_id(),
                )
                enrich_graphics_incident(config, event)
                try:
                    db.insert_events([event], dedup_window_seconds=0)
                except TypeError:
                    db.insert_events([event])
                if on_event is not None:
                    on_event(event)
                matched += 1
        previous = current
    return matched


def is_graphics_incident(event: Mapping[str, object]) -> bool:
    details = event.get("details")
    return (
        event.get("category") == "graphics"
        and isinstance(details, Mapping)
        and bool(details.get("incident_id"))
    )


__all__ = [
    "build_compositor_transition_event",
    "classify_gnome_journal",
    "classify_graphics_coredump",
    "classify_graphics_kernel",
    "enrich_graphics_incident",
    "is_graphics_incident",
    "stream_compositor_watch",
]
