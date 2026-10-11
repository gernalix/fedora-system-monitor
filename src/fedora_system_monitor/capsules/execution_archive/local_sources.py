"""Bounded adapters for local executions not started by an interactive shell.

There is no background watcher here.  Journal cursors and native container event
timestamps are consumed only on an explicit collection pass.  Browser content,
environment, stdin, shell history and arbitrary argv are never read or stored.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Callable, Iterable

from . import Archive, atomic_json
from .capture import OUTPUT_DENY

Run = Callable[..., subprocess.CompletedProcess]
UNIT = re.compile(r"^[A-Za-z0-9_.@:-]{1,200}\.(?:service|timer|scope)$")
NAME = re.compile(r"^[A-Za-z0-9_.@:+-]{1,200}$")
EXIT = re.compile(r"(?:status|code)=(\d+)(?:/|\b)")
CURSOR_FIELDS = (
    "__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_PID,_SYSTEMD_UNIT,_SYSTEMD_USER_UNIT,"
    "_SYSTEMD_INVOCATION_ID,INVOCATION_ID,MESSAGE_ID,MESSAGE,PRIORITY,UNIT,"
    "JOB_RESULT,RESULT,EXIT_CODE,EXIT_STATUS,_COMM,_EXE,SYSLOG_IDENTIFIER"
)


def _run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=False, **kwargs)


def _present(command: str) -> bool:
    return shutil.which(command) is not None


def _files(paths: Iterable[Path], pattern: str = "*") -> list[Path]:
    found: list[Path] = []
    for root in paths:
        if root.is_dir() and not root.is_symlink():
            found.extend(p for p in root.glob(pattern) if p.is_file() and not p.is_symlink())
    return sorted(found)


def _git_hooks(repo: Path) -> list[Path]:
    direct = _files((repo / ".git/hooks",))
    if direct or not _present("git"):
        return direct
    result = _run(["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                  capture_output=True, text=True, timeout=5)
    if result.returncode:
        return []
    common = Path(result.stdout.strip())
    return _files((common / "hooks",)) if common.is_absolute() else []


def inventory(home: Path | None = None, repo: Path | None = None) -> dict:
    """Return presence and coverage decisions without opening source contents."""
    home = home or Path.home()
    repo = repo or Path.cwd()
    cron = _files(tuple(Path(p) for p in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
                                          "/etc/cron.weekly", "/etc/cron.monthly")))
    autostart = _files((Path("/etc/xdg/autostart"), home / ".config/autostart"), "*.desktop")
    hooks = _git_hooks(repo)
    native = _files((Path("/etc/opt/chrome/native-messaging-hosts"),
                     Path("/etc/chromium/native-messaging-hosts"),
                     home / ".config/google-chrome/NativeMessagingHosts",
                     home / ".config/chromium/NativeMessagingHosts"), "*.json")
    studios = [p for p in (home / ".config/Google").glob("AndroidStudio*") if p.is_dir()]
    ide_present = bool(studios or (home / ".gradle").is_dir() or
                       (home / ".config/JetBrains").is_dir())
    launchers = _files((Path("/usr/local/bin"), home / ".local/bin"))
    return {
        "schema": "fedora-system-monitor.local-execution-inventory.v1",
        "sources": [
            {"source": "systemd-system", "present": _present("systemctl") and _present("journalctl"),
             "coverage": "filtered-command+pid+timestamp+exit-when-journal-provides; combined-journal-stream only for exact opt-in unit",
             "collector": "explicit bounded journal pass with per-unit cursor"},
            {"source": "systemd-user", "present": _present("systemctl") and _present("journalctl"),
             "coverage": "filtered-command+pid+timestamp+exit-when-journal-provides; combined-journal-stream only for exact opt-in unit",
             "collector": "explicit bounded journal pass with per-unit cursor"},
            {"source": "timers", "present": _present("systemctl"),
             "coverage": "service execution via systemd journal; timer trigger metadata otherwise", "collector": "systemd"},
            {"source": "cron-anacron", "present": bool(cron) or _present("crond") or _present("anacron"),
             "count": len(cron), "coverage": "metadata-only when crond journal is explicitly collected; job output NOT COVERED",
             "collector": "systemd journal"},
            {"source": "udev", "present": Path("/usr/lib/systemd/system/systemd-udevd.service").exists(),
             "coverage": "metadata-only; executed RUN payload/output NOT COVERED", "collector": "existing FSM event/journal paths"},
            {"source": "autostart", "present": bool(autostart), "count": len(autostart),
             "coverage": "inventory metadata-only; executions/output NOT COVERED", "collector": "none"},
            {"source": "git-hooks", "present": bool(hooks), "count": len(hooks),
             "coverage": "PID+parent+timestamp+exit through explicit lifecycle wrapper; output/stdin NOT COVERED", "collector": "opt-in supported hook wrapper"},
            {"source": "podman", "present": _present("podman"),
             "coverage": "native lifecycle metadata; logs/output NOT COVERED without a present exact safe container", "collector": "podman events"},
            {"source": "docker", "present": _present("docker"), "coverage": "NOT COVERED", "collector": "none"},
            {"source": "ide-gradle", "present": ide_present,
             "coverage": "PID+parent+timestamp+exit only when launched through explicit wrapper; IDE logs/output NOT COVERED", "collector": "opt-in wrapper"},
            {"source": "chrome-native-messaging", "present": bool(native), "count": len(native),
             "coverage": "configuration inventory metadata-only; process/page/message content NOT COVERED", "collector": "none"},
            {"source": "launchers", "present": bool(launchers), "count": len(launchers),
             "coverage": "PID+parent+timestamp+exit only when launched through explicit wrapper; output/stdin NOT COVERED", "collector": "opt-in wrapper"},
            {"source": "auditd-ebpf", "present": _present("auditctl") or _present("bpftrace"),
             "coverage": "NOT ENABLED; global exec interception rejected as unnecessary/invasive", "collector": "none"},
        ],
        "excluded": ["ChatGPT conversations", "Codex transcripts", "browser page content",
                     "environment", "passwords/tokens", "hidden stdin", "shell history"],
    }


def _state_path(a: Archive) -> Path:
    return a.root / "local-source-cursors.json"


def _state(a: Archive) -> dict:
    path = _state_path(a)
    value = json.loads(path.read_text()) if path.exists() else {"schema": 1, "journals": {}, "podman_since": None}
    if not isinstance(value, dict) or not isinstance(value.get("journals"), dict):
        raise ValueError("invalid source cursor state")
    return value


def _unit_key(scope: str, unit: str) -> str:
    return hashlib.sha256((scope + "\0" + unit).encode()).hexdigest()


def _timestamp(entry: dict) -> float:
    try:
        return int(entry.get("__REALTIME_TIMESTAMP", 0)) / 1_000_000
    except (TypeError, ValueError):
        return time.time()


def _exit_code(entry: dict) -> int | None:
    value = entry.get("EXIT_STATUS")
    if isinstance(value, str) and value.isdigit():
        return int(value)
    message = entry.get("MESSAGE")
    match = EXIT.search(message) if isinstance(message, str) else None
    if match:
        return int(match.group(1))
    if isinstance(message, str) and message.endswith("Deactivated successfully."):
        return 0
    return None


def _journal_source(scope: str, unit: str) -> tuple[str, str]:
    if unit == "crond.service":
        return "cron", "scheduled"
    if unit == "systemd-udevd.service":
        return "udev", "device-event"
    return ("systemd-user" if scope == "user" else "systemd-system"), "service"


def collect_journal(a: Archive, *, scope: str, unit: str, include_output: bool = False,
                    since: str = "-15min", runner: Run = _run) -> dict:
    if scope not in {"system", "user"} or not UNIT.fullmatch(unit):
        raise ValueError("exact systemd unit required")
    state = _state(a)
    key = _unit_key(scope, unit)
    saved_cursor = state["journals"].get(key)
    cursor = saved_cursor.get("cursor") if isinstance(saved_cursor, dict) else saved_cursor
    argv = ["journalctl", "--quiet", "--no-pager", "--output=json",
            "--output-fields=" + CURSOR_FIELDS]
    if scope == "user":
        argv.append("--user")
    argv += ["--unit", unit]
    argv += ["--after-cursor", cursor] if cursor else ["--since", since]
    result = runner(argv, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError("journal query failed")
    entries: list[dict] = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("__CURSOR"):
            entries.append(item)
    source, label = _journal_source(scope, unit)
    inserted = duplicates = content = 0
    last = cursor
    last_timestamp = 0
    for item in entries:
        raw_cursor = str(item["__CURSOR"])
        item_timestamp = _timestamp(item)
        invocation = str(item.get("_SYSTEMD_INVOCATION_ID") or item.get("INVOCATION_ID") or raw_cursor)
        command = Path(str(item.get("_EXE") or item.get("_COMM") or "unknown")).name[:80]
        pid_text = str(item.get("_PID") or "0")
        pid = int(pid_text) if pid_text.isdigit() else 0
        unit_field = item.get("_SYSTEMD_USER_UNIT") if scope == "user" else item.get("_SYSTEMD_UNIT")
        own_stream = str(unit_field or "") == unit
        message = item.get("MESSAGE")
        payload = None
        gap = "journal metadata only"
        coverage = "metadata-only"
        if include_output and own_stream and command not in {"systemd", "systemd-journald"} and isinstance(message, str):
            encoded = message.encode("utf-8", "replace") + b"\n"
            if not OUTPUT_DENY.search(encoded):
                payload, coverage, gap = encoded, "journal-stream", "stdout/stderr not distinguished by journald"
                content += 1
            else:
                gap = "recognizable-sensitive-output"
        metadata = {
            "unit": unit, "scope": scope, "command": command or "unknown",
            "argv": "filtered-to-executable-basename", "parent_pid": "not-provided-by-journal",
            "message_id": str(item.get("MESSAGE_ID") or "")[:64],
            "result": str(item.get("JOB_RESULT") or item.get("RESULT") or "")[:64],
            "boot_id": str(item.get("_BOOT_ID") or "")[:64],
        }
        _m, created = a.record_external(
            source=source, label=label, identity=raw_cursor, correlation_key=invocation,
            started=item_timestamp, pid=pid, exit_code=_exit_code(item), metadata=metadata,
            output=payload, coverage=coverage, content_gap=gap)
        inserted += int(created)
        duplicates += int(not created)
        last = raw_cursor
        last_timestamp = max(last_timestamp, item_timestamp)
    if last != cursor:
        with a.lock():
            current = _state(a)
            previous = current["journals"].get(key)
            previous_timestamp = previous.get("timestamp", 0) if isinstance(previous, dict) else 0
            if last_timestamp >= previous_timestamp:
                current["journals"][key] = {"cursor": last, "timestamp": last_timestamp}
                atomic_json(_state_path(a), current)
    return {"source": source, "unit": unit, "scope": scope, "read": len(entries),
            "inserted": inserted, "duplicates": duplicates, "content_events": content,
            "cursor_advanced": last != cursor}


def parse_podman_events(lines: str) -> list[dict]:
    parsed = []
    for line in lines.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        status = str(item.get("Status") or item.get("status") or "")[:80]
        kind = str(item.get("Type") or item.get("type") or "")[:40]
        actor = item.get("Actor") if isinstance(item.get("Actor"), dict) else {}
        attrs = actor.get("Attributes") if isinstance(actor.get("Attributes"), dict) else {}
        ident = str(item.get("ID") or item.get("id") or actor.get("ID") or "")[:128]
        stamp = item.get("TimeNano") or item.get("timeNano") or item.get("Time") or item.get("time")
        try:
            started = float(stamp) / (1_000_000_000 if float(stamp) > 10_000_000_000 else 1)
        except (TypeError, ValueError):
            continue
        if not status or not kind or not ident:
            continue
        parsed.append({"identity": f"{stamp}:{kind}:{status}:{ident}", "started": started,
                       "correlation": ident, "metadata": {"type": kind, "status": status,
                       "container_id": ident, "name": str(attrs.get("name") or "")[:128],
                       "image": str(attrs.get("image") or "")[:256]}})
    return parsed


def collect_podman(a: Archive, *, since: str = "-15m", runner: Run = _run) -> dict:
    state = _state(a)
    start = state.get("podman_since") or since
    try:
        numeric_start = float(start)
        if numeric_start > 10_000_000_000:
            start = f"{numeric_start / 1_000_000_000:.6f}"
    except (TypeError, ValueError):
        pass
    result = runner(["podman", "events", "--stream=false", "--since", str(start), "--format", "json"],
                    capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError("podman events failed")
    events = parse_podman_events(result.stdout)
    inserted = duplicates = 0
    for item in events:
        _m, created = a.record_external(source="podman", label="container",
                                        identity=item["identity"], correlation_key=item["correlation"],
                                        started=item["started"], metadata=item["metadata"],
                                        content_gap="native logs not selected")
        inserted += int(created)
        duplicates += int(not created)
    finished = time.time()
    with a.lock():
        current = _state(a)
        try:
            previous = float(current.get("podman_since") or 0)
        except (TypeError, ValueError):
            previous = 0
        if previous > 10_000_000_000:  # migrate the short-lived nanosecond v1 cursor
            previous /= 1_000_000_000
        current["podman_since"] = f"{max(previous, finished):.6f}"
        atomic_json(_state_path(a), current)
    return {"source": "podman", "read": len(events), "inserted": inserted,
            "duplicates": duplicates, "coverage": "metadata-only"}


def run_wrapped(root: Path | None, source: str, name: str, argv: list[str]) -> int:
    """Run an explicitly adopted lifecycle boundary; archive failure is fail-open."""
    if source not in {"git-hook", "ide", "launcher"} or not NAME.fullmatch(name) or not argv:
        raise ValueError("invalid wrapped source")
    started = time.time()
    child = subprocess.Popen(argv)
    code = child.wait()
    normalized = code if code >= 0 else 128 - code
    try:
        a = Archive(root)
        a.record_external(source=source, label={"git-hook": "hook", "ide": "ide", "launcher": "launcher"}[source],
                          identity=f"{started:.9f}:{os.getpid()}:{child.pid}:{name}", started=started,
                          pid=child.pid, parent_pid=os.getpid(), exit_code=normalized,
                          metadata={"name": name, "command": Path(argv[0]).name[:80],
                                    "argv": "filtered-to-executable-basename"},
                          content_gap="stdout/stderr/stdin inherited and not recorded")
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        pass
    return normalized
