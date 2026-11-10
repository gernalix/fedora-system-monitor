"""Authenticate journal producers using journal-owned fields, never syslog names.

Only journalctl records belong here: underscore fields are authenticated by
journald. COREDUMP_* and SYSLOG_IDENTIFIER are payload, not producer identity.
"""
from __future__ import annotations

from collections.abc import Mapping
import pwd
import re

_COREDUMP_UNIT = re.compile(r"systemd-coredump@[^/\s]+\.service\Z")
_SLEEP_UNITS = {
    "systemd-suspend.service", "systemd-hibernate.service",
    "systemd-hybrid-sleep.service", "systemd-suspend-then-hibernate.service",
}


def operator_uid(config: Mapping[str, object] | None = None) -> int | None:
    monitor = (config or {}).get("monitor", {})
    user = monitor.get("operator_user", "daniele") if isinstance(monitor, Mapping) else "daniele"
    try:
        return pwd.getpwnam(str(user)).pw_uid
    except KeyError:
        return None


def is_coredump_producer(entry: Mapping[str, object]) -> bool:
    return bool(_COREDUMP_UNIT.fullmatch(str(entry.get("_SYSTEMD_UNIT", ""))))


def is_shell_producer(entry: Mapping[str, object], config: Mapping[str, object] | None = None) -> bool:
    uid = operator_uid(config)
    return (
        uid is not None and str(entry.get("_UID", "")) == str(uid)
        and entry.get("_EXE") == "/usr/bin/gnome-shell"
    )


def is_manager_producer(entry: Mapping[str, object], config: Mapping[str, object] | None = None) -> bool:
    if str(entry.get("_UID", "")) == "0" and str(entry.get("_PID", "")) == "1":
        return True
    uid = operator_uid(config)
    return (
        uid is not None and str(entry.get("_UID", "")) == str(uid)
        and entry.get("_SYSTEMD_UNIT") == f"user@{uid}.service"
        and str(entry.get("_EXE", "")) in {"/usr/lib/systemd/systemd", "/lib/systemd/systemd"}
    )


def is_sleep_producer(entry: Mapping[str, object]) -> bool:
    return str(entry.get("_SYSTEMD_UNIT", "")) in _SLEEP_UNITS


def is_journald_producer(entry: Mapping[str, object]) -> bool:
    unit = str(entry.get("_SYSTEMD_UNIT", ""))
    return unit == "systemd-journald.service" or bool(
        re.fullmatch(r"systemd-journald@[^/\s]+\.service", unit)
    )
