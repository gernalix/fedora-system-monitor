"""Lightweight minute, five-minute, and fifteen-minute collectors."""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
import os
from pathlib import Path
import re
import socket
import time
from typing import Any

from .common import (
    command_problem,
    config_value,
    external,
    operator_external,
    stable_hash,
    state_get,
    state_set,
    sustained_severity,
)
from .model import CADENCE_SECONDS, CollectionResult, record


PROC_ROOT = Path("/proc")
SYS_ROOT = Path("/sys")
MOUNTINFO_PATH = PROC_ROOT / "self" / "mountinfo"
UUID_LINK_ROOT = Path("/dev/disk/by-uuid")

_DEFAULT_SERVICES = {
    "NetworkManager.service",
    "sshd.service",
    "firewalld.service",
    "bluetooth.service",
    "libvirtd.service",
    "podman.service",
    "docker.service",
    "rustdesk.service",
    "smartd.service",
    "auditd.service",
    "udisks2.service",
    "upower.service",
    "uptime-kuma.service",
}
_PSEUDO_FILESYSTEMS = {
    "autofs", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts", "devtmpfs",
    "efivarfs", "fusectl", "hugetlbfs", "mqueue", "nsfs", "proc", "pstore", "ramfs",
    "securityfs", "sysfs", "tracefs",
}


def _read(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def _number(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _threshold(config: Mapping[str, Any], paths: tuple[tuple[str, ...], ...], default: float) -> float:
    return _number(config_value(config, *paths, default=default), default)


def _key_values(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in _read(path).splitlines():
        fields = line.split()
        if len(fields) >= 2:
            try:
                values[fields[0]] = int(fields[1])
            except ValueError:
                continue
    return values


def _psi_memory() -> dict[str, float]:
    values: dict[str, float] = {}
    for line in _read(PROC_ROOT / "pressure" / "memory").splitlines():
        fields = line.split()
        if not fields:
            continue
        prefix = fields[0]
        for field in fields[1:]:
            key, separator, raw = field.partition("=")
            if not separator or key not in {"avg10", "avg60", "avg300"}:
                continue
            values[f"{prefix}_{key}"] = _number(raw, 0.0)
    return values


def _zram_details() -> dict[str, float | int | bool]:
    root = SYS_ROOT / "block"
    original = compressed = memory_used = disk_size = writeback_bytes = 0
    devices = 0
    writeback_configured = False
    for device in (sorted(root.glob("zram*")) if root.exists() else []):
        stats = _read(device / "mm_stat").split()
        if len(stats) >= 3:
            original += int(_number(stats[0], 0))
            compressed += int(_number(stats[1], 0))
            memory_used += int(_number(stats[2], 0))
        disk_size += int(_number(_read(device / "disksize").strip(), 0))
        backing = _read(device / "backing_dev").strip().strip("[]")
        writeback_configured = writeback_configured or bool(backing and backing != "none")
        bd_stats = _read(device / "bd_stat").split()
        if bd_stats:
            writeback_bytes += int(_number(bd_stats[0], 0)) * 4096
        devices += 1
    return {
        "devices": devices,
        "original_bytes": original,
        "compressed_bytes": compressed,
        "memory_used_bytes": memory_used,
        "disk_size_bytes": disk_size,
        "compression_ratio": original / compressed if compressed else 0.0,
        "writeback_configured": writeback_configured,
        "writeback_bytes": writeback_bytes,
    }


def collect_proc(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    stat_line = next((line for line in _read(PROC_ROOT / "stat").splitlines() if line.startswith("cpu ")), "")
    fields = stat_line.split()[1:]
    if len(fields) >= 4:
        values = [int(value) for value in fields]
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        previous = state_get(db, "proc.cpu", {})
        basis = "cumulative"
        busy_percent = 100.0 * (total - idle) / total if total else 0.0
        if isinstance(previous, Mapping):
            delta_total = total - int(previous.get("total", total))
            delta_idle = idle - int(previous.get("idle", idle))
            if delta_total > 0 and 0 <= delta_idle <= delta_total:
                busy_percent = 100.0 * (delta_total - delta_idle) / delta_total
                basis = "interval"
        state_set(db, "proc.cpu", {"total": total, "idle": idle})
        result.metrics.append(
            record(cadence, "cpu", "cpu_total_used_percent", round(busy_percent, 3), "%", source="procfs", details={"basis": basis})
        )
    else:
        result.errors.append("procfs: cannot parse /proc/stat")

    load_fields = _read(PROC_ROOT / "loadavg").split()
    for index, name in enumerate(("load_1m", "load_5m", "load_15m")):
        if len(load_fields) > index:
            try:
                result.metrics.append(record(cadence, "cpu", name, float(load_fields[index]), "load", source="procfs"))
            except ValueError:
                pass

    memory: dict[str, int] = {}
    for line in _read(PROC_ROOT / "meminfo").splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        parts = raw.split()
        if parts and parts[0].isdigit():
            memory[key] = int(parts[0]) * 1024
    total_memory = memory.get("MemTotal", 0)
    available = memory.get("MemAvailable", 0)
    if total_memory:
        used = max(0, total_memory - available)
        used_percent = used * 100.0 / total_memory
        warning = _threshold(config, (("thresholds", "memory", "ram_warning_percent"), ("thresholds", "ram_used_percent", "warning")), 90)
        critical = _threshold(config, (("thresholds", "memory", "ram_critical_percent"), ("thresholds", "ram_used_percent", "critical")), 95)
        duration = _threshold(config, (("thresholds", "memory", "ram_warning_duration_seconds"), ("thresholds", "ram_used_percent", "warning_duration_seconds")), 300)
        severity = sustained_severity(db, "condition.ram", used_percent, warning=warning, critical=critical, duration_seconds=duration)
        result.metrics.extend(
            [
                record(cadence, "memory", "memory.used_percent", round(used_percent, 3), "%", severity=severity, source="procfs"),
                record(cadence, "memory", "ram_used_bytes", used, "bytes", severity=severity, source="procfs"),
                record(cadence, "memory", "ram_available_bytes", available, "bytes", severity=severity, source="procfs"),
            ]
        )
    swap_total = memory.get("SwapTotal", 0)
    swap_free = memory.get("SwapFree", 0)
    swap_used = max(0, swap_total - swap_free)
    swap_percent = swap_used * 100.0 / swap_total if swap_total else 0.0
    result.metrics.extend(
        [
            record(cadence, "memory", "swap.used_percent", round(swap_percent, 3), "%", source="procfs", details={"informational": True}),
            record(cadence, "memory", "swap_used_bytes", swap_used, "bytes", source="procfs"),
        ]
    )

    available_percent = available * 100.0 / total_memory if total_memory else 0.0
    psi = _psi_memory()
    vmstat = _key_values(PROC_ROOT / "vmstat")
    current_time = time.time()
    previous = state_get(db, "proc.memory_pressure", {})
    elapsed = 0.0
    if isinstance(previous, Mapping):
        elapsed = current_time - _number(previous.get("timestamp"), current_time)

    def counter_rate(name: str) -> float:
        current = vmstat.get(name, 0)
        before = int(_number(previous.get(name), current)) if isinstance(previous, Mapping) else current
        return (current - before) / elapsed if elapsed > 0 and current >= before else 0.0

    swap_in_bps = counter_rate("pswpin") * 4096
    swap_out_bps = counter_rate("pswpout") * 4096
    scan_rate = sum(counter_rate(name) for name in vmstat if name.startswith("pgscan_"))
    steal_rate = sum(counter_rate(name) for name in vmstat if name.startswith("pgsteal_"))
    oom_delta = int(max(0.0, counter_rate("oom_kill") * elapsed)) if elapsed > 0 else 0
    state_set(db, "proc.memory_pressure", {"timestamp": current_time, **vmstat})

    zram = _zram_details()
    psi_some = psi.get("some_avg10", 0.0)
    psi_full = psi.get("full_avg10", 0.0)
    available_warning = _threshold(config, (("thresholds", "memory", "available_warning_percent"),), 10)
    available_critical = _threshold(config, (("thresholds", "memory", "available_critical_percent"),), 5)
    psi_some_warning = _threshold(config, (("thresholds", "memory", "psi_some_warning_percent"),), 10)
    psi_full_critical = _threshold(config, (("thresholds", "memory", "psi_full_critical_percent"),), 5)
    swap_out_warning = _threshold(config, (("thresholds", "memory", "swap_out_warning_mib_per_second"),), 16) * 1024**2
    reclaim_warning = _threshold(config, (("thresholds", "memory", "reclaim_warning_pages_per_second"),), 4096)
    supporting_pressure = psi_some >= 1 or swap_out_bps >= swap_out_warning / 4 or scan_rate >= reclaim_warning / 4
    pressure_level = 0
    reasons: list[str] = []
    if oom_delta:
        pressure_level = 2
        reasons.append("oom")
    if psi_full >= psi_full_critical:
        pressure_level = 2
        reasons.append("psi_full")
    if available_percent < available_critical and (psi_full >= 1 or swap_out_bps >= swap_out_warning or scan_rate >= reclaim_warning):
        pressure_level = 2
        reasons.append("low_available_with_activity")
    elif pressure_level < 2 and ((available_percent < available_warning and supporting_pressure) or psi_some >= psi_some_warning):
        pressure_level = 1
        reasons.append("sustained_pressure")
    pressure_details = {
        "available_percent": round(available_percent, 3),
        "psi_some_avg10_percent": round(psi_some, 3),
        "psi_full_avg10_percent": round(psi_full, 3),
        "swap_in_bytes_per_second": round(swap_in_bps, 3),
        "swap_out_bytes_per_second": round(swap_out_bps, 3),
        "reclaim_scan_pages_per_second": round(scan_rate, 3),
        "reclaim_efficiency_percent": round(100.0 * steal_rate / scan_rate, 3) if scan_rate else None,
        "oom_kills_delta": oom_delta,
        "zram_compression_ratio": round(float(zram["compression_ratio"]), 3),
        "reasons": reasons,
    }
    severity = "critical" if pressure_level == 2 else "warning" if pressure_level == 1 else "info"
    result.metrics.extend(
        [
            record(cadence, "memory", "memory.available_percent", round(available_percent, 3), "%", source="procfs"),
            record(cadence, "memory", "memory.psi_some_avg10_percent", round(psi_some, 3), "%", source="procfs"),
            record(cadence, "memory", "memory.psi_full_avg10_percent", round(psi_full, 3), "%", source="procfs"),
            record(cadence, "memory", "memory.swap_in_bytes_per_second", round(swap_in_bps, 3), "bytes/s", source="procfs"),
            record(cadence, "memory", "memory.swap_out_bytes_per_second", round(swap_out_bps, 3), "bytes/s", source="procfs"),
            record(cadence, "memory", "memory.reclaim_scan_pages_per_second", round(scan_rate, 3), "pages/s", source="procfs"),
            record(cadence, "memory", "memory.oom_kills_delta", oom_delta, "events", severity="critical" if oom_delta else "info", source="procfs"),
            record(cadence, "memory", "memory.pressure_level", pressure_level, "level", severity=severity, source="procfs", details=pressure_details),
        ]
    )
    if int(zram["devices"]):
        result.metrics.extend(
            [
                record(cadence, "memory", "zram.compression_ratio", round(float(zram["compression_ratio"]), 3), "ratio", source="sysfs"),
                record(cadence, "memory", "zram.memory_used_bytes", int(zram["memory_used_bytes"]), "bytes", source="sysfs"),
                record(cadence, "memory", "zram.writeback_bytes", int(zram["writeback_bytes"]), "bytes", source="sysfs", details={"configured": bool(zram["writeback_configured"])}),
            ]
        )
    return result


def _unescape_mount(value: str) -> str:
    return value.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")


def mount_table() -> list[dict[str, str]]:
    mounts: list[dict[str, str]] = []
    for line in _read(MOUNTINFO_PATH).splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
            mount_point = _unescape_mount(fields[4])
            mounts.append(
                {
                    "mount_point": mount_point,
                    "root": _unescape_mount(fields[3]),
                    "major_minor": fields[2],
                    "options": fields[5],
                    "fstype": fields[separator + 1],
                    "source": _unescape_mount(fields[separator + 2]),
                }
            )
        except (ValueError, IndexError):
            continue
    return mounts


def _disk_severity(config: Mapping[str, Any], free_percent: float, free_bytes: int, total_bytes: int) -> str:
    warning = _threshold(config, (("thresholds", "disk", "warning_free_percent"), ("thresholds", "disk_free_percent", "warning")), 20)
    critical = _threshold(config, (("thresholds", "disk", "critical_free_percent"), ("thresholds", "disk_free_percent", "critical")), 10)
    emergency = _threshold(config, (("thresholds", "disk", "emergency_free_percent"), ("thresholds", "disk_free_percent", "emergency")), 5)
    if free_percent < emergency:
        return "emergency"
    if free_percent < critical:
        return "critical"
    if free_percent < warning:
        return "warning"
    small_limit = _threshold(config, (("storage", "small_filesystem_max_gib"),), 5) * 1024**3
    absolute = _threshold(config, (("thresholds", "disk", "absolute_free_gib"), ("thresholds", "disk_free_gib", "warning")), 10) * 1024**3
    if total_bytes > small_limit and free_bytes < absolute:
        return "warning"
    return "info"


def _filesystem_source_id(source: str) -> str:
    """Prefer the filesystem UUID while keeping mapper and sdX names out of IDs."""

    source_path = source.split("[", 1)[0]
    try:
        resolved = os.path.realpath(source_path)
        if UUID_LINK_ROOT.exists():
            for link in UUID_LINK_ROOT.iterdir():
                try:
                    if os.path.realpath(link) == resolved:
                        return f"fsuuid:{link.name}"
                except OSError:
                    continue
    except OSError:
        pass
    return stable_hash(source_path or source, "filesystem")


def _filesystem_device_id(mount: Mapping[str, str], view_path: str) -> tuple[str, str]:
    source_id = _filesystem_source_id(mount.get("source", "unknown"))
    root = mount.get("root", "/")
    view = stable_hash(f"{root}|{view_path}", "view").split(":", 1)[1]
    return f"{source_id}:view:{view}", source_id


def _mount_for_path(path: str, mounts: list[dict[str, str]]) -> dict[str, str] | None:
    candidates = []
    for mount in mounts:
        mount_point = mount["mount_point"]
        if path == mount_point or path.startswith(mount_point.rstrip("/") + "/"):
            candidates.append(mount)
    return max(candidates, key=lambda item: len(item["mount_point"])) if candidates else None


def collect_filesystems(
    scope: str,
    config: Mapping[str, Any],
    db: object,
    *,
    all_relevant: bool,
) -> CollectionResult:
    del db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    critical = set(config_value(config, ("collection", "critical_filesystems"), default=["/", "/home", "/var", "/tmp", "/boot", "/boot/efi"]))
    configured_ignored = set(config_value(config, ("collection", "ignore_filesystem_types"), default=[]))
    ignored = _PSEUDO_FILESYSTEMS | configured_ignored
    seen: set[str] = set()
    mounts = mount_table()
    selected = list(mounts)
    for target in sorted(critical):
        if any(mount["mount_point"] == target for mount in selected) or not Path(target).exists():
            continue
        parent = _mount_for_path(target, mounts)
        if parent:
            view = dict(parent)
            relative = os.path.relpath(target, parent["mount_point"])
            view["root"] = str(Path(parent.get("root", "/")) / relative) if relative != "." else parent.get("root", "/")
            view["mount_point"] = target
            selected.append(view)
    for mount in selected:
        path = mount["mount_point"]
        fstype = mount["fstype"]
        if path in seen:
            continue
        if all_relevant:
            if fstype in ignored and path != "/tmp":
                continue
            if path.startswith(("/proc", "/sys", "/dev", "/run/credentials", "/run/user")):
                continue
            if "/systemd-private-" in path:
                continue
        elif path not in critical:
            continue
        seen.add(path)
        try:
            stats = os.statvfs(path)
        except OSError as exc:
            result.events.append(
                record(cadence, "filesystem", "filesystem_stat_failed", None, None, severity="warning", source="statvfs", device_id=f"mount:{path}", details={"mount_point": path}, outcome="error", error_message=type(exc).__name__)
            )
            continue
        total = stats.f_blocks * stats.f_frsize
        free = stats.f_bavail * stats.f_frsize
        if total <= 0:
            continue
        free_percent = free * 100.0 / total if total else 0.0
        severity = _disk_severity(config, free_percent, free, total)
        device_id, source_id = _filesystem_device_id(mount, path)
        details = {
            "mount_point": path,
            "filesystem": fstype,
            "read_only": "ro" in mount["options"].split(","),
            "filesystem_id": source_id,
            "filesystem_root": mount.get("root", "/"),
            "total_bytes": total,
            "free_bytes": free,
        }
        result.metrics.extend(
            [
                record(cadence, "filesystem", "filesystem.free_percent", round(free_percent, 4), "%", severity=severity, source="statvfs", device_id=device_id, details=details),
                record(cadence, "filesystem", "filesystem_free_bytes", free, "bytes", severity=severity, source="statvfs", device_id=device_id, details=details),
            ]
        )
        # FUSE implementations commonly report a synthetic zero inode count;
        # treating it as exhaustion creates an alert that cannot be meaningful.
        if stats.f_files > 0 and not fstype.startswith("fuse."):
            inode_percent = stats.f_favail * 100.0 / stats.f_files
            inode_warning = _threshold(config, (("thresholds", "inode", "warning_free_percent"), ("thresholds", "inode_free_percent", "warning")), 15)
            inode_critical = _threshold(config, (("thresholds", "inode", "critical_free_percent"), ("thresholds", "inode_free_percent", "critical")), 5)
            inode_severity = "critical" if inode_percent < inode_critical else "warning" if inode_percent < inode_warning else "info"
            result.metrics.extend(
                [
                    record(cadence, "filesystem", "filesystem.inode_free_percent", round(inode_percent, 4), "%", severity=inode_severity, source="statvfs", device_id=device_id, details=details),
                    record(cadence, "filesystem", "filesystem_inodes_free", stats.f_favail, "inodes", severity=inode_severity, source="statvfs", device_id=device_id, details=details),
                ]
            )
    return result


def _configured_service_sets(config: Mapping[str, Any]) -> tuple[set[str], set[str], set[str]]:
    def configured_units(value: Any) -> set[str]:
        if not isinstance(value, list):
            return set()
        units: set[str] = set()
        for item in value:
            if isinstance(item, str) and item.strip():
                units.add(item.strip())
            elif isinstance(item, Mapping) and isinstance(item.get("name"), str) and item["name"].strip():
                units.add(item["name"].strip())
        return units

    essential = configured_units(config_value(config, ("services", "essential"), default=[]))
    secondary = configured_units(config_value(config, ("services", "secondary"), default=[]))
    legacy = config_value(config, ("monitoring", "services"), default=[])
    if isinstance(legacy, list):
        for item in legacy:
            if isinstance(item, str):
                secondary.add(item)
            elif isinstance(item, Mapping) and item.get("name"):
                target = essential if item.get("essential") else secondary
                target.add(str(item["name"]))
    raw_patterns = config_value(config, ("services", "name_patterns"), default=["backup", "adb", "kuma", "megavault", "monitor"])
    patterns = {item.strip() for item in raw_patterns if isinstance(item, str) and item.strip()} if isinstance(raw_patterns, list) else set()
    return essential, secondary, patterns


def discover_services(config: Mapping[str, Any]) -> list[str]:
    essential, secondary, patterns = _configured_service_sets(config)
    auto_detect = bool(config_value(config, ("services", "auto_detect"), default=True))
    candidates = (_DEFAULT_SERVICES if auto_detect else set()) | {unit for unit in essential | secondary if not unit.startswith("user:")}
    listing = external(config, ["systemctl", "list-unit-files", "--type=service", "--all", "--no-legend", "--no-pager"])
    if listing.ok:
        states = {fields[0]: fields[1] for line in listing.stdout.splitlines() if len(fields := line.split()) >= 2 and fields[0].endswith(".service")}
        installed = {unit for unit in states if "@." not in unit}
        candidates &= installed
        if auto_detect:
            for unit in installed:
                lowered = unit.lower()
                if states.get(unit, "").startswith("enabled") and any(pattern.lower() in lowered for pattern in patterns):
                    candidates.add(unit)
            for unit_path in Path("/etc/systemd/system").glob("*.service"):
                try:
                    unit_text = unit_path.read_text(encoding="utf-8", errors="replace")[:65536]
                except OSError:
                    continue
                if "@." not in unit_path.name and "/home/daniele/MegaVault" in unit_text and unit_path.name in installed:
                    candidates.add(unit_path.name)
    return sorted(candidates)


def _discover_user_services(config: Mapping[str, Any], patterns: set[str]) -> list[str]:
    if not bool(config_value(config, ("services", "monitor_user"), default=True)):
        return []
    essential, secondary, _ = _configured_service_sets(config)
    explicit = {unit.removeprefix("user:") for unit in essential | secondary if unit.startswith("user:")}
    listing = operator_external(config, ["systemctl", "--user", "list-unit-files", "--type=service", "--all", "--no-legend", "--no-pager"])
    if not listing.ok:
        return sorted(explicit)
    states = {fields[0]: fields[1] for line in listing.stdout.splitlines() if len(fields := line.split()) >= 2 and fields[0].endswith(".service")}
    installed = set(states)
    candidates = explicit & installed
    for unit in installed:
        if states.get(unit, "").startswith("enabled") and any(pattern.lower() in unit.lower() for pattern in patterns):
            candidates.add(unit)
    return sorted(candidates)


def _parse_systemctl_show(output: str) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in output.splitlines() + [""]:
        if not line.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            current[key] = value
    return blocks


def collect_services(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    essential, _, patterns = _configured_service_sets(config)
    now = time.time()
    cached = state_get(db, "services.discovery", {})
    if isinstance(cached, Mapping) and now - _number(cached.get("time"), 0) < 3600:
        units = [str(unit) for unit in cached.get("system", [])]
        user_units = [str(unit) for unit in cached.get("user", [])]
    else:
        units = discover_services(config)
        user_units = _discover_user_services(config, patterns)
        state_set(db, "services.discovery", {"time": now, "system": units, "user": user_units})
    if not units and not user_units:
        result.metrics.append(record(cadence, "service", "monitored_service_count", 0, "services", source="systemd"))
        return result

    properties = "--property=Id,LoadState,ActiveState,SubState,UnitFileState,Type,Result,NRestarts,Triggers"
    blocks: list[tuple[dict[str, str], str]] = []
    if units:
        status = external(config, ["systemctl", "show", properties, "--", *units])
        if status.ok:
            blocks.extend((item, "system") for item in _parse_systemctl_show(status.stdout))
        else:
            result.errors.append(f"systemd: {command_problem(status)}")
    if user_units:
        user_status = operator_external(config, ["systemctl", "--user", "show", properties, "--", *user_units])
        if user_status.ok:
            blocks.extend((item, "user") for item in _parse_systemctl_show(user_status.stdout))
        else:
            result.errors.append(f"user systemd: {command_problem(user_status)}")

    failed_count = 0
    previous_runtime = state_get(db, "services.runtime", {})
    previous_runtime = previous_runtime if isinstance(previous_runtime, Mapping) else {}
    current_runtime: dict[str, Any] = {}
    loop_count = int(_threshold(config, (("thresholds", "services", "restart_loop_count"),), 3))
    loop_window = _threshold(config, (("thresholds", "services", "restart_loop_window_minutes"),), 15) * 60
    for item, unit_scope in blocks:
        unit = item.get("Id")
        if not unit:
            continue
        state_id = unit if unit_scope == "system" else f"user:{unit}"
        is_essential = state_id in essential or unit in essential
        active = item.get("ActiveState") == "active"
        failed = item.get("ActiveState") == "failed" or item.get("Result") not in {"", "success"}
        successful_oneshot = item.get("Type") == "oneshot" and item.get("Result") in {"", "success"} and item.get("ActiveState") == "inactive"
        restart_count = int(item.get("NRestarts") or 0)
        old = previous_runtime.get(state_id, {})
        old = old if isinstance(old, Mapping) else {}
        restart_times = [float(value) for value in old.get("restart_times", []) if _number(value, 0) >= now - loop_window] if isinstance(old.get("restart_times", []), list) else []
        delta_restarts = max(0, restart_count - int(old.get("restart_count", restart_count)))
        restart_times.extend([now] * min(delta_restarts, loop_count + 1))
        restart_loop = len(restart_times) >= loop_count
        severity = "info"
        if failed:
            severity = "critical" if is_essential else "warning"
            failed_count += 1
        elif is_essential and not active and not successful_oneshot:
            severity = "critical"
        if restart_loop:
            severity = "critical"
        result.metrics.append(
            record(
                cadence,
                "service",
                "service.active",
                1 if active else 0,
                "boolean",
                severity=severity,
                source="systemd",
                device_id=state_id,
                details={
                    "unit": unit,
                    "scope": unit_scope,
                    "load_state": item.get("LoadState"),
                    "active_state": item.get("ActiveState"),
                    "sub_state": item.get("SubState"),
                    "unit_file_state": item.get("UnitFileState"),
                    "type": item.get("Type"),
                    "result": item.get("Result"),
                    "restart_count": restart_count,
                    "restart_count_window": len(restart_times),
                    "restart_loop": restart_loop,
                    "successful_inactive_oneshot": successful_oneshot,
                    "importance": "essential" if is_essential else "secondary",
                },
            )
        )
        result.metrics.append(record(cadence, "service", "service.restart_count_window", len(restart_times), "restarts", severity="critical" if restart_loop else "info", source="systemd", device_id=state_id, details={"unit": unit, "scope": unit_scope, "window_seconds": loop_window}))
        if delta_restarts and active:
            result.events.append(record(cadence, "service", "service_restarted", delta_restarts, "restarts", source="systemd", device_id=state_id, details={"unit": unit, "scope": unit_scope, "restart_count": restart_count}, outcome="recovered"))
        if old.get("active_state") == "failed" and active:
            result.events.append(record(cadence, "service", "service_recovered", 1, "event", source="systemd", device_id=state_id, details={"unit": unit, "scope": unit_scope}, outcome="recovered"))
        current_runtime[state_id] = {"active_state": item.get("ActiveState"), "restart_count": restart_count, "restart_times": restart_times}
    state_set(db, "services.runtime", current_runtime)
    result.metrics.append(record(cadence, "service", "monitored_service_count", len(units) + len(user_units), "services", source="systemd", details={"system": len(units), "user": len(user_units)}))
    result.metrics.append(
        record(cadence, "service", "failed_service_count", failed_count, "services", severity="warning" if failed_count else "info", source="systemd")
    )
    return result


def _nmcli_sections(output: str) -> list[dict[str, str]]:
    sections: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in output.splitlines() + [""]:
        if not line.strip():
            if current:
                sections.append(current)
                current = {}
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current[key] = value.replace("\\:", ":")
    return sections


def _network_manager_snapshot(config: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    result = external(
        config,
        ["nmcli", "-t", "-f", "GENERAL.DEVICE,GENERAL.TYPE,GENERAL.STATE,GENERAL.CONNECTION,IP4.ADDRESS,IP4.GATEWAY", "device", "show"],
    )
    if not result.ok:
        return {}, command_problem(result)
    snapshot: dict[str, Any] = {"connected": False, "device": None, "ssid": None, "ip": None, "gateway": None}
    for section in _nmcli_sections(result.stdout):
        if section.get("GENERAL.TYPE") != "wifi":
            continue
        if section.get("GENERAL.STATE", "").startswith("100"):
            snapshot.update(
                {
                    "connected": True,
                    "device": section.get("GENERAL.DEVICE"),
                    "ssid": section.get("GENERAL.CONNECTION") or None,
                    "ip": next((value for key, value in section.items() if key.startswith("IP4.ADDRESS")), None),
                    "gateway": section.get("IP4.GATEWAY") or None,
                }
            )
            break
    general = external(config, ["nmcli", "-t", "-f", "STATE,CONNECTIVITY", "general"])
    if general.ok:
        fields = general.stdout.strip().split(":", 1)
        snapshot["network_state"] = fields[0] if fields else "unknown"
        snapshot["connectivity"] = fields[1] if len(fields) > 1 else "unknown"
    return snapshot, None


def _duration_severity(
    db: object,
    key: str,
    failing: bool,
    threshold: float,
    *,
    cadence: int,
    now: float,
) -> str:
    state = state_get(db, key, {})
    if not isinstance(state, Mapping):
        state = {}
    last = _number(state.get("last"), now)
    since = _number(state.get("since"), now)
    if now - last > cadence * 2.5:
        since = now
    if not failing:
        state_set(db, key, {})
        return "info"
    if not state:
        since = now
    state_set(db, key, {"since": since, "last": now})
    return "warning" if now - since >= threshold else "info"


def _network_transition_events(
    scope: str,
    db: object,
    snapshot: Mapping[str, Any],
) -> list[dict[str, Any]]:
    cadence = CADENCE_SECONDS[scope]
    previous = state_get(db, "network.snapshot", None)
    state_set(db, "network.snapshot", dict(snapshot))
    if not isinstance(previous, Mapping):
        return []
    events: list[dict[str, Any]] = []
    was_connected = bool(previous.get("connected"))
    connected = bool(snapshot.get("connected"))
    if was_connected != connected:
        name = "wifi_connected" if connected else "wifi_disconnected"
        events.append(record(cadence, "network", name, 1, "event", source="NetworkManager", device_id=str(snapshot.get("device") or previous.get("device") or "wifi"), details={"ssid": snapshot.get("ssid") if connected else previous.get("ssid")}, outcome="detected"))
        if not connected:
            history = state_get(db, "network.disconnect_times", [])
            history = list(history) if isinstance(history, list) else []
            history.append(time.time())
            state_set(db, "network.disconnect_times", history[-100:])
    had_gateway = bool(previous.get("gateway"))
    has_gateway = bool(snapshot.get("gateway"))
    if had_gateway != has_gateway:
        events.append(record(cadence, "network", "gateway_recovered" if has_gateway else "gateway_lost", 1, "event", severity="info" if has_gateway else "warning", source="NetworkManager", device_id="default_gateway", details={"wifi_connected": connected}, outcome="recovered" if has_gateway else "detected"))
    if previous.get("network_state") and snapshot.get("network_state") and previous.get("network_state") != snapshot.get("network_state"):
        events.append(record(cadence, "network", "networkmanager_state_changed", 1, "event", source="NetworkManager", details={"old": previous.get("network_state"), "new": snapshot.get("network_state")}, outcome="detected"))
    for key, event_name in (("ssid", "wifi_ssid_changed"), ("ip", "network_ip_changed"), ("device", "network_interface_changed")):
        if connected and previous.get(key) and snapshot.get(key) and previous.get(key) != snapshot.get(key):
            details = {"old": previous.get(key), "new": snapshot.get(key)}
            events.append(record(cadence, "network", event_name, 1, "event", source="NetworkManager", device_id=str(snapshot.get("device") or "wifi"), details=details, outcome="detected"))
    return events


def _internet_probe(config: Mapping[str, Any]) -> tuple[bool, float | None, str | None]:
    enabled = bool(config_value(config, ("collection", "internet_check_enabled"), default=True))
    if not enabled:
        return True, None, "disabled"
    host = str(config_value(config, ("collection", "internet_host"), ("collection", "internet_probe_host"), default="1.1.1.1"))
    port = int(_number(config_value(config, ("collection", "internet_port"), default=443), 443))
    timeout = _number(config_value(config, ("collection", "internet_timeout_seconds"), ("collection", "internet_probe_timeout_seconds"), default=2), 2)
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return True, (time.monotonic() - started) * 1000, None
    except OSError as exc:
        return False, None, type(exc).__name__


def collect_network_essential(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    snapshot, error = _network_manager_snapshot(config)
    if error:
        result.errors.append(f"NetworkManager: {error}")
        result.events.append(record(cadence, "network", "network_status_unavailable", None, None, severity="warning", source="NetworkManager", outcome="error", error_message=error))
    else:
        now = time.time()
        wifi_threshold = _threshold(config, (("thresholds", "network", "wifi_down_duration_seconds"), ("thresholds", "wifi_disconnected_seconds")), 120)
        wifi_severity = _duration_severity(db, "condition.wifi_down", not bool(snapshot.get("connected")), wifi_threshold, cadence=cadence, now=now)
        # This is host Wi-Fi health, not per-interface inventory.  A stable key
        # is required so a reconnect on wlp* can recover an alert opened while
        # NetworkManager had no active interface name.
        result.metrics.append(record(cadence, "network", "wifi.connected", 1 if snapshot.get("connected") else 0, "boolean", severity=wifi_severity, source="NetworkManager", device_id="wifi", details={"ssid": snapshot.get("ssid"), "interface": snapshot.get("device")}))
        connectivity_values = {"unknown": 0, "none": 0, "portal": 1, "limited": 2, "full": 4}
        connectivity = str(snapshot.get("connectivity") or "unknown")
        result.metrics.append(record(cadence, "network", "networkmanager_connectivity", connectivity_values.get(connectivity, 0), "state", source="NetworkManager", details={"state": connectivity}))
        result.events.extend(_network_transition_events(scope, db, snapshot))

    reachable, latency, probe_error = _internet_probe(config)
    if probe_error != "disabled":
        now = time.time()
        threshold = _threshold(config, (("thresholds", "network", "internet_down_duration_seconds"), ("thresholds", "internet_unreachable_seconds")), 180)
        severity = _duration_severity(db, "condition.internet_down", not reachable, threshold, cadence=cadence, now=now)
        result.metrics.append(record(cadence, "network", "network.internet_reachable", 1 if reachable else 0, "boolean", severity=severity, source="tcp_probe", outcome="ok" if reachable else "error", error_message=probe_error))
        if latency is not None:
            result.metrics.append(record(cadence, "network", "internet_connect_latency_ms", round(latency, 3), "ms", source="tcp_probe"))
    return result


def collect_power(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    del config, db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    root = SYS_ROOT / "class" / "power_supply"
    if not root.exists():
        return result
    for supply in sorted(root.iterdir()):
        supply_type = _read(supply / "type").strip()
        if supply_type == "Battery":
            present = _read(supply / "present", "1").strip() != "0"
            capacity = _number(_read(supply / "capacity").strip(), math.nan)
            status = _read(supply / "status").strip() or "unknown"
            if math.isfinite(capacity):
                result.metrics.append(record(cadence, "power", "battery_charge_percent", capacity, "%", source="sysfs", device_id=supply.name, details={"status": status, "present": present}))
            result.metrics.append(record(cadence, "power", "battery_present", 1 if present else 0, "boolean", source="sysfs", device_id=supply.name))
            scaled_metrics = (
                ("energy_now", "battery_energy_wh", 1_000_000, "Wh"),
                ("power_now", "battery_power_w", 1_000_000, "W"),
                ("voltage_now", "battery_voltage_v", 1_000_000, "V"),
            )
            for filename, name, divisor, unit in scaled_metrics:
                raw = _number(_read(supply / filename).strip(), math.nan)
                if math.isfinite(raw):
                    result.metrics.append(record(cadence, "power", name, round(raw / divisor, 3), unit, source="sysfs", device_id=supply.name))
            temperature = _number(_read(supply / "temp").strip(), math.nan)
            if math.isfinite(temperature):
                temperature_c = temperature / 10 if temperature > 200 else temperature
                severity = "critical" if temperature_c >= 60 else "warning" if temperature_c >= 50 else "info"
                result.metrics.append(record(cadence, "power", "battery_temperature_c", round(temperature_c, 3), "C", severity=severity, source="sysfs", device_id=supply.name))
        elif supply_type in {"Mains", "USB", "USB_C"}:
            online = _read(supply / "online").strip()
            if online in {"0", "1"}:
                result.metrics.append(record(cadence, "power", "external_power_online", int(online), "boolean", source="sysfs", device_id=supply.name, details={"type": supply_type}))
    return result


def collect_network_detail(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    current_time = time.time()
    counters: dict[str, dict[str, int]] = {}
    for line in _read(PROC_ROOT / "net" / "dev").splitlines()[2:]:
        if ":" not in line:
            continue
        interface, raw = line.split(":", 1)
        interface = interface.strip()
        if interface == "lo":
            continue
        fields = raw.split()
        if len(fields) < 16:
            continue
        counters[interface] = {"rx": int(fields[0]), "tx": int(fields[8])}
    previous = state_get(db, "network.counters", {})
    previous_time = _number(previous.get("time"), current_time) if isinstance(previous, Mapping) else current_time
    previous_counters = previous.get("interfaces", {}) if isinstance(previous, Mapping) else {}
    elapsed = current_time - previous_time
    for interface, values in counters.items():
        result.metrics.extend(
            [
                record(cadence, "network", "interface_rx_bytes", values["rx"], "bytes", source="procfs", device_id=interface),
                record(cadence, "network", "interface_tx_bytes", values["tx"], "bytes", source="procfs", device_id=interface),
            ]
        )
        old = previous_counters.get(interface) if isinstance(previous_counters, Mapping) else None
        if isinstance(old, Mapping) and elapsed > 0 and values["rx"] >= int(old.get("rx", 0)) and values["tx"] >= int(old.get("tx", 0)):
            result.metrics.extend(
                [
                    record(cadence, "network", "interface_download_bytes_per_second", round((values["rx"] - int(old["rx"])) / elapsed, 3), "bytes/s", source="procfs", device_id=interface, details={"sample_seconds": round(elapsed, 3)}),
                    record(cadence, "network", "interface_upload_bytes_per_second", round((values["tx"] - int(old["tx"])) / elapsed, 3), "bytes/s", source="procfs", device_id=interface, details={"sample_seconds": round(elapsed, 3)}),
                ]
            )
    state_set(db, "network.counters", {"time": current_time, "interfaces": counters})

    snapshot, error = _network_manager_snapshot(config)
    if not error:
        result.events.extend(_network_transition_events(scope, db, snapshot))
        for key, name in (("ip", "wifi_ipv4_present"), ("gateway", "default_gateway_present")):
            result.metrics.append(record(cadence, "network", name, 1 if snapshot.get(key) else 0, "boolean", source="NetworkManager", device_id=str(snapshot.get("device") or "wifi"), details={key: snapshot.get(key)}))
        wifi = external(config, ["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,RATE", "device", "wifi", "list", "--rescan", "no"])
        if wifi.ok:
            for line in wifi.stdout.splitlines():
                fields = line.split(":")
                if fields and fields[0] in {"*", "yes"} and len(fields) >= 4:
                    try:
                        result.metrics.append(record(cadence, "network", "wifi_signal_percent", float(fields[-2]), "%", source="NetworkManager", device_id=str(snapshot.get("device") or "wifi"), details={"ssid": snapshot.get("ssid")}))
                        bitrate_match = re.search(r"([0-9.]+)", fields[-1])
                        if bitrate_match:
                            result.metrics.append(record(cadence, "network", "wifi_bitrate_mbps", float(bitrate_match.group(1)), "Mbit/s", source="NetworkManager", device_id=str(snapshot.get("device") or "wifi")))
                    except ValueError:
                        pass
                    break
        gateway = snapshot.get("gateway")
        if gateway:
            timeout_seconds = max(1, int(_number(config_value(config, ("collection", "gateway_ping_timeout_seconds"), default=2), 2)))
            ping = external(config, ["ping", "-n", "-c", "1", "-W", str(timeout_seconds), str(gateway)], timeout=timeout_seconds + 1)
            match = re.search(r"time[=<]([0-9.]+)\s*ms", ping.stdout)
            reachable = ping.returncode == 0
            result.metrics.append(record(cadence, "network", "network.gateway_reachable", 1 if reachable else 0, "boolean", severity="warning" if snapshot.get("connected") and not reachable else "info", source="ping", device_id="default_gateway", details={"wifi_connected": bool(snapshot.get("connected"))}, outcome="ok" if reachable else "error"))
            if match:
                result.metrics.append(record(cadence, "network", "gateway_latency_ms", float(match.group(1)), "ms", source="ping", device_id="default_gateway"))
    elif error:
        result.errors.append(f"NetworkManager: {error}")
    reachable, latency, probe_error = _internet_probe(config)
    if probe_error != "disabled":
        result.metrics.append(record(cadence, "network", "network.internet_reachable", 1 if reachable else 0, "boolean", severity="warning" if not reachable else "info", source="tcp_probe", outcome="ok" if reachable else "error", error_message=probe_error))
        if latency is not None:
            result.metrics.append(record(cadence, "network", "internet_connect_latency_ms", round(latency, 3), "ms", source="tcp_probe"))
    return result


def collect_temperatures(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    hwmon_root = SYS_ROOT / "class" / "hwmon"
    if not hwmon_root.exists():
        return result
    cpu_warning = _threshold(config, (("thresholds", "temperature", "cpu_warning_c"), ("thresholds", "cpu_temperature_c", "warning")), 90)
    cpu_critical = _threshold(config, (("thresholds", "temperature", "cpu_critical_c"), ("thresholds", "cpu_temperature_c", "critical")), 95)
    cpu_duration = _threshold(config, (("thresholds", "temperature", "cpu_warning_duration_seconds"), ("thresholds", "cpu_temperature_c", "warning_duration_seconds")), 300)
    nvme_warning = _threshold(config, (("thresholds", "temperature", "nvme_warning_c"), ("thresholds", "nvme_temperature_c", "warning")), 70)
    nvme_critical = _threshold(config, (("thresholds", "temperature", "nvme_critical_c"), ("thresholds", "nvme_temperature_c", "critical")), 80)
    seen: set[tuple[str, str]] = set()
    for hwmon in sorted(hwmon_root.glob("hwmon*")):
        chip = _read(hwmon / "name").strip() or hwmon.name
        for input_path in sorted(hwmon.glob("temp*_input")):
            match = re.match(r"temp(\d+)_input", input_path.name)
            if not match:
                continue
            index = match.group(1)
            raw = _read(input_path).strip()
            try:
                temperature = float(raw) / 1000.0
            except ValueError:
                continue
            if temperature <= -100 or temperature > 250:
                continue
            label = _read(hwmon / f"temp{index}_label").strip() or f"sensor_{index}"
            identity = (chip, label)
            if identity in seen:
                continue
            seen.add(identity)
            alarm = _read(hwmon / f"temp{index}_alarm").strip() == "1" or _read(hwmon / f"temp{index}_max_alarm").strip() == "1"
            sensor_type = "temperature"
            severity = "warning" if alarm else "info"
            if chip == "k10temp" or label.lower() in {"tctl", "tdie", "cpu"}:
                sensor_type = "temperature.cpu_c"
                severity = sustained_severity(db, f"condition.temperature.{chip}.{label}", temperature, warning=cpu_warning, critical=cpu_critical, duration_seconds=cpu_duration)
            elif chip == "nvme" or "nvme" in chip:
                sensor_type = "temperature.nvme_c"
                severity = "critical" if temperature >= nvme_critical else "warning" if temperature >= nvme_warning else severity
            hardware_critical = _number(_read(hwmon / f"temp{index}_crit").strip(), math.nan) / 1000.0
            details: dict[str, Any] = {"chip": chip, "sensor": label, "alarm": alarm}
            if math.isfinite(hardware_critical):
                details["hardware_critical_c"] = hardware_critical
                if temperature >= hardware_critical:
                    severity = "critical"
            result.metrics.append(record(cadence, "temperature", sensor_type, round(temperature, 3), "C", severity=severity, source="hwmon", device_id=f"{chip}:{label}", details=details))
            result.metrics.append(record(cadence, "temperature", "sensor.alarm", 1 if alarm else 0, "boolean", severity="warning" if alarm else "info", source="hwmon", device_id=f"{chip}:{label}", details={"chip": chip, "sensor": label}))
    return result


def collect_processes(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    del db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    limit = max(1, int(_number(config_value(config, ("collection", "top_process_limit"), default=5), 5)))
    process_list = external(config, ["ps", "-eo", "pid=,user=,comm=,%cpu=,%mem=,stat=", "--sort=-%cpu"], max_output=1_000_000)
    if not process_list.ok:
        result.errors.append(f"processes: {command_problem(process_list)}")
        return result
    processes: list[dict[str, Any]] = []
    for line in process_list.stdout.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6:
            continue
        try:
            processes.append({"pid": int(fields[0]), "user": fields[1], "executable": fields[2], "cpu_percent": float(fields[3]), "memory_percent": float(fields[4]), "state": fields[5][:1]})
        except ValueError:
            continue
    top_cpu = sorted(processes, key=lambda item: item["cpu_percent"], reverse=True)[:limit]
    top_memory = sorted(processes, key=lambda item: item["memory_percent"], reverse=True)[:limit]
    zombies = sum(item["state"] == "Z" for item in processes)
    result.metrics.extend(
        [
            record(cadence, "process", "process_count", len(processes), "processes", source="procps"),
            record(cadence, "process", "zombie_process_count", zombies, "processes", severity="warning" if zombies else "info", source="procps"),
            record(cadence, "process", "top_cpu_process_count", len(top_cpu), "processes", source="procps", details={"processes": top_cpu}),
            record(cadence, "process", "top_memory_process_count", len(top_memory), "processes", source="procps", details={"processes": top_memory}),
        ]
    )
    file_nr = _read(PROC_ROOT / "sys" / "fs" / "file-nr").split()
    if len(file_nr) >= 3:
        try:
            used = max(0, int(file_nr[0]) - int(file_nr[1]))
            result.metrics.append(record(cadence, "process", "global_file_descriptors_used", used, "descriptors", source="procfs", details={"maximum": int(file_nr[2])}))
        except ValueError:
            pass
    return result


def _block_device_id(name: str) -> str:
    base = SYS_ROOT / "class" / "block" / name
    serial = _read(base / "device" / "serial").strip()
    model = _read(base / "device" / "model").strip()
    if serial:
        return stable_hash(serial, "disk")
    if model:
        return stable_hash(f"{model}:{name}", "disk")
    return f"block:{name}"


def collect_diskstats(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    del config
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    current_time = time.time()
    current: dict[str, dict[str, int]] = {}
    for line in _read(PROC_ROOT / "diskstats").splitlines():
        fields = line.split()
        if len(fields) < 14:
            continue
        name = fields[2]
        if name.startswith(("loop", "ram", "zram", "dm-")) or (SYS_ROOT / "class" / "block" / name / "partition").exists():
            continue
        try:
            current[name] = {
                "reads": int(fields[3]), "sectors_read": int(fields[5]), "read_ms": int(fields[6]),
                "writes": int(fields[7]), "sectors_written": int(fields[9]), "write_ms": int(fields[10]),
                "io_ms": int(fields[12]), "weighted_ms": int(fields[13]),
            }
        except ValueError:
            continue
    previous = state_get(db, "diskstats", {})
    previous_time = _number(previous.get("time"), current_time) if isinstance(previous, Mapping) else current_time
    old_devices = previous.get("devices", {}) if isinstance(previous, Mapping) else {}
    elapsed = current_time - previous_time
    for name, values in current.items():
        device_id = _block_device_id(name)
        details = {"kernel_name": name, "sample_seconds": round(elapsed, 3)}
        result.metrics.extend(
            [
                record(cadence, "disk_io", "disk_reads_completed", values["reads"], "operations", source="procfs", device_id=device_id, details=details),
                record(cadence, "disk_io", "disk_writes_completed", values["writes"], "operations", source="procfs", device_id=device_id, details=details),
            ]
        )
        old = old_devices.get(name) if isinstance(old_devices, Mapping) else None
        if not isinstance(old, Mapping) or elapsed <= 0:
            continue
        deltas = {key: values[key] - int(old.get(key, values[key])) for key in values}
        if any(value < 0 for value in deltas.values()):
            continue
        operations = deltas["reads"] + deltas["writes"]
        result.metrics.extend(
            [
                record(cadence, "disk_io", "disk_read_bytes_per_second", round(deltas["sectors_read"] * 512 / elapsed, 3), "bytes/s", source="procfs", device_id=device_id, details=details),
                record(cadence, "disk_io", "disk_write_bytes_per_second", round(deltas["sectors_written"] * 512 / elapsed, 3), "bytes/s", source="procfs", device_id=device_id, details=details),
                record(cadence, "disk_io", "disk_iops", round(operations / elapsed, 3), "operations/s", source="procfs", device_id=device_id, details=details),
                record(cadence, "disk_io", "disk_busy_percent", round(min(100.0, deltas["io_ms"] / (elapsed * 10)), 3), "%", source="procfs", device_id=device_id, details=details),
            ]
        )
        if operations:
            result.metrics.append(record(cadence, "disk_io", "disk_await_ms", round((deltas["read_ms"] + deltas["write_ms"]) / operations, 3), "ms", source="procfs", device_id=device_id, details=details))
    state_set(db, "diskstats", {"time": current_time, "devices": current})
    return result


_JOURNAL_PATTERNS = (
    (re.compile(r"\b(?:Buffer )?I/O error\b|blk_update_request", re.I), "kernel_io_error", "critical"),
    (re.compile(r"Remounting filesystem.*read-only|re-mounted.*read-only", re.I), "filesystem_remounted_read_only", "critical"),
    (re.compile(r"\b(?:USB|usb).*\breset\b", re.I), "usb_reset", "warning"),
    (re.compile(r"\bnvme\b.*\b(?:error|reset|timeout)\b", re.I), "nvme_error", "critical"),
)


def collect_journal_io(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    lookback = max(1, int(_number(config_value(config, ("collection", "journal_lookback_minutes"), default=20), 20)))
    journal = external(config, ["journalctl", "-b", "_TRANSPORT=kernel", f"--since=-{lookback}min", "--no-pager", "-q", "-o", "json"], max_output=2_000_000)
    if not journal.ok:
        result.errors.append(f"journal: {command_problem(journal)}")
        return result
    seen = state_get(db, "journal.io.seen", [])
    seen_set = set(seen) if isinstance(seen, list) else set()
    new_seen = list(seen_set)
    for line in journal.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = str(entry.get("MESSAGE", ""))
        matched = next(((name, severity) for pattern, name, severity in _JOURNAL_PATTERNS if pattern.search(message)), None)
        if not matched:
            continue
        cursor = str(entry.get("__CURSOR") or stable_hash(f"{entry.get('__REALTIME_TIMESTAMP')}:{message}", "journal"))
        if cursor in seen_set:
            continue
        new_seen.append(cursor)
        name, severity = matched
        device = re.search(r"\b(?:sd[a-z][0-9]*|nvme\d+n\d+(?:p\d+)?|dm-\d+)\b", message)
        result.events.append(
            record(
                cadence,
                "storage",
                name,
                1,
                "event",
                severity=severity,
                source="kernel_journal",
                device_id=f"kernel:{device.group(0)}" if device else None,
                details={
                    "boot_id": entry.get("_BOOT_ID"),
                    "journal_cursor": cursor,
                    "monotonic_usec": entry.get("__MONOTONIC_TIMESTAMP"),
                    "kernel_device": device.group(0) if device else None,
                },
                outcome="detected",
            )
        )
    state_set(db, "journal.io.seen", new_seen[-1000:])
    return result


def collect_network_stability(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    window_minutes = _threshold(config, (("thresholds", "network", "disconnect_window_minutes"),), 30)
    threshold = int(_threshold(config, (("thresholds", "network", "disconnect_count"), ("thresholds", "wifi_disconnect_count")), 3))
    cutoff = time.time() - window_minutes * 60
    history = state_get(db, "network.disconnect_times", [])
    recent = [float(value) for value in history if _number(value, 0) >= cutoff] if isinstance(history, list) else []
    state_set(db, "network.disconnect_times", recent)
    journal_count = 0
    journal = external(config, ["journalctl", "-u", "NetworkManager.service", f"--since=-{int(window_minutes)}min", "--no-pager", "-q", "-o", "json"], max_output=1_000_000)
    if journal.ok:
        transition = re.compile(r"device \([^)]+\): state change: (?:activated|deactivating) -> (?:disconnected|unavailable|failed)", re.I)
        for line in journal.stdout.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if transition.search(str(entry.get("MESSAGE", ""))):
                journal_count += 1
    disconnect_count = max(len(recent), journal_count)
    result.metrics.append(record(cadence, "network", "wifi_disconnects_in_window", disconnect_count, "disconnects", severity="warning" if disconnect_count >= threshold else "info", source="NetworkManager_journal", details={"window_minutes": window_minutes, "state_count": len(recent), "journal_count": journal_count}))

    active = external(config, ["nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"])
    vpn_items: list[dict[str, str]] = []
    if active.ok:
        for line in active.stdout.splitlines():
            fields = line.split(":")
            if len(fields) >= 3 and fields[1].lower() in {"vpn", "wireguard", "tun"}:
                vpn_items.append({"type": fields[1], "device": fields[2]})
    vpn_state = sorted(vpn_items, key=lambda item: (item["type"], item["device"]))
    previous = state_get(db, "network.vpn", None)
    state_set(db, "network.vpn", vpn_state)
    result.metrics.append(record(cadence, "network", "vpn_connection_count", len(vpn_state), "connections", source="NetworkManager", details={"connections": vpn_state}))
    if isinstance(previous, list) and previous != vpn_state:
        result.events.append(record(cadence, "network", "vpn_state_changed", 1, "event", source="NetworkManager", details={"connected_count": len(vpn_state)}, outcome="detected"))
    return result


def _flatten_lsblk(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for node in nodes:
        flattened.append(node)
        children = node.get("children")
        if isinstance(children, list):
            flattened.extend(_flatten_lsblk(children))
    return flattened


def collect_expected_mounts(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    del db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    expected = config_value(config, ("storage", "expected_devices"), ("monitoring", "expected_disks"), default=[])
    if not isinstance(expected, list) or not expected:
        return result
    listing = external(config, ["lsblk", "-J", "-b", "-o", "NAME,TYPE,MODEL,LABEL,UUID,MOUNTPOINTS"])
    if not listing.ok:
        result.errors.append(f"expected mounts: {command_problem(listing)}")
        return result
    try:
        nodes = _flatten_lsblk(json.loads(listing.stdout).get("blockdevices", []))
    except (json.JSONDecodeError, AttributeError):
        nodes = []
    for configured in expected:
        if isinstance(configured, str):
            identifier = configured
            required = True
        elif isinstance(configured, Mapping):
            identifier = str(configured.get("uuid") or configured.get("label") or configured.get("model") or configured.get("id") or "")
            required = bool(configured.get("required", True))
        else:
            continue
        present = False
        mounted = False
        for node in nodes:
            values = {str(node.get(key) or "") for key in ("uuid", "label", "model", "name")}
            if identifier in values or any(identifier and identifier.lower() in value.lower() for value in values):
                present = True
                mounts = node.get("mountpoints") or []
                mounted = bool([value for value in mounts if value])
                break
        severity = "warning" if required and (not present or not mounted) else "info"
        result.metrics.append(record(cadence, "storage", "expected_device_mounted", 1 if present and mounted else 0, "boolean", severity=severity, source="lsblk", device_id=stable_hash(identifier, "expected"), details={"present": present, "mounted": mounted, "required": required}))
    return result


def collect_backup_processes(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    del db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    listing = external(config, ["ps", "-eo", "pid=,user=,comm=,unit="])
    if not listing.ok:
        return result
    names = {"restic", "borg", "borgmatic", "rclone", "rsync", "cp", "dd", "tar", "duplicity"}
    processes: list[dict[str, Any]] = []
    for line in listing.stdout.splitlines():
        fields = line.split(None, 3)
        if len(fields) < 3 or fields[2].lower() not in names:
            continue
        try:
            process = {"pid": int(fields[0]), "user": fields[1], "executable": fields[2]}
        except ValueError:
            continue
        if len(fields) == 4 and fields[3] != "-":
            process["unit"] = fields[3]
        processes.append(process)
    result.metrics.append(record(cadence, "backup", "copy_or_backup_process_count", len(processes), "processes", source="procps", details={"processes": processes[:20], "truncated": len(processes) > 20}))
    return result


__all__ = [
    "collect_backup_processes",
    "collect_diskstats",
    "collect_expected_mounts",
    "collect_filesystems",
    "collect_journal_io",
    "collect_network_detail",
    "collect_network_essential",
    "collect_network_stability",
    "collect_power",
    "collect_proc",
    "collect_processes",
    "collect_services",
    "collect_temperatures",
    "discover_services",
    "mount_table",
]
