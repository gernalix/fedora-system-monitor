"""Hourly health, daily hardware, and weekly diagnostic collectors."""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
import os
from pathlib import Path
import re
import shutil
import time
from typing import Any

from ..config import validate_config

from .common import (
    command_problem,
    config_value,
    external,
    fingerprint,
    stable_hash,
    state_get,
    state_set,
)
from .model import CADENCE_SECONDS, CollectionResult, record
from .periodic import PROC_ROOT, SYS_ROOT


def _read(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _flatten_block(nodes: list[dict[str, Any]], parent: str | None = None) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for original in nodes:
        node = dict(original)
        node["parent"] = parent
        flattened.append(node)
        children = node.get("children")
        if isinstance(children, list):
            flattened.extend(_flatten_block(children, str(node.get("name") or parent or "")))
    return flattened


def _block_listing(config: Mapping[str, Any], *, include_serial: bool = False) -> tuple[list[dict[str, Any]], str | None]:
    columns = "NAME,PATH,TYPE,TRAN,SIZE,RO,RM,HOTPLUG,MODEL,VENDOR,FSTYPE,LABEL,UUID,MOUNTPOINTS"
    if include_serial:
        columns += ",SERIAL,WWN"
    output = external(config, ["lsblk", "-J", "-b", "-o", columns], timeout=20, max_output=2_000_000)
    if not output.ok:
        return [], command_problem(output)
    try:
        payload = json.loads(output.stdout)
        nodes = payload.get("blockdevices", []) if isinstance(payload, Mapping) else []
        return _flatten_block(nodes if isinstance(nodes, list) else []), None
    except json.JSONDecodeError:
        return [], "invalid JSON"


def _stable_block_id(node: Mapping[str, Any]) -> str:
    uuid = str(node.get("uuid") or "")
    if uuid:
        return f"fsuuid:{uuid}"
    serial = str(node.get("serial") or node.get("wwn") or "")
    if serial:
        return stable_hash(serial, "disk")
    basis = f"{node.get('vendor')}:{node.get('model')}:{node.get('size')}:{node.get('type')}"
    return stable_hash(basis, "block")


def _smart_messages(messages: object) -> list[str]:
    if not isinstance(messages, list):
        return []
    output: list[str] = []
    for message in messages[:8]:
        if not isinstance(message, Mapping):
            continue
        text = str(message.get("string") or "").strip()
        if text:
            output.append(text[:300])
    return output


def _smart_diagnostics(
    node: Mapping[str, Any],
    command: list[str],
    health: object,
    payload: object,
    messages: object,
) -> dict[str, Any]:
    smartctl_data = payload.get("smartctl") if isinstance(payload, Mapping) else None
    device_data = payload.get("device") if isinstance(payload, Mapping) else None
    return {
        "model": node.get("model"),
        "transport": node.get("tran"),
        "command": list(smartctl_data.get("argv", command))[:20] if isinstance(smartctl_data, Mapping) else command,
        "exit_status": int(_float(smartctl_data.get("exit_status"), getattr(health, "returncode", 0))) if isinstance(smartctl_data, Mapping) else int(getattr(health, "returncode", 0)),
        "messages": _smart_messages(messages),
        "device_type": device_data.get("type") if isinstance(device_data, Mapping) else None,
        "protocol": device_data.get("protocol") if isinstance(device_data, Mapping) else None,
    }


def _smart_failure_class(health: object, message_text: str, device: str) -> str:
    if bool(getattr(health, "missing", False)):
        return "command_unavailable"
    if bool(getattr(health, "timed_out", False)):
        return "timeout"
    if not Path(device).exists():
        return "device_absent"
    if re.search(r"permission denied|operation not permitted", message_text, re.I):
        return "permission"
    if re.search(r"device open failed|no such device|cannot open", message_text, re.I):
        return "device_open"
    return "smart_command"


def collect_smart(
    scope: str,
    config: Mapping[str, Any],
    db: object,
    *,
    detailed: bool,
) -> CollectionResult:
    del db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    nodes, error = _block_listing(config, include_serial=True)
    if error:
        result.errors.append(f"SMART device discovery: {error}")
        return result
    allow_wakeup = bool(config_value(config, ("collection", "smart_allow_wakeup"), default=False))
    skip_model_patterns = [
        str(pattern).strip().casefold()
        for pattern in config_value(
            config,
            ("collection", "smart_periodic_skip_model_patterns"),
            default=(),
        )
        if str(pattern).strip()
    ]
    disks = [node for node in nodes if node.get("type") == "disk" and str(node.get("path") or "").startswith("/dev/") and not str(node.get("name") or "").startswith("zram")]
    smart_missing = False
    for node in disks:
        device = str(node.get("path"))
        device_id = _stable_block_id(node)
        model = str(node.get("model") or "").strip()
        transport = str(node.get("tran") or "").strip().casefold()
        matched_skip_pattern = next(
            (pattern for pattern in skip_model_patterns if pattern in model.casefold()),
            "",
        )
        if transport == "usb" and matched_skip_pattern:
            result.metrics.append(
                record(
                    cadence,
                    "storage",
                    "smart.periodic_probe_enabled",
                    0,
                    "boolean",
                    source="policy",
                    device_id=device_id,
                    details={
                        "model": model,
                        "transport": transport,
                        "reason": "usb_bridge_periodic_smart_passthrough_unsafe",
                        "matched_pattern": matched_skip_pattern,
                    },
                    outcome="skipped",
                )
            )
            continue
        command = ["smartctl", "-j"]
        if not allow_wakeup:
            command.extend(["-n", "standby"])
        command.append("-H")
        command.append(device)
        health = external(config, command, timeout=20, max_output=500_000)
        if health.missing:
            smart_missing = True
            break
        payload: Any = None
        try:
            payload = json.loads(health.stdout) if health.stdout.strip().startswith("{") else None
        except json.JSONDecodeError:
            payload = None
        smartctl_data = payload.get("smartctl") if isinstance(payload, Mapping) else None
        messages = smartctl_data.get("messages", []) if isinstance(smartctl_data, Mapping) else []
        message_text = " ".join(str(message.get("string", "")) for message in messages if isinstance(message, Mapping)) if isinstance(messages, list) else ""
        diagnostics = _smart_diagnostics(node, command, health, payload, messages)
        diagnostics["identity"] = device_id
        sleeping = (isinstance(payload, Mapping) and str(payload.get("power_mode", "")).lower() in {"sleep", "standby"}) or bool(re.search(r"device is in (?:sleep|standby) mode", message_text, re.I))
        if sleeping:
            diagnostics["reason"] = "device_asleep"
            result.metrics.append(record(cadence, "storage", "smart_check_skipped_asleep", 1, "boolean", source="smartctl", device_id=device_id, details=diagnostics, outcome="skipped"))
            continue
        unsupported = any(
            isinstance(message, Mapping)
            and re.search(r"unknown usb bridge|unsupported|not supported|unable to detect device type", str(message.get("string", "")), re.I)
            for message in messages
        ) if isinstance(messages, list) else False
        if unsupported:
            diagnostics["reason"] = "device_or_bridge_unsupported"
            result.metrics.append(record(cadence, "storage", "smart.supported", 0, "boolean", source="smartctl", device_id=device_id, details=diagnostics, outcome="skipped"))
            continue
        passed = payload.get("smart_status", {}).get("passed") if isinstance(payload, Mapping) and isinstance(payload.get("smart_status"), Mapping) else None
        if passed is not None:
            severity = "info" if passed else "critical"
            result.metrics.append(record(cadence, "storage", "smart.health", 1 if passed else 0, "boolean", severity=severity, source="smartctl", device_id=device_id, details={"model": node.get("model"), "transport": node.get("tran"), "device_type": diagnostics.get("device_type"), "protocol": diagnostics.get("protocol")}, outcome="ok" if passed else "error"))
        elif not health.ok:
            failure_class = _smart_failure_class(health, message_text, device)
            diagnostics["failure_class"] = failure_class
            if failure_class == "device_absent":
                diagnostics["reason"] = "device_disappeared_after_discovery"
                result.metrics.append(record(cadence, "storage", "smart_check_skipped_absent", 1, "boolean", source="smartctl", device_id=device_id, details=diagnostics, outcome="skipped"))
            else:
                diagnostic_message = "; ".join(diagnostics["messages"]) or command_problem(health)
                result.events.append(record(cadence, "storage", "smart_check_failed", 1, "failure", severity="warning", source="smartctl", device_id=device_id, details=diagnostics, outcome="error", error_message=diagnostic_message[:500]))
            continue

        if detailed and isinstance(payload, Mapping):
            device_data = payload.get("device")
            device_type = str(device_data.get("type") or "") if isinstance(device_data, Mapping) else ""
            detail_command = ["smartctl", "-j"]
            if not allow_wakeup:
                detail_command.extend(["-n", "standby"])
            if device_type.startswith("snt"):
                # Some USB-to-NVMe bridges, including ASMedia variants, hang on
                # the NVMe error-log request used by -x. Keep health, attributes,
                # and the read-only self-test log without probing that log page.
                detail_command.extend(["-A", "-l", "selftest"])
                result.metrics.append(record(cadence, "storage", "smart.error_log_supported", 0, "boolean", source="smartctl", device_id=device_id, details={"model": node.get("model"), "device_type": device_type, "reason": "usb_nvme_bridge_safe_mode"}, outcome="skipped"))
            else:
                detail_command.append("-x")
            detail_command.append(device)
            detail = external(config, detail_command, timeout=20, max_output=500_000)
            detail_payload: Any = None
            try:
                detail_payload = json.loads(detail.stdout) if detail.stdout.strip().startswith("{") else None
            except json.JSONDecodeError:
                detail_payload = None
            if isinstance(detail_payload, Mapping):
                payload = detail_payload
            elif not detail.ok:
                detail_smartctl = detail_payload.get("smartctl") if isinstance(detail_payload, Mapping) else None
                detail_messages = detail_smartctl.get("messages", []) if isinstance(detail_smartctl, Mapping) else []
                detail_diagnostics = _smart_diagnostics(node, detail_command, detail, detail_payload, detail_messages)
                detail_diagnostics["identity"] = device_id
                detail_diagnostics["failure_class"] = _smart_failure_class(detail, " ".join(_smart_messages(detail_messages)), device)
                result.events.append(record(cadence, "storage", "smart_detail_check_failed", 1, "failure", severity="warning", source="smartctl", device_id=device_id, details=detail_diagnostics, outcome="error", error_message=("; ".join(detail_diagnostics["messages"]) or command_problem(detail))[:500]))

            attributes_root = payload.get("ata_smart_attributes")
            table = attributes_root.get("table", []) if isinstance(attributes_root, Mapping) else []
            selected = {
                "Reallocated_Sector_Ct": ("smart.reallocated_sectors", "warning"),
                "Current_Pending_Sector": ("smart.pending_sectors", "critical"),
                "Offline_Uncorrectable": ("smart.offline_uncorrectable", "critical"),
                "Reported_Uncorrect": ("smart.reported_uncorrectable", "critical"),
                "UDMA_CRC_Error_Count": ("smart.interface_crc_errors", "warning"),
                "Power_On_Hours": ("smart.power_on_hours", "info"),
                "Temperature_Celsius": ("temperature.drive_c", "warning"),
            }
            if isinstance(table, list):
                for attribute in table:
                    if not isinstance(attribute, Mapping) or attribute.get("name") not in selected:
                        continue
                    raw = attribute.get("raw")
                    raw_value = raw.get("value") if isinstance(raw, Mapping) else None
                    if not isinstance(raw_value, (int, float)):
                        continue
                    metric_name, problem_level = selected[str(attribute["name"])]
                    severity = "info"
                    if metric_name == "temperature.drive_c":
                        severity = "critical" if raw_value >= 75 else "warning" if raw_value >= 65 else "info"
                    elif raw_value and problem_level in {"warning", "critical"}:
                        severity = problem_level
                    unit = "C" if metric_name == "temperature.drive_c" else "hours" if metric_name.endswith("power_on_hours") else "count"
                    result.metrics.append(record(cadence, "storage" if not metric_name.startswith("temperature") else "temperature", metric_name, raw_value, unit, severity=severity, source="smartctl", device_id=device_id))

            error_log = payload.get("ata_smart_error_log")
            summary = error_log.get("summary") if isinstance(error_log, Mapping) else None
            error_count = _float(summary.get("count"), math.nan) if isinstance(summary, Mapping) else math.nan
            if math.isfinite(error_count):
                result.metrics.append(record(cadence, "storage", "smart.error_log_entries", error_count, "entries", source="smartctl", device_id=device_id))

            self_test = payload.get("ata_smart_self_test_log")
            standard = self_test.get("standard") if isinstance(self_test, Mapping) else None
            self_tests = standard.get("table", []) if isinstance(standard, Mapping) else []
            failures = 0
            if isinstance(standard, Mapping) and isinstance(self_tests, list):
                for test in self_tests:
                    status = test.get("status") if isinstance(test, Mapping) else None
                    text = str(status.get("string", "")) if isinstance(status, Mapping) else ""
                    if re.search(r"(?:failure|error)", text, re.I) and not re.search(r"without error", text, re.I):
                        failures += 1
                result.metrics.append(record(cadence, "storage", "smart.self_test_failures", failures, "tests", severity="critical" if failures else "info", source="smartctl", device_id=device_id))

            nvme_self_test = payload.get("nvme_self_test_log")
            if isinstance(nvme_self_test, Mapping):
                operation = nvme_self_test.get("current_self_test_operation")
                operation_value = int(_float(operation.get("value"), 0)) if isinstance(operation, Mapping) else 0
                result.metrics.append(record(cadence, "storage", "smart.self_test_in_progress", 1 if operation_value else 0, "boolean", source="smartctl", device_id=device_id))
                tests = nvme_self_test.get("table", [])
                nvme_failures = 0
                if isinstance(tests, list):
                    for test in tests:
                        result_text = str((test.get("result") or {}).get("string", "")) if isinstance(test, Mapping) and isinstance(test.get("result"), Mapping) else ""
                        if result_text and not re.search(r"completed without error|success", result_text, re.I):
                            nvme_failures += 1
                result.metrics.append(record(cadence, "storage", "smart.self_test_failures", nvme_failures, "tests", severity="critical" if nvme_failures else "info", source="smartctl", device_id=device_id))

        if detailed and str(node.get("tran") or "").lower() == "nvme":
            nvme = external(config, ["nvme", "smart-log", device, "-o", "json"], timeout=20, max_output=500_000)
            if nvme.ok:
                try:
                    data = json.loads(nvme.stdout)
                except json.JSONDecodeError:
                    data = {}
                if isinstance(data, Mapping):
                    temperature_raw = _float(data.get("temperature"), math.nan)
                    temperature = temperature_raw - 273.15 if temperature_raw > 200 else temperature_raw
                    critical_warning = int(_float(data.get("critical_warning"), 0))
                    metrics = (
                        ("nvme_critical_warning", critical_warning, "bitmask", "critical" if critical_warning else "info"),
                        ("nvme_available_spare_percent", _float(data.get("avail_spare")), "%", "info"),
                        ("nvme_percent_used", _float(data.get("percent_used")), "%", "warning" if _float(data.get("percent_used")) >= 90 else "info"),
                        ("nvme_media_errors", _float(data.get("media_errors")), "errors", "critical" if _float(data.get("media_errors")) else "info"),
                        ("smart.error_log_entries", _float(data.get("num_err_log_entries")), "entries", "info"),
                        ("nvme_unsafe_shutdowns", _float(data.get("unsafe_shutdowns")), "events", "info"),
                        ("nvme_power_on_hours", _float(data.get("power_on_hours")), "hours", "info"),
                    )
                    for name, value, unit, severity in metrics:
                        result.metrics.append(record(cadence, "storage", name, value, unit, severity=severity, source="nvme-cli", device_id=device_id))
                    if math.isfinite(temperature):
                        result.metrics.append(record(cadence, "temperature", "temperature.nvme_c", round(temperature, 3), "C", severity="critical" if temperature >= 80 else "warning" if temperature >= 70 else "info", source="nvme-cli", device_id=device_id))
            elif not nvme.missing:
                result.errors.append(f"NVMe SMART {device_id}: {command_problem(nvme)}")
    if smart_missing:
        result.errors.append("SMART: command unavailable")
    return result


def collect_btrfs_health(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    del db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    mounts = external(config, ["findmnt", "-rn", "-t", "btrfs", "-o", "TARGET"], timeout=20, max_output=100_000)
    if not mounts.ok:
        if not mounts.missing:
            result.errors.append(f"Btrfs discovery: {command_problem(mounts)}")
        return result
    targets = [line.strip() for line in mounts.stdout.splitlines() if line.strip()]
    if not targets:
        return result
    target = "/" if "/" in targets else targets[0]
    device_stats = external(config, ["btrfs", "device", "stats", target], timeout=60, max_output=200_000)
    if device_stats.ok:
        names = {
            "write_io_errs": "btrfs.write_io_errors",
            "read_io_errs": "btrfs.read_io_errors",
            "flush_io_errs": "btrfs.flush_io_errors",
            "corruption_errs": "btrfs.corruption_errors",
            "generation_errs": "btrfs.generation_errors",
        }
        for raw_name, metric_name in names.items():
            match = re.search(rf"\.{raw_name}\s+(\d+)", device_stats.stdout)
            if match:
                value = int(match.group(1))
                result.metrics.append(record(cadence, "storage", metric_name, value, "errors", severity="critical" if value else "info", source="btrfs", device_id=target))
    else:
        result.errors.append(f"Btrfs device stats: {command_problem(device_stats)}")
    scrub = external(config, ["btrfs", "scrub", "status", "-R", target], timeout=60, max_output=200_000)
    if scrub.ok:
        errors = 0
        if not re.search(r"error summary:\s+no errors found", scrub.stdout, re.I):
            counts = [int(value) for value in re.findall(r"(?:read|csum|verify|super|malloc|uncorrectable|unverified|corrected)_errors:\s*(\d+)", scrub.stdout, re.I)]
            if not counts:
                counts = [int(value) for value in re.findall(r"(?:^|\s)[a-z_]+=(\d+)", scrub.stdout, re.I)]
            errors = sum(counts)
        result.metrics.append(record(cadence, "storage", "btrfs.scrub_errors", errors, "errors", severity="critical" if errors else "info", source="btrfs", device_id=target, details={"status_known": "no stats available" not in scrub.stdout.lower()}))
    else:
        result.errors.append(f"Btrfs scrub status: {command_problem(scrub)}")
    return result


def _parse_size(text: str) -> int | None:
    match = re.search(r"([0-9.]+)\s*([KMGTPE]?)i?B", text, re.I)
    if not match:
        return None
    factors = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4, "P": 1024**5, "E": 1024**6}
    return int(float(match.group(1)) * factors[match.group(2).upper()])


def collect_uptime_kernel(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    del db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    uptime_raw = _read(PROC_ROOT / "uptime").split()
    if uptime_raw:
        try:
            result.metrics.append(record(cadence, "system", "uptime_seconds", float(uptime_raw[0]), "seconds", source="procfs"))
        except ValueError:
            pass
    boot_id = _read(PROC_ROOT / "sys" / "kernel" / "random" / "boot_id").strip()
    running = os.uname().release
    result.metrics.append(record(cadence, "system", "kernel_running", 1, "kernel", source="uname", device_id=running, details={"version": running, "boot_id": boot_id}))

    kernels = external(config, ["rpm", "-q", "kernel-core", "--qf", r"%{INSTALLTIME}\t%{VERSION}-%{RELEASE}.%{ARCH}\n"])
    if kernels.ok:
        installed: list[tuple[int, str]] = []
        for line in kernels.stdout.splitlines():
            fields = line.split("\t", 1)
            if len(fields) == 2 and fields[0].isdigit():
                installed.append((int(fields[0]), fields[1]))
        newest = max(installed)[1] if installed else None
        running_is_newest = newest == running if newest else True
        result.metrics.append(record(cadence, "update", "running_latest_installed_kernel", 1 if running_is_newest else 0, "boolean", severity="warning" if not running_is_newest else "info", source="rpm", details={"running": running, "latest_installed": newest, "installed_count": len(installed)}))

    needs = external(config, ["dnf", "--cacheonly", "needs-restarting", "--json"], timeout=30, max_output=1_000_000)
    if needs.ok:
        reboot = False
        try:
            payload = json.loads(needs.stdout or "{}")
            if isinstance(payload, Mapping):
                reboot = bool(payload.get("reboot_required") or payload.get("reboot_needed"))
        except json.JSONDecodeError:
            reboot = "reboot should" in needs.stdout.lower() and "not be necessary" not in needs.stdout.lower()
        result.metrics.append(record(cadence, "update", "reboot_recommended", 1 if reboot else 0, "boolean", severity="warning" if reboot else "info", source="dnf5_cache"))

    offline = external(config, ["dnf", "offline", "status"], timeout=20)
    if offline.ok:
        downloaded = "offline transaction was initiated" in offline.stdout.lower()
        result.metrics.append(record(cadence, "update", "offline_transaction_downloaded", 1 if downloaded else 0, "boolean", source="dnf5", details={"armed_for_reboot": Path("/system-update").exists()}))

    database_path = Path(str(config_value(config, ("monitor", "database_path"), ("general", "database_path"), default="/var/lib/fedora-system-monitor/monitor.sqlite3")))
    try:
        result.metrics.append(record(cadence, "monitor", "database_size_bytes", database_path.stat().st_size, "bytes", source="filesystem"))
    except OSError:
        pass
    journal = external(config, ["journalctl", "--disk-usage"], timeout=10)
    if journal.ok:
        size = _parse_size(journal.stdout)
        if size is not None:
            result.metrics.append(record(cadence, "monitor", "journal_size_bytes", size, "bytes", source="journald"))
    return result


def collect_coredumps(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    listing = external(config, ["coredumpctl", "--no-pager", "--since", "1 hour ago", "--json=short"], timeout=20, max_output=1_000_000)
    if listing.missing:
        return result
    if listing.returncode == 1 and not listing.timed_out:
        result.metrics.append(record(cadence, "system", "coredumps_in_last_hour", 0, "coredumps", source="systemd-coredump"))
        return result
    if not listing.ok:
        result.errors.append(f"coredump metadata: {command_problem(listing)}")
        return result
    try:
        entries = json.loads(listing.stdout or "[]")
    except json.JSONDecodeError:
        result.errors.append("coredump metadata: invalid JSON")
        return result
    if not isinstance(entries, list):
        return result
    seen = state_get(db, "system.coredumps_seen", [])
    seen_set = set(seen) if isinstance(seen, list) else set()
    all_ids: list[str] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        executable = Path(str(entry.get("exe") or "unknown")).name
        event_id = fingerprint({key: entry.get(key) for key in ("time", "pid", "uid", "sig", "exe", "size")})
        all_ids.append(event_id)
        if event_id in seen_set:
            continue
        result.events.append(
            record(
                cadence,
                "system",
                "process_coredump",
                1,
                "crash",
                severity="warning",
                source="systemd-coredump",
                device_id=f"process:{executable}",
                details={
                    "executable": executable,
                    "pid": entry.get("pid"),
                    "uid": entry.get("uid"),
                    "signal": entry.get("sig"),
                    "corefile_state": entry.get("corefile"),
                    "core_size_bytes": entry.get("size"),
                    "event_time_usec": entry.get("time"),
                },
                outcome="detected",
            )
        )
    state_set(db, "system.coredumps_seen", (list(seen_set) + all_ids)[-1000:])
    result.metrics.append(record(cadence, "system", "coredumps_in_last_hour", len(entries), "coredumps", severity="warning" if entries else "info", source="systemd-coredump"))
    return result


def collect_hardware_inventory(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    del db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    nodes, error = _block_listing(config, include_serial=True)
    if error:
        result.errors.append(f"hardware inventory: {error}")
    for node in nodes:
        stable_id = _stable_block_id(node)
        mountpoints = [value for value in (node.get("mountpoints") or []) if value]
        result.hardware_inventory.append(
            {
                "category": "hardware",
                "name": str(node.get("model") or node.get("label") or node.get("name") or "block_device"),
                "item_key": stable_id,
                "stable_id": stable_id,
                "device_id": stable_id,
                "vendor": node.get("vendor"),
                "model": node.get("model"),
                "serial": node.get("serial") or None,
                "filesystem_uuid": node.get("uuid") or None,
                "label": node.get("label") or None,
                "filesystem": node.get("fstype") or None,
                "size_bytes": node.get("size"),
                "mount_point": mountpoints[0] if mountpoints else None,
                "present": True,
                "source": "lsblk",
                "details": {
                    "type": node.get("type"),
                    "transport": node.get("tran"),
                    "read_only": bool(node.get("ro")),
                    "removable": bool(node.get("rm")),
                    "hotplug": bool(node.get("hotplug")),
                    "mountpoints": mountpoints,
                    "parent": node.get("parent"),
                    "kernel_name": node.get("name"),
                },
            }
        )

    cpu_model = ""
    for line in _read(PROC_ROOT / "cpuinfo").splitlines():
        if line.lower().startswith("model name") and ":" in line:
            cpu_model = line.split(":", 1)[1].strip()
            break
    if cpu_model:
        result.hardware_inventory.append({"category": "hardware", "name": cpu_model, "item_key": "cpu:primary", "stable_id": "cpu:primary", "device_id": "cpu:primary", "source": "procfs", "details": {"logical_cpu_count": os.cpu_count()}})
    product_name = _read(SYS_ROOT / "class" / "dmi" / "id" / "product_name").strip()
    product_version = _read(SYS_ROOT / "class" / "dmi" / "id" / "product_version").strip()
    if product_name:
        result.hardware_inventory.append({"category": "hardware", "name": product_name, "item_key": "system:chassis", "stable_id": "system:chassis", "device_id": "system:chassis", "model": product_name, "source": "sysfs", "details": {"product_version": product_version}})
    result.metrics.append(record(cadence, "hardware", "hardware_inventory_item_count", len(result.hardware_inventory), "items", source="inventory"))
    return result


def collect_battery_health(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    del config, db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    root = SYS_ROOT / "class" / "power_supply"
    if not root.exists():
        return result
    for battery in sorted(root.iterdir()):
        if _read(battery / "type").strip() != "Battery":
            continue
        full = _float(_read(battery / "energy_full").strip() or _read(battery / "charge_full").strip(), math.nan)
        design = _float(_read(battery / "energy_full_design").strip() or _read(battery / "charge_full_design").strip(), math.nan)
        health = full * 100.0 / design if math.isfinite(full) and math.isfinite(design) and design else math.nan
        cycles = _float(_read(battery / "cycle_count").strip(), math.nan)
        if math.isfinite(health):
            severity = "critical" if health < 50 else "warning" if health < 70 else "info"
            result.metrics.append(record(cadence, "power", "battery_health_percent", round(health, 3), "%", severity=severity, source="sysfs", device_id=battery.name))
            result.metrics.append(record(cadence, "power", "battery_wear_percent", round(max(0.0, 100.0 - health), 3), "%", source="sysfs", device_id=battery.name))
        if math.isfinite(design):
            result.metrics.append(record(cadence, "power", "battery_design_capacity_wh", round(design / 1_000_000, 3), "Wh", source="sysfs", device_id=battery.name))
        if math.isfinite(full):
            result.metrics.append(record(cadence, "power", "battery_full_capacity_wh", round(full / 1_000_000, 3), "Wh", source="sysfs", device_id=battery.name))
        if math.isfinite(cycles):
            result.metrics.append(record(cadence, "power", "battery_charge_cycles", cycles, "cycles", source="sysfs", device_id=battery.name))
        result.hardware_inventory.append(
            {
                "category": "hardware",
                "name": _read(battery / "model_name").strip() or battery.name,
                "item_key": f"battery:{battery.name}",
                "stable_id": f"battery:{battery.name}",
                "device_id": f"battery:{battery.name}",
                "vendor": _read(battery / "manufacturer").strip() or None,
                "model": _read(battery / "model_name").strip() or None,
                "serial": _read(battery / "serial_number").strip() or None,
                "source": "sysfs",
                "details": {"design_capacity_wh": design / 1_000_000 if math.isfinite(design) else None, "full_capacity_wh": full / 1_000_000 if math.isfinite(full) else None, "health_percent": health if math.isfinite(health) else None, "charge_cycles": cycles if math.isfinite(cycles) else None},
            }
        )
    return result


def collect_directory_sizes(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    del db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    paths = config_value(config, ("inventory", "directory_size_paths"), default=["/var", "/home/daniele/MegaVault", "/home/daniele/Downloads"])
    if not isinstance(paths, list):
        return result
    timeout = max(30.0, _float(config_value(config, ("monitor", "command_timeout_seconds"), ("general", "command_timeout_seconds"), default=12), 12) * 5)
    for configured in paths:
        path = str(configured)
        if not Path(path).exists():
            continue
        usage = external(config, ["du", "-s", "-x", "-B1", "--", path], timeout=timeout, max_output=20_000)
        if usage.ok:
            try:
                size = int(usage.stdout.split()[0])
            except (IndexError, ValueError):
                continue
            result.metrics.append(record(cadence, "filesystem", "directory_size_bytes", size, "bytes", source="du", device_id=f"directory:{fingerprint(path)[:20]}", details={"path": path}))
        else:
            result.events.append(record(cadence, "collector", "directory_size_failed", 1, "failure", severity="warning", source="du", device_id=f"directory:{fingerprint(path)[:20]}", details={"path": path}, outcome="error", error_message=command_problem(usage)))
    return result


def collect_db_check(scope: str, config: Mapping[str, Any], db: object, *, quick: bool) -> CollectionResult:
    del config
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    integrity = getattr(db, "integrity_check", None)
    if integrity is None:
        return result
    try:
        raw = list(integrity(quick=quick) or [])
        problems = [item for item in raw if str(item).strip().lower() != "ok"]
        result.metrics.append(record(cadence, "monitor", "database_integrity_ok", 0 if problems else 1, "boolean", severity="critical" if problems else "info", source="sqlite", details={"quick": quick, "problem_count": len(problems)}))
        if problems:
            result.events.append(record(cadence, "monitor", "database_integrity_failed", len(problems), "problems", severity="critical", source="sqlite", details={"quick": quick, "problem_count": len(problems)}, outcome="error", error_message="SQLite integrity check reported problems"))
    except Exception as exc:
        result.errors.append(f"database integrity: {type(exc).__name__}")
    return result


def collect_weekly_diagnostics(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    config_errors = validate_config(config)
    result.metrics.append(record(cadence, "monitor", "collector_config_valid", 0 if config_errors else 1, "boolean", severity="critical" if config_errors else "info", source="config", details={"validation_error_count": len(config_errors)}))
    result.merge(collect_db_check(scope, config, db, quick=False))
    index_check = getattr(db, "check_indexes", None)
    if index_check is not None:
        try:
            indexes = index_check()
            missing = list(indexes.get("missing", [])) if isinstance(indexes, Mapping) else []
            result.metrics.append(record(cadence, "monitor", "database_indexes_ok", 0 if missing else 1, "boolean", severity="warning" if missing else "info", source="sqlite", details={"missing_count": len(missing)}))
        except Exception as exc:
            result.errors.append(f"database indexes: {type(exc).__name__}")

    unit_paths = sorted(Path("/etc/systemd/system").glob("fedora-system-monitor*"))
    unit_paths = [path for path in unit_paths if path.is_file() and path.suffix in {".service", ".timer", ".path"}]
    if unit_paths:
        verify = external(config, ["systemd-analyze", "verify", *map(str, unit_paths)], timeout=45, max_output=500_000)
        result.metrics.append(record(cadence, "monitor", "systemd_units_verify_ok", 1 if verify.ok else 0, "boolean", severity="critical" if not verify.ok else "info", source="systemd-analyze", details={"unit_count": len(unit_paths), "duration_ms": verify.duration_ms}, outcome="ok" if verify.ok else "error", error_message=None if verify.ok else command_problem(verify)))

    database_path = Path(str(config_value(config, ("monitor", "database_path"), ("general", "database_path"), default="/var/lib/fedora-system-monitor/monitor.sqlite3")))
    try:
        current_size = database_path.stat().st_size
        previous = state_get(db, "monitor.database_size_weekly", None)
        state_set(db, "monitor.database_size_weekly", current_size)
        growth = current_size - int(previous) if isinstance(previous, (int, float)) else 0
        ratio = growth / int(previous) if isinstance(previous, (int, float)) and previous else 0.0
        result.metrics.append(record(cadence, "monitor", "database_weekly_growth_bytes", growth, "bytes", severity="warning" if ratio > 0.5 and growth > 100 * 1024**2 else "info", source="filesystem", details={"growth_ratio": ratio, "current_size_bytes": current_size}))
    except OSError:
        pass

    required = ["journalctl", "udevadm", "nmcli", "lsblk", "smartctl", "dnf", "flatpak", "systemd-analyze"]
    missing_tools = [tool for tool in required if shutil.which(tool) is None]
    result.metrics.append(record(cadence, "monitor", "collector_sources_available", len(required) - len(missing_tools), "sources", severity="warning" if missing_tools else "info", source="PATH", details={"required_count": len(required), "missing": missing_tools}))

    journal = external(config, ["journalctl", "--list-boots", "--no-pager"], timeout=15, max_output=200_000)
    result.metrics.append(record(cadence, "monitor", "journal_source_readable", 1 if journal.ok else 0, "boolean", severity="warning" if not journal.ok else "info", source="journald", outcome="ok" if journal.ok else "error", error_message=None if journal.ok else command_problem(journal)))
    udev = external(config, ["udevadm", "--version"], timeout=10)
    result.metrics.append(record(cadence, "monitor", "udev_source_available", 1 if udev.ok else 0, "boolean", severity="warning" if not udev.ok else "info", source="udev", outcome="ok" if udev.ok else "error", error_message=None if udev.ok else command_problem(udev)))
    return result


__all__ = [
    "collect_battery_health",
    "collect_btrfs_health",
    "collect_coredumps",
    "collect_db_check",
    "collect_directory_sizes",
    "collect_hardware_inventory",
    "collect_smart",
    "collect_uptime_kernel",
    "collect_weekly_diagnostics",
]
