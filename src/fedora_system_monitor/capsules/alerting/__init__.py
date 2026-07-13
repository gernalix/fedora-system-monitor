"""Threshold evaluation with persisted duration, hysteresis, and recovery state."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable


StateGetter = Callable[[str, Any], Any]
StateSetter = Callable[[str, Any], None]


@dataclass(frozen=True)
class AlertSignal:
    key: str
    category: str
    name: str
    severity: str
    active: bool
    message: str
    source: str
    device_id: str = ""
    details: dict[str, Any] | None = None
    occurred_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _nested(config: dict[str, Any], path: str, default: Any) -> Any:
    value: Any = config
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def _now(now: datetime | None) -> datetime:
    current = now or datetime.now(timezone.utc)
    return current if current.tzinfo else current.replace(tzinfo=timezone.utc)


def _severity_rank(value: str) -> int:
    return {"info": 0, "warning": 1, "critical": 2, "emergency": 3}.get(value, 0)


def _disk_level(metric: dict[str, Any], active_level: str, config: dict[str, Any]) -> tuple[str, int]:
    free_percent = float(metric["value"])
    details = metric.get("details") or {}
    total = float(details.get("total_bytes") or 0)
    free = float(details.get("free_bytes") or 0)
    small_limit = float(_nested(config, "storage.small_filesystem_max_gib", 5.0)) * 1024**3
    if total and total <= small_limit:
        configured_minimum = float(_nested(config, "storage.small_filesystem_min_free_mib", 128)) * 1024**2
        minimum = min(configured_minimum, total * 0.10)
        if free < minimum / 2:
            return "critical", 0
        if free < minimum:
            return "warning", 0
        return "", 0
    warning = float(_nested(config, "thresholds.disk.warning_free_percent", 20))
    critical = float(_nested(config, "thresholds.disk.critical_free_percent", 10))
    emergency = float(_nested(config, "thresholds.disk.emergency_free_percent", 5))
    hysteresis = float(_nested(config, "thresholds.disk.recovery_hysteresis_percent", 2))
    absolute = float(_nested(config, "thresholds.disk.absolute_free_gib", 10)) * 1024**3
    if active_level == "emergency":
        emergency += hysteresis
    if active_level == "critical":
        critical += hysteresis
    if active_level == "warning":
        warning += hysteresis
    if free_percent < emergency:
        return "emergency", 0
    if free_percent < critical:
        return "critical", 0
    # The absolute floor is a warning backstop for large volumes.  Applying a
    # 10 GiB floor to a roughly 10 GiB filesystem makes recovery impossible
    # even when the filesystem is almost empty.
    absolute_applicable = total >= absolute * 100.0 / max(warning, 0.001)
    if free_percent < warning or (absolute_applicable and free < absolute):
        return "warning", 0
    return "", 0


def _inode_level(value: float, active_level: str, config: dict[str, Any]) -> tuple[str, int]:
    warning = float(_nested(config, "thresholds.inode.warning_free_percent", 15))
    critical = float(_nested(config, "thresholds.inode.critical_free_percent", 5))
    hysteresis = float(_nested(config, "thresholds.inode.recovery_hysteresis_percent", 2))
    if active_level == "critical":
        critical += hysteresis
    if active_level == "warning":
        warning += hysteresis
    if value < critical:
        return "critical", 0
    if value < warning:
        return "warning", 0
    return "", 0


def _high_level(
    value: float,
    active_level: str,
    warning: float,
    critical: float,
    hysteresis: float,
    warning_duration: int = 0,
) -> tuple[str, int]:
    if active_level == "critical":
        critical -= hysteresis
    if active_level == "warning":
        warning -= hysteresis
    if value > critical:
        return "critical", 0
    if value > warning:
        return "warning", warning_duration
    return "", 0


def _metric_condition(metric: dict[str, Any], active_level: str, config: dict[str, Any]) -> tuple[str, int, str] | None:
    name = str(metric.get("name", ""))
    value = float(metric.get("value") or 0)
    if name == "filesystem.free_percent":
        level, duration = _disk_level(metric, active_level, config)
        return level, duration, f"filesystem free space is {value:.1f}%"
    if name == "filesystem.inode_free_percent":
        level, duration = _inode_level(value, active_level, config)
        return level, duration, f"filesystem free inodes are {value:.1f}%"
    if name == "memory.used_percent":
        level, duration = _high_level(
            value,
            active_level,
            float(_nested(config, "thresholds.memory.ram_warning_percent", 90)),
            float(_nested(config, "thresholds.memory.ram_critical_percent", 95)),
            float(_nested(config, "thresholds.memory.recovery_hysteresis_percent", 5)),
            int(_nested(config, "thresholds.memory.ram_warning_duration_seconds", 300)),
        )
        return level, duration, f"RAM use is {value:.1f}%"
    if name == "swap.used_percent":
        level, duration = _high_level(
            value,
            active_level,
            float(_nested(config, "thresholds.memory.swap_warning_percent", 20)),
            float(_nested(config, "thresholds.memory.swap_critical_percent", 50)),
            float(_nested(config, "thresholds.memory.recovery_hysteresis_percent", 5)),
        )
        return level, duration, f"swap use is {value:.1f}%"
    if name in {"temperature.cpu_c", "temperature.nvme_c"}:
        kind = "nvme" if name.endswith("nvme_c") else "cpu"
        level, duration = _high_level(
            value,
            active_level,
            float(_nested(config, f"thresholds.temperature.{kind}_warning_c", 70 if kind == "nvme" else 90)),
            float(_nested(config, f"thresholds.temperature.{kind}_critical_c", 80 if kind == "nvme" else 95)),
            float(_nested(config, "thresholds.temperature.recovery_hysteresis_c", 5)),
            int(_nested(config, f"thresholds.temperature.{kind}_warning_duration_seconds", 300)),
        )
        return level, duration, f"{kind.upper()} temperature is {value:.1f} C"
    if name == "sensor.alarm":
        return ("warning", 0, "hardware sensor alarm is asserted") if value > 0 else (
            "",
            0,
            "hardware sensor alarm recovered",
        )
    if name == "network.internet_reachable":
        return ("", 0, "Internet connectivity recovered") if value else (
            "warning",
            int(_nested(config, "thresholds.network.internet_down_duration_seconds", 180)),
            "Internet is not reachable",
        )
    if name == "wifi.connected":
        return ("", 0, "Wi-Fi connectivity recovered") if value else (
            "warning",
            int(_nested(config, "thresholds.network.wifi_down_duration_seconds", 120)),
            "Wi-Fi is disconnected",
        )
    if name == "network.gateway_reachable":
        connected = bool((metric.get("details") or {}).get("wifi_connected", True))
        if value or not connected:
            return "", 0, "gateway connectivity recovered"
        return "warning", 0, "gateway is unreachable while Wi-Fi is connected"
    if name == "service.active":
        details = metric.get("details") or {}
        failed = details.get("active_state") == "failed" or details.get("result") == "failed"
        importance = details.get("importance", "secondary")
        if value:
            return "", 0, "service recovered"
        if importance == "essential":
            return "critical", 0, "essential systemd service is inactive"
        if failed:
            return "warning", 0, "systemd service is failed"
        return "", 0, "optional systemd service is inactive"
    if name == "smart.health":
        return ("", 0, "SMART health recovered") if value else ("critical", 0, "SMART health check failed")
    if name == "filesystem.read_only":
        unexpected = bool(value) and not (metric.get("details") or {}).get("expected_read_only")
        return ("critical", 0, "filesystem is unexpectedly read-only") if unexpected else (
            "",
            0,
            "filesystem is writable or intentionally read-only",
        )
    return None


def evaluate_metric_alerts(
    metrics: Iterable[dict[str, Any]],
    config: dict[str, Any],
    get_state: StateGetter,
    set_state: StateSetter,
    *,
    now: datetime | None = None,
) -> list[AlertSignal]:
    """Evaluate current metrics and return active/recovery signals."""
    current = _now(now)
    output: list[AlertSignal] = []
    for metric in metrics:
        name = str(metric.get("name", ""))
        device_id = str(metric.get("device_id") or "host")
        key = f"{name}:{device_id}"
        state_key = f"alert-condition:{key}"
        state = get_state(state_key, {}) or {}
        active_level = str(state.get("active_level") or "")
        condition = _metric_condition(metric, active_level, config)
        if condition is None:
            continue
        desired, duration, message = condition
        if desired:
            since_text = state.get("breach_since")
            if state.get("breach_level") != desired or not since_text:
                since_text = current.isoformat()
            try:
                since = datetime.fromisoformat(str(since_text))
            except ValueError:
                since = current
            if since.tzinfo is None:
                since = since.replace(tzinfo=timezone.utc)
            state.update({"breach_since": since.isoformat(), "breach_level": desired, "recovery_samples": 0})
            if (current - since).total_seconds() >= duration:
                if active_level != desired or _severity_rank(desired) > _severity_rank(active_level):
                    output.append(
                        AlertSignal(
                            key=key,
                            category=str(metric.get("category") or "system"),
                            name=name,
                            severity=desired,
                            active=True,
                            message=message,
                            source=str(metric.get("source") or "collector"),
                            device_id=device_id,
                            details={"value": metric.get("value"), "unit": metric.get("unit")},
                        )
                    )
                state["active_level"] = desired
        else:
            state.pop("breach_since", None)
            state.pop("breach_level", None)
            if active_level:
                samples = int(state.get("recovery_samples") or 0) + 1
                state["recovery_samples"] = samples
                required = int(_nested(config, "thresholds.network.recovery_samples", 2)) if name.startswith(("network.", "wifi.")) else 1
                if samples >= required:
                    output.append(
                        AlertSignal(
                            key=key,
                            category=str(metric.get("category") or "system"),
                            name=name,
                            severity=active_level,
                            active=False,
                            message=message,
                            source=str(metric.get("source") or "collector"),
                            device_id=device_id,
                            details={"value": metric.get("value"), "unit": metric.get("unit")},
                        )
                    )
                    state["active_level"] = ""
                    state["recovery_samples"] = 0
        set_state(state_key, state)
    return output


def evaluate_event_alerts(events: Iterable[dict[str, Any]]) -> list[AlertSignal]:
    """Turn critical point events into deduplicated active alerts."""
    alert_names = {
        "oom_killer",
        "kernel_panic",
        "kernel_oops",
        "io_error",
        "filesystem_read_only",
        "smart_failed",
        "service_failed",
        "unsafe_removal",
        "temperature_critical",
        "restart_loop",
        "package_transaction_incomplete",
        "dnf_transaction_failed",
        "mount_failed",
        "update_failed",
        "software_update_failed",
        "unsafe_device_removal",
        "disk_io_error",
        "device_mount_failed",
        "device_unmount_failed",
    }
    signals: list[AlertSignal] = []
    for event in events:
        name = str(event.get("name") or "")
        severity = str(event.get("severity") or "info")
        if name not in alert_names and severity not in {"critical", "emergency"}:
            continue
        device_id = str(event.get("device_id") or "host")
        service_device = device_id.removeprefix("systemd-unit:")
        key = {
            "service_failed": f"service.active:{device_id}",
            "systemd_unit_failed": f"service.active:{service_device}",
            "filesystem_read_only": f"filesystem.read_only:{device_id}",
            "smart_failed": f"smart.health:{device_id}",
        }.get(name, f"event:{name}:{device_id}")
        signals.append(
            AlertSignal(
                key=key,
                category=str(event.get("category") or "system"),
                name=name,
                severity=severity,
                active=True,
                message=str(event.get("message") or name.replace("_", " ")),
                source=str(event.get("source") or "event"),
                device_id=device_id,
                details=event.get("details") or {},
                occurred_at=str(event.get("timestamp_utc") or "") or None,
            )
        )
    return signals


__all__ = ["AlertSignal", "evaluate_event_alerts", "evaluate_metric_alerts"]
