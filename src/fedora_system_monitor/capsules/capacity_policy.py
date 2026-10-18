"""Filesystem capacity policy shared by collectors and alert evaluation."""

from __future__ import annotations

from typing import Any, Mapping


GIB = 1024**3


def _nested(config: Mapping[str, Any], path: tuple[str, ...], default: Any) -> Any:
    value: Any = config
    for part in path:
        if not isinstance(value, Mapping) or part not in value:
            return default
        value = value[part]
    return value


def _capacity_override(config: Mapping[str, Any], filesystem_id: str) -> Mapping[str, Any] | None:
    if not filesystem_id.startswith("fsuuid:"):
        return None
    uuid = filesystem_id.split(":", 1)[1].casefold()
    overrides = _nested(config, ("storage", "capacity_overrides"), [])
    if not isinstance(overrides, list):
        return None
    for item in overrides:
        if isinstance(item, Mapping) and str(item.get("filesystem_uuid") or "").casefold() == uuid:
            return item
    return None


def disk_capacity_level(
    config: Mapping[str, Any],
    free_percent: float,
    free_bytes: int | float,
    total_bytes: int | float,
    *,
    filesystem_id: str = "",
    active_level: str = "",
) -> tuple[str, str]:
    """Return severity and policy name for one filesystem capacity sample."""

    override = _capacity_override(config, filesystem_id)
    if override is not None:
        warning = float(override["warning_free_gib"])
        critical = float(override["critical_free_gib"])
        emergency = float(override["emergency_free_gib"])
        hysteresis = float(override.get("recovery_hysteresis_gib", 0))
        if active_level == "emergency":
            emergency += hysteresis
        if active_level == "critical":
            critical += hysteresis
        if active_level == "warning":
            warning += hysteresis
        free_gib = float(free_bytes) / GIB
        if free_gib < emergency:
            return "emergency", "filesystem_uuid_absolute"
        if free_gib < critical:
            return "critical", "filesystem_uuid_absolute"
        if free_gib < warning:
            return "warning", "filesystem_uuid_absolute"
        return "", "filesystem_uuid_absolute"

    small_limit = float(_nested(config, ("storage", "small_filesystem_max_gib"), 5.0)) * GIB
    if total_bytes and total_bytes <= small_limit:
        configured_minimum = float(_nested(config, ("storage", "small_filesystem_min_free_mib"), 128)) * 1024**2
        minimum = min(configured_minimum, float(total_bytes) * 0.10)
        if free_bytes < minimum / 2:
            return "critical", "small_filesystem"
        if free_bytes < minimum:
            return "warning", "small_filesystem"
        return "", "small_filesystem"

    warning = float(_nested(config, ("thresholds", "disk", "warning_free_percent"), 20))
    critical = float(_nested(config, ("thresholds", "disk", "critical_free_percent"), 10))
    emergency = float(_nested(config, ("thresholds", "disk", "emergency_free_percent"), 5))
    hysteresis = float(_nested(config, ("thresholds", "disk", "recovery_hysteresis_percent"), 2))
    absolute = float(_nested(config, ("thresholds", "disk", "absolute_free_gib"), 10)) * GIB
    if active_level == "emergency":
        emergency += hysteresis
    if active_level == "critical":
        critical += hysteresis
    if active_level == "warning":
        warning += hysteresis
    if free_percent < emergency:
        return "emergency", "global_percent"
    if free_percent < critical:
        return "critical", "global_percent"
    absolute_applicable = total_bytes >= absolute * 100.0 / max(warning, 0.001)
    if free_percent < warning or (absolute_applicable and free_bytes < absolute):
        return "warning", "global_percent"
    return "", "global_percent"
