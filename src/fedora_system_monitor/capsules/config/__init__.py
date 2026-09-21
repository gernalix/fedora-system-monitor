"""Configuration loading, validation, defaults, and secret redaction.

The capsule intentionally depends only on the Python standard library.  Public
callers should use :func:`load_config` instead of parsing the TOML file directly
so additions to ``DEFAULT_CONFIG`` remain backward compatible.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re
import tomllib
from typing import Any, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class ConfigError(ValueError):
    """Raised when a configuration file cannot be parsed or validated."""


DEFAULT_CONFIG: dict[str, Any] = {
    "config_version": 1,
    "monitor": {
        "hostname": "",
        "timezone": "Europe/Copenhagen",
        "operator_user": "daniele",
        "database_path": "/var/lib/fedora-system-monitor/monitor.sqlite3",
        "backup_directory": "/var/lib/fedora-system-monitor/backups",
        "lock_path": "/run/fedora-system-monitor/collector.lock",
        "command_timeout_seconds": 12,
        "log_level": "INFO",
    },
    "collection": {
        "critical_filesystems": ["/", "/home", "/var", "/tmp", "/boot", "/boot/efi"],
        "ignore_filesystem_types": [
            "autofs", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts", "devtmpfs",
            "efivarfs", "erofs", "fusectl", "hugetlbfs", "mqueue", "nsfs", "overlay", "proc",
            "pstore", "ramfs", "securityfs", "squashfs", "sysfs", "tmpfs", "tracefs",
        ],
        "top_process_limit": 5,
        "internet_check_enabled": True,
        "internet_host": "1.1.1.1",
        "internet_port": 443,
        "internet_timeout_seconds": 2.0,
        "gateway_ping_timeout_seconds": 2,
        "journal_lookback_minutes": 20,
    },
    "services": {
        "auto_detect": True,
        "essential": ["NetworkManager.service", "firewalld.service", "user:discord-exporter-crawl.service"],
        "secondary": [
            "bluetooth.service",
            "libvirtd.service",
            "podman.service",
            "docker.service",
            "rustdesk.service",
            "smartd.service",
            "sshd.service",
            "uptime-kuma.service",
        ],
        "name_patterns": ["backup", "adb", "kuma", "megavault", "monitor"],
    },
    "storage": {
        "known_labels": ["Ventoy", "VTOYEFI", "VEEAMRE", "Seagate Expansion Drive"],
        "known_model_patterns": ["Samsung Portable SSD T7", "Seagate"],
        "small_filesystem_max_gib": 5.0,
        "small_filesystem_min_free_mib": 128,
        "expected_devices": [],
    },
    "inventory": {
        "user_home": "/home/daniele",
        "android_sdk": "/home/daniele/Android/Sdk",
        "manual_paths": ["/opt", "/usr/local", "/home/daniele/.local/opt", "/home/daniele/.local/bin"],
        "launcher_paths": [
            "/usr/share/applications",
            "/usr/local/share/applications",
            "/home/daniele/.local/share/applications",
        ],
        "appimage_paths": [
            "/home/daniele/Applications",
            "/home/daniele/.local/opt",
            "/home/daniele/Downloads",
        ],
        "directory_size_paths": ["/var", "/home/daniele/MegaVault", "/home/daniele/Downloads"],
        "max_scan_depth": 4,
        "metadata_hash_max_bytes": 16 * 1024 * 1024,
    },
    "context": {
        "activitywatch_data_path": "/home/daniele/projects/activity-watch-data",
        "output_directory": "/home/daniele/projects/fedora-context-data",
        "sync_lookback_minutes": 30,
        "overlap_minutes": 10,
        "max_backfill_hours": 48,
        "incident_before_minutes": 10,
        "incident_after_minutes": 5,
        "git_push": False,
        "git_remote": "origin",
        "git_branch": "main",
        "expected_repository": "gernalix/fedora-context-data",
        "git_timeout_seconds": 120,
    },
    "thresholds": {
        "disk": {
            "warning_free_percent": 20.0,
            "critical_free_percent": 10.0,
            "emergency_free_percent": 5.0,
            "absolute_free_gib": 10.0,
            "recovery_hysteresis_percent": 2.0,
        },
        "inode": {
            "warning_free_percent": 15.0,
            "critical_free_percent": 5.0,
            "recovery_hysteresis_percent": 2.0,
        },
        "temperature": {
            "cpu_warning_c": 90.0,
            "cpu_warning_duration_seconds": 300,
            "cpu_critical_c": 95.0,
            "nvme_warning_c": 70.0,
            "nvme_warning_duration_seconds": 300,
            "nvme_critical_c": 80.0,
            "recovery_hysteresis_c": 5.0,
        },
        "memory": {
            "ram_warning_percent": 90.0,
            "ram_warning_duration_seconds": 300,
            "ram_critical_percent": 95.0,
            "available_warning_percent": 10.0,
            "available_critical_percent": 5.0,
            "psi_some_warning_percent": 10.0,
            "psi_full_critical_percent": 5.0,
            "swap_out_warning_mib_per_second": 16.0,
            "reclaim_warning_pages_per_second": 4096.0,
            "recovery_hysteresis_percent": 5.0,
        },
        "battery": {
            "health_warning_percent": 70.0,
            "health_critical_percent": 50.0,
            "recovery_hysteresis_percent": 5.0,
        },
        "network": {
            "wifi_down_duration_seconds": 120,
            "internet_down_duration_seconds": 180,
            "disconnect_count": 3,
            "disconnect_window_minutes": 30,
            "recovery_samples": 2,
        },
        "services": {
            "restart_loop_count": 3,
            "restart_loop_window_minutes": 15,
        },
    },
    "retention": {
        "minute_days": 14,
        "five_minute_days": 60,
        "fifteen_minute_days": 180,
        "hourly_days": 365,
        "daily_days": 1825,
        "hardware_event_days": 365,
        "general_event_days": 365,
        "alert_days": 730,
        "inventory_daily_days": 35,
        "backup_daily_count": 14,
        "backup_weekly_count": 8,
        "backup_monthly_count": 12,
    },
    "notifications": {
        "uptime_kuma_credentials": "/home/daniele/.config/codex/secrets/fedora_system_monitor_uptime_kuma.toml",
        "telegram_credentials": "/home/daniele/.config/codex/secrets/telegram.env",
        "filesystem_free_change_gib": 1.0,
        "reminder_seconds": 21600,
        "timeout_seconds": 5,
        "inverted_categories": [],
    },
}


_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:token|api[_-]?key|password|passwd|secret|credential|authorization)\b"
    r"\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_SECRET_QUERY_RE = re.compile(
    r"(?i)([?&](?:token|api[_-]?key|key|password|secret|credential|auth)=)[^&#\s]+"
)
_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
_KUMA_PUSH_RE = re.compile(r"(?i)(/api/push/)[^/?#\s]+")


def redact_text(value: object) -> str:
    """Return text with common credential forms replaced by ``[REDACTED]``.

    Redaction is deliberately targeted: UUIDs, device serials, paths, and other
    operational identifiers are not hidden merely because they are long.
    """

    text = str(value)
    text = _KUMA_PUSH_RE.sub(r"\1[REDACTED]", text)
    text = _SECRET_QUERY_RE.sub(r"\1[REDACTED]", text)
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    return _SECRET_ASSIGNMENT_RE.sub(r"\1[REDACTED]", text)


def _merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(base.get(key), dict):
            base[key] = _merge(dict(base[key]), value)
        else:
            base[key] = deepcopy(value)
    return base


def _migrate_legacy_config(parsed: Mapping[str, Any]) -> dict[str, Any]:
    """Drop thresholds whose former meaning is unsafe for Fedora zram."""

    migrated = deepcopy(dict(parsed))
    thresholds = migrated.get("thresholds")
    memory = thresholds.get("memory") if isinstance(thresholds, Mapping) else None
    if isinstance(memory, Mapping):
        current = dict(memory)
        current.pop("swap_warning_percent", None)
        current.pop("swap_critical_percent", None)
        migrated["thresholds"] = dict(thresholds)
        migrated["thresholds"]["memory"] = current
    return migrated


def load_config(path: str | Path | None) -> dict[str, Any]:
    """Load TOML at *path*, merge it over defaults, and validate the result.

    ``None`` returns an independent copy of the defaults.  A missing explicit
    path is considered an operator error and raises :class:`ConfigError`.
    """

    config = deepcopy(DEFAULT_CONFIG)
    if path is not None:
        source = Path(path)
        try:
            with source.open("rb") as handle:
                parsed = tomllib.load(handle)
        except FileNotFoundError as exc:
            raise ConfigError(f"configuration file not found: {source}") from exc
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"cannot read configuration {source}: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ConfigError("configuration root must be a TOML table")
        config = _merge(config, _migrate_legacy_config(parsed))

    errors = validate_config(config)
    if errors:
        raise ConfigError("invalid configuration: " + "; ".join(errors))
    return config


def _number(config: Mapping[str, Any], path: tuple[str, ...], errors: list[str]) -> float | None:
    value: Any = config
    for part in path:
        if not isinstance(value, Mapping) or part not in value:
            errors.append(f"{'.'.join(path)} is required")
            return None
        value = value[part]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{'.'.join(path)} must be a number")
        return None
    return float(value)


def _require_positive(config: Mapping[str, Any], path: tuple[str, ...], errors: list[str]) -> None:
    value = _number(config, path, errors)
    if value is not None and value <= 0:
        errors.append(f"{'.'.join(path)} must be greater than zero")


def _require_percent(config: Mapping[str, Any], path: tuple[str, ...], errors: list[str]) -> None:
    value = _number(config, path, errors)
    if value is not None and not 0 <= value <= 100:
        errors.append(f"{'.'.join(path)} must be between 0 and 100")


def _value(config: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = config
    for part in path:
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def _require_string(
    config: Mapping[str, Any],
    path: tuple[str, ...],
    errors: list[str],
    *,
    allow_empty: bool = False,
) -> None:
    value = _value(config, path)
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        qualifier = "a string" if allow_empty else "a non-empty string"
        errors.append(f"{'.'.join(path)} must be {qualifier}")


def _require_list(config: Mapping[str, Any], path: tuple[str, ...], errors: list[str]) -> None:
    if not isinstance(_value(config, path), list):
        errors.append(f"{'.'.join(path)} must be an array")


def _require_bool(config: Mapping[str, Any], path: tuple[str, ...], errors: list[str]) -> None:
    if not isinstance(_value(config, path), bool):
        errors.append(f"{'.'.join(path)} must be boolean")


def _ordered_thresholds(
    config: Mapping[str, Any],
    base: tuple[str, ...],
    keys: tuple[str, ...],
    errors: list[str],
    *,
    ascending: bool,
) -> None:
    values = [_number(config, base + (key,), errors) for key in keys]
    if any(value is None for value in values):
        return
    ordered = all(
        left < right if ascending else left > right
        for left, right in zip(values, values[1:])
    )
    if not ordered:
        relation = " < " if ascending else " > "
        errors.append(f"{'.'.join(base)} must satisfy {relation.join(keys)}")


def validate_config(config: Mapping[str, Any] | object) -> list[str]:
    """Return all known validation errors without mutating *config*."""

    if not isinstance(config, Mapping):
        return ["configuration root must be a mapping"]

    errors: list[str] = []

    def validate_known_keys(current: Mapping[str, Any], defaults: Mapping[str, Any], prefix: tuple[str, ...] = ()) -> None:
        for key, value in current.items():
            if key not in defaults:
                errors.append(f"unknown configuration key: {'.'.join((*prefix, str(key)))}")
            elif isinstance(value, Mapping) and isinstance(defaults[key], Mapping):
                validate_known_keys(value, defaults[key], (*prefix, str(key)))

    def require_string_items(path: tuple[str, ...], *, absolute: bool = False) -> None:
        value = _value(config, path)
        if not isinstance(value, list):
            return
        for index, item in enumerate(value):
            if not isinstance(item, str) or not item.strip():
                errors.append(f"{'.'.join(path)}[{index}] must be a non-empty string")
            elif absolute and not Path(item).is_absolute():
                errors.append(f"{'.'.join(path)}[{index}] must be an absolute path")

    validate_known_keys(config, DEFAULT_CONFIG)
    version = config.get("config_version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        errors.append("config_version must be a positive integer")

    if not isinstance(config.get("monitor"), Mapping):
        errors.append("monitor must be a table")
    for key in (
        "timezone",
        "operator_user",
        "database_path",
        "backup_directory",
        "lock_path",
        "log_level",
    ):
        _require_string(config, ("monitor", key), errors)
    _require_string(config, ("monitor", "hostname"), errors, allow_empty=True)
    _require_positive(config, ("monitor", "command_timeout_seconds"), errors)
    for key in ("database_path", "backup_directory", "lock_path"):
        value = _value(config, ("monitor", key))
        if isinstance(value, str) and value and not Path(value).is_absolute():
            errors.append(f"monitor.{key} must be an absolute path")
    timezone_name = _value(config, ("monitor", "timezone"))
    if isinstance(timezone_name, str):
        try:
            ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError:
            errors.append("monitor.timezone is unknown")

    if not isinstance(config.get("collection"), Mapping):
        errors.append("collection must be a table")
    for key in ("critical_filesystems", "ignore_filesystem_types"):
        _require_list(config, ("collection", key), errors)
    require_string_items(("collection", "critical_filesystems"), absolute=True)
    require_string_items(("collection", "ignore_filesystem_types"))
    _require_bool(config, ("collection", "internet_check_enabled"), errors)
    _require_string(config, ("collection", "internet_host"), errors)
    for key in (
        "top_process_limit",
        "internet_port",
        "internet_timeout_seconds",
        "gateway_ping_timeout_seconds",
        "journal_lookback_minutes",
    ):
        _require_positive(config, ("collection", key), errors)
    port = _value(config, ("collection", "internet_port"))
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        errors.append("collection.internet_port must be an integer from 1 to 65535")

    if not isinstance(config.get("services"), Mapping):
        errors.append("services must be a table")
    _require_bool(config, ("services", "auto_detect"), errors)
    for key in ("essential", "secondary", "name_patterns"):
        _require_list(config, ("services", key), errors)
    for key in ("essential", "secondary"):
        value = _value(config, ("services", key))
        if isinstance(value, list):
            for index, item in enumerate(value):
                valid = isinstance(item, str) and bool(item.strip())
                valid = valid or (
                    isinstance(item, Mapping)
                    and isinstance(item.get("name"), str)
                    and bool(item["name"].strip())
                    and set(item).issubset({"name", "essential"})
                )
                if not valid:
                    errors.append(f"services.{key}[{index}] must be a unit string or a name/essential table")
    require_string_items(("services", "name_patterns"))

    if not isinstance(config.get("storage"), Mapping):
        errors.append("storage must be a table")
    for key in ("known_labels", "known_model_patterns", "expected_devices"):
        _require_list(config, ("storage", key), errors)
    require_string_items(("storage", "known_labels"))
    require_string_items(("storage", "known_model_patterns"))
    expected = _value(config, ("storage", "expected_devices"))
    if isinstance(expected, list):
        for index, item in enumerate(expected):
            valid = isinstance(item, str) and bool(item.strip())
            if isinstance(item, Mapping):
                identity = [item.get(key) for key in ("uuid", "label", "model", "id")]
                valid = any(isinstance(value, str) and value.strip() for value in identity)
                valid = valid and set(item).issubset({"uuid", "label", "model", "id", "required"})
                valid = valid and ("required" not in item or isinstance(item["required"], bool))
            if not valid:
                errors.append(f"storage.expected_devices[{index}] must contain a stable identifier")
    for key in ("small_filesystem_max_gib", "small_filesystem_min_free_mib"):
        _require_positive(config, ("storage", key), errors)

    if not isinstance(config.get("inventory"), Mapping):
        errors.append("inventory must be a table")
    for key in ("user_home", "android_sdk"):
        _require_string(config, ("inventory", key), errors)
        value = _value(config, ("inventory", key))
        if isinstance(value, str) and value and not Path(value).is_absolute():
            errors.append(f"inventory.{key} must be an absolute path")
    for key in ("manual_paths", "launcher_paths", "appimage_paths", "directory_size_paths"):
        _require_list(config, ("inventory", key), errors)
        require_string_items(("inventory", key), absolute=True)
    for key in ("max_scan_depth", "metadata_hash_max_bytes"):
        _require_positive(config, ("inventory", key), errors)

    if not isinstance(config.get("context"), Mapping):
        errors.append("context must be a table")
    for key in ("activitywatch_data_path", "output_directory", "git_remote", "git_branch", "expected_repository"):
        _require_string(config, ("context", key), errors)
    for key in ("activitywatch_data_path", "output_directory"):
        value = _value(config, ("context", key))
        if isinstance(value, str) and value and not Path(value).is_absolute():
            errors.append(f"context.{key} must be an absolute path")
    for key in ("sync_lookback_minutes", "overlap_minutes", "max_backfill_hours", "incident_before_minutes", "incident_after_minutes", "git_timeout_seconds"):
        value = _value(config, ("context", key))
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            errors.append(f"context.{key} must be a non-negative number")
    _require_bool(config, ("context", "git_push"), errors)

    threshold_orders = (
        (
            ("thresholds", "disk"),
            ("warning_free_percent", "critical_free_percent", "emergency_free_percent"),
            False,
        ),
        (("thresholds", "inode"), ("warning_free_percent", "critical_free_percent"), False),
        (("thresholds", "temperature"), ("cpu_warning_c", "cpu_critical_c"), True),
        (("thresholds", "temperature"), ("nvme_warning_c", "nvme_critical_c"), True),
        (("thresholds", "memory"), ("ram_warning_percent", "ram_critical_percent"), True),
        (("thresholds", "memory"), ("available_critical_percent", "available_warning_percent"), True),
        (("thresholds", "battery"), ("health_critical_percent", "health_warning_percent"), True),
    )
    for base, keys, ascending in threshold_orders:
        _ordered_thresholds(config, base, keys, errors, ascending=ascending)

    for path in (
        ("thresholds", "disk", "warning_free_percent"),
        ("thresholds", "disk", "critical_free_percent"),
        ("thresholds", "disk", "emergency_free_percent"),
        ("thresholds", "disk", "recovery_hysteresis_percent"),
        ("thresholds", "inode", "warning_free_percent"),
        ("thresholds", "inode", "critical_free_percent"),
        ("thresholds", "inode", "recovery_hysteresis_percent"),
        ("thresholds", "memory", "ram_warning_percent"),
        ("thresholds", "memory", "ram_critical_percent"),
        ("thresholds", "memory", "available_warning_percent"),
        ("thresholds", "memory", "available_critical_percent"),
        ("thresholds", "memory", "psi_some_warning_percent"),
        ("thresholds", "memory", "psi_full_critical_percent"),
        ("thresholds", "memory", "recovery_hysteresis_percent"),
        ("thresholds", "battery", "health_warning_percent"),
        ("thresholds", "battery", "health_critical_percent"),
        ("thresholds", "battery", "recovery_hysteresis_percent"),
    ):
        _require_percent(config, path, errors)

    for path in (
        ("thresholds", "disk", "absolute_free_gib"),
        ("thresholds", "temperature", "cpu_warning_duration_seconds"),
        ("thresholds", "temperature", "nvme_warning_duration_seconds"),
        ("thresholds", "temperature", "recovery_hysteresis_c"),
        ("thresholds", "memory", "ram_warning_duration_seconds"),
        ("thresholds", "memory", "swap_out_warning_mib_per_second"),
        ("thresholds", "memory", "reclaim_warning_pages_per_second"),
        ("thresholds", "network", "wifi_down_duration_seconds"),
        ("thresholds", "network", "internet_down_duration_seconds"),
        ("thresholds", "network", "disconnect_count"),
        ("thresholds", "network", "disconnect_window_minutes"),
        ("thresholds", "network", "recovery_samples"),
        ("thresholds", "services", "restart_loop_count"),
        ("thresholds", "services", "restart_loop_window_minutes"),
    ):
        _require_positive(config, path, errors)

    if not isinstance(config.get("retention"), Mapping):
        errors.append("retention must be a table")
    for key in (
        "minute_days",
        "five_minute_days",
        "fifteen_minute_days",
        "hourly_days",
        "daily_days",
        "hardware_event_days",
        "general_event_days",
        "alert_days",
        "inventory_daily_days",
        "backup_daily_count",
        "backup_weekly_count",
        "backup_monthly_count",
    ):
        _require_positive(config, ("retention", key), errors)

    if not isinstance(config.get("notifications"), Mapping):
        errors.append("notifications must be a table")
    _require_string(config, ("notifications", "uptime_kuma_credentials"), errors)
    _require_string(config, ("notifications", "telegram_credentials"), errors)
    _require_positive(config, ("notifications", "filesystem_free_change_gib"), errors)
    _require_positive(config, ("notifications", "reminder_seconds"), errors)
    _require_positive(config, ("notifications", "timeout_seconds"), errors)
    _require_list(config, ("notifications", "inverted_categories"), errors)
    require_string_items(("notifications", "inverted_categories"))
    return errors


__all__ = ["ConfigError", "DEFAULT_CONFIG", "load_config", "redact_text", "validate_config"]
