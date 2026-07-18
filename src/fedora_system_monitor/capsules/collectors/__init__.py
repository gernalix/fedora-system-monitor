"""Stable orchestration API for all periodic and event-driven collectors."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import time
from typing import Any

from .model import CADENCE_SECONDS, CollectionResult, record
from .periodic import (
    collect_backup_processes,
    collect_diskstats,
    collect_expected_mounts,
    collect_filesystems,
    collect_journal_io,
    collect_network_detail,
    collect_network_essential,
    collect_network_stability,
    collect_power,
    collect_proc,
    collect_processes,
    collect_services,
    collect_temperatures,
    discover_services,
)
from .software import (
    collect_full_software_inventory,
    collect_manual_changes,
    collect_package_snapshot,
    collect_software_history,
    collect_updates,
)
from .system import (
    collect_battery_health,
    collect_btrfs_health,
    collect_coredumps,
    collect_db_check,
    collect_directory_sizes,
    collect_hardware_inventory,
    collect_smart,
    collect_uptime_kernel,
    collect_weekly_diagnostics,
)


Collector = Callable[[str, Mapping[str, Any], object], CollectionResult]


def _critical_filesystems(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    return collect_filesystems(scope, config, db, all_relevant=False)


def _all_filesystems(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    return collect_filesystems(scope, config, db, all_relevant=True)


def _smart_synthetic(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    return collect_smart(scope, config, db, detailed=False)


def _smart_detailed(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    return collect_smart(scope, config, db, detailed=True)


def _db_quick(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    return collect_db_check(scope, config, db, quick=True)


_COLLECTORS: dict[str, tuple[tuple[str, Collector], ...]] = {
    "minute": (
        ("proc", collect_proc),
        ("critical_filesystems", _critical_filesystems),
        ("services", collect_services),
        ("network_essential", collect_network_essential),
        ("power", collect_power),
    ),
    "five_minute": (
        ("filesystems", _all_filesystems),
        ("network_detail", collect_network_detail),
        ("temperatures", collect_temperatures),
        ("processes", collect_processes),
        ("services", collect_services),
        ("power", collect_power),
    ),
    "fifteen_minute": (
        ("diskstats", collect_diskstats),
        ("journal_io", collect_journal_io),
        ("network_stability", collect_network_stability),
        ("expected_mounts", collect_expected_mounts),
        ("backup_processes", collect_backup_processes),
    ),
    "hourly": (
        ("package_snapshot", collect_package_snapshot),
        ("updates", collect_updates),
        ("software_history", collect_software_history),
        ("manual_changes", collect_manual_changes),
        ("smart", _smart_synthetic),
        ("uptime_kernel", collect_uptime_kernel),
        ("coredumps", collect_coredumps),
    ),
    "daily": (
        ("software_inventory", collect_full_software_inventory),
        ("hardware_inventory", collect_hardware_inventory),
        ("smart_detailed", _smart_detailed),
        ("btrfs_health", collect_btrfs_health),
        ("battery_health", collect_battery_health),
        ("directory_sizes", collect_directory_sizes),
        ("updates", collect_updates),
        ("database_quick_check", _db_quick),
        ("expected_mounts", collect_expected_mounts),
    ),
    "weekly": (
        ("weekly_diagnostics", collect_weekly_diagnostics),
        ("software_inventory", collect_full_software_inventory),
        ("package_snapshot", collect_package_snapshot),
    ),
    "software_event": (
        ("software_history", collect_software_history),
        ("manual_changes", collect_manual_changes),
    ),
}


def collect_scope(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    """Collect *scope* with per-collector fault and timeout isolation.

    The function never persists metrics, events, or inventory rows itself; the
    coordinator owns that transaction. Only small delta/dedup snapshots are
    updated through ``db.get_state`` and ``db.set_state``.
    """

    if scope not in _COLLECTORS:
        choices = ", ".join(sorted(_COLLECTORS))
        raise ValueError(f"unsupported collector scope {scope!r}; expected one of: {choices}")
    if not isinstance(config, Mapping):
        raise TypeError("collector config must be a mapping")
    started = time.monotonic()
    result = CollectionResult(scope)
    cadence = CADENCE_SECONDS[scope]
    for name, collector in _COLLECTORS[scope]:
        try:
            partial = collector(scope, config, db)
            if not isinstance(partial, CollectionResult):
                raise TypeError("collector returned an invalid result")
            result.merge(partial)
        except Exception as exc:
            message = f"collector raised {type(exc).__name__}"
            result.errors.append(f"{name}: {message}")
            result.events.append(
                record(
                    cadence,
                    "collector",
                    "collector_failure",
                    1,
                    "failure",
                    severity="warning",
                    source=f"collector:{name}",
                    details={"collector": name, "exception_type": type(exc).__name__},
                    outcome="error",
                    error_message=message,
                )
            )
    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


__all__ = ["CADENCE_SECONDS", "CollectionResult", "collect_scope", "discover_services"]
