"""Data contracts shared by collector implementations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


CADENCE_SECONDS = {
    # Path-triggered snapshot metrics use the hourly retention tier.
    "software_event": 3600,
    "minute": 60,
    "five_minute": 300,
    "fifteen_minute": 900,
    "hourly": 3600,
    "daily": 86400,
    "weekly": 604800,
}


def record(
    cadence: int,
    category: str,
    name: str,
    value: float | int | None = None,
    unit: str | None = None,
    *,
    severity: str = "info",
    source: str,
    device_id: str | None = None,
    details: Mapping[str, Any] | None = None,
    outcome: str = "ok",
    error_message: str | None = None,
) -> dict[str, Any]:
    """Build the normalized record shape accepted by the database capsule."""

    return {
        "cadence": cadence,
        "category": category,
        "name": name,
        "value": value,
        "unit": unit,
        "severity": severity,
        "source": source,
        "device_id": device_id,
        "details": dict(details or {}),
        "outcome": outcome,
        "error_message": error_message,
    }


@dataclass
class CollectionResult:
    """One isolated collection run, including optional inventory snapshots."""

    scope: str
    metrics: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    hardware_inventory: list[dict[str, Any]] = field(default_factory=list)
    software_inventory: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0

    def merge(self, other: "CollectionResult") -> None:
        self.metrics.extend(other.metrics)
        self.events.extend(other.events)
        self.hardware_inventory.extend(other.hardware_inventory)
        self.software_inventory.extend(other.software_inventory)
        self.errors.extend(other.errors)


__all__ = ["CADENCE_SECONDS", "CollectionResult", "record"]
