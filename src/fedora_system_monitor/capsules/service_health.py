"""Per-service systemd health projection to independent Uptime Kuma push monitors."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from fedora_system_monitor.capsules.kuma_admin import KumaMonitorSpec
from fedora_system_monitor.capsules.notifications import (
    NotificationResult,
    configured_push_keys,
    send_named_heartbeat,
)


def service_monitor_key(state_id: str) -> str:
    """Stable, TOML-safe endpoint key for one systemd service identity."""
    identity = state_id.strip()
    slug = re.sub(r"[^a-z0-9]+", "_", identity.lower()).strip("_") or "service"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:10]
    return f"service_{slug[:72]}_{digest}"


def service_monitor_spec(state_id: str) -> KumaMonitorSpec:
    identity = state_id.strip()
    if not identity:
        raise ValueError("service identity must not be empty")
    return KumaMonitorSpec(
        service_monitor_key(identity),
        f"Fedora Service · {identity}",
        f"Independent systemd health for {identity}; state is pushed by Fedora System Monitor.",
        180,
        60,
        2,
    )


def service_monitor_specs(state_ids: Iterable[str]) -> tuple[KumaMonitorSpec, ...]:
    return tuple(service_monitor_spec(identity) for identity in sorted({item.strip() for item in state_ids if item.strip()}))


def _details(row: Mapping[str, Any]) -> dict[str, Any]:
    raw = row.get("details_json")
    if not raw:
        return {}
    try:
        value = json.loads(str(raw))
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _fresh(timestamp: object, *, now: datetime, max_age_seconds: int) -> bool:
    try:
        observed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    age = (now - observed.astimezone(timezone.utc)).total_seconds()
    return -30 <= age <= max_age_seconds


def _healthy(row: Mapping[str, Any], details: Mapping[str, Any], *, fresh: bool, collector_failed: bool) -> bool:
    if collector_failed or not fresh:
        return False
    active = str(details.get("active_state") or "") == "active"
    successful_oneshot = bool(details.get("successful_inactive_oneshot"))
    failed = (
        str(details.get("active_state") or "") == "failed"
        or str(details.get("result") or "") not in {"", "success"}
        or bool(details.get("restart_loop"))
    )
    return not failed and (active or successful_oneshot)


def send_service_heartbeats(
    config: dict[str, Any],
    db: Any,
    *,
    collector_failed: bool = False,
    ping_ms: int | None = None,
    max_age_seconds: int = 180,
    now: datetime | None = None,
) -> list[NotificationResult]:
    """Push health for services that have an independently provisioned endpoint.

    Presence in the credential file is the explicit allowlist. This keeps stock
    Fedora services out while allowing newly registered custom services to start
    emitting immediately after their Kuma monitor is provisioned.
    """
    configured = configured_push_keys(config)
    service_keys = {key for key in configured if key.startswith("service_")}
    if not service_keys:
        return []
    rows = db.query(
        """
        SELECT p.device_id,p.value,p.timestamp_utc,p.details_json
        FROM periodic_metrics p
        JOIN (
          SELECT device_id,MAX(id) AS id
          FROM periodic_metrics
          WHERE name='service.active' AND device_id IS NOT NULL
          GROUP BY device_id
        ) latest ON latest.id=p.id
        ORDER BY p.device_id
        """
    )
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    results: list[NotificationResult] = []
    for row in rows:
        state_id = str(row.get("device_id") or "").strip()
        if not state_id:
            continue
        endpoint = service_monitor_key(state_id)
        if endpoint not in service_keys:
            continue
        details = _details(row)
        fresh = _fresh(row.get("timestamp_utc"), now=current, max_age_seconds=max_age_seconds)
        healthy = _healthy(row, details, fresh=fresh, collector_failed=collector_failed)
        active_state = str(details.get("active_state") or "unknown")
        sub_state = str(details.get("sub_state") or "unknown")
        reason = "collector failed" if collector_failed else "stale sample" if not fresh else f"{active_state}/{sub_state}"
        if details.get("restart_loop"):
            reason += "; restart loop"
        results.append(
            send_named_heartbeat(
                config,
                endpoint,
                healthy=healthy,
                message=f"{state_id}: {reason}",
                ping_ms=ping_ms,
            )
        )
    return results


__all__ = [
    "send_service_heartbeats",
    "service_monitor_key",
    "service_monitor_spec",
    "service_monitor_specs",
]
