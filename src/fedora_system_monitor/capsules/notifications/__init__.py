"""Optional, secret-safe Uptime Kuma and Telegram notifications."""

from __future__ import annotations

import os
import tomllib
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from fedora_system_monitor.capsules.alerting import AlertSignal
from fedora_system_monitor.capsules.config import redact_text


@dataclass(frozen=True)
class NotificationResult:
    channel: str
    category: str
    attempted: bool
    delivered: bool
    status: str
    error: str = ""


def _credentials_path(config: dict[str, Any]) -> Path:
    credentials_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials_directory:
        candidate = Path(credentials_directory) / "uptime-kuma.toml"
        if candidate.is_file():
            return candidate
    return Path(
        config.get("notifications", {}).get(
            "uptime_kuma_credentials",
            "/home/daniele/.config/codex/secrets/fedora_system_monitor_uptime_kuma.toml",
        )
    )


def _telegram_credentials_path(config: Mapping[str, Any]) -> Path:
    return Path(
        str(
            config.get("notifications", {}).get(
                "telegram_credentials",
                "/home/daniele/.config/codex/secrets/telegram.env",
            )
        )
    )


def integration_status(config: dict[str, Any]) -> dict[str, Any]:
    """Return configuration state without returning any endpoint value."""
    path = _credentials_path(config)
    if not path.is_file():
        return {"configured": False, "secure": False, "categories": [], "reason": "credentials file absent"}
    try:
        if path.stat().st_mode & 0o077:
            return {"configured": False, "secure": False, "categories": [], "reason": "credentials file permissions are unsafe"}
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except PermissionError:
        return {
            "configured": None,
            "secure": None,
            "protected": True,
            "categories": [],
            "reason": "credentials file is root-only; use sudo to verify integration",
        }
    except (OSError, tomllib.TOMLDecodeError):
        return {"configured": False, "secure": False, "categories": [], "reason": "credentials file unreadable"}
    endpoints = data.get("push", {}) if isinstance(data, dict) else {}
    allow_http = bool(data.get("transport", {}).get("allow_insecure_http", False)) if isinstance(data, dict) else False
    configured = sorted(key for key, value in endpoints.items() if isinstance(value, str) and value.strip())
    secure = all(urllib.parse.urlsplit(endpoints[key]).scheme == "https" for key in configured)
    allowed = secure or (
        allow_http
        and configured
        and all(urllib.parse.urlsplit(endpoints[key]).scheme in {"http", "https"} for key in configured)
    )
    reason = "ready" if configured and secure else "ready with explicitly allowed HTTP" if allowed else "push URLs not configured with an allowed transport"
    return {"configured": bool(configured and allowed), "secure": secure, "categories": configured, "reason": reason}


def _load_endpoints(config: dict[str, Any]) -> dict[str, str]:
    path = _credentials_path(config)
    try:
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            return {}
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    endpoints = data.get("push", {}) if isinstance(data, dict) else {}
    allow_http = bool(data.get("transport", {}).get("allow_insecure_http", False)) if isinstance(data, dict) else False
    return {
        str(key): str(value).strip()
        for key, value in endpoints.items()
        if isinstance(value, str)
        and value.strip()
        and urllib.parse.urlsplit(value).scheme in ({"http", "https"} if allow_http else {"https"})
    }


def _push(url: str, *, up: bool, message: str, ping_ms: int | None, timeout: float) -> tuple[bool, str]:
    parsed = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query.update({"status": "up" if up else "down", "msg": redact_text(message)[:180]})
    if ping_ms is not None:
        query["ping"] = str(max(0, int(ping_ms)))
    target = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), ""))
    request = urllib.request.Request(target, headers={"User-Agent": "fedora-system-monitor/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            delivered = 200 <= response.status < 300
            return delivered, "delivered" if delivered else f"HTTP {response.status}"
    except Exception as exc:  # URL and token must never escape through exception text.
        return False, exc.__class__.__name__


def send_telegram_message(config: Mapping[str, Any], message: str) -> NotificationResult:
    credentials_path = _telegram_credentials_path(config)
    try:
        if credentials_path.stat().st_mode & 0o077:
            return NotificationResult("telegram", "filesystem", False, False, "not configured")
    except OSError:
        return NotificationResult("telegram", "filesystem", False, False, "not configured")
    previous_config = os.environ.get("TELEGRAM_NOTIFY_CONFIG")
    os.environ["TELEGRAM_NOTIFY_CONFIG"] = str(credentials_path)
    try:
        import telegram_notify

        telegram_notify.load_config_files()
        telegram_notify.validate_config()
        telegram_notify.send_message("Fedora System Monitor", redact_text(message))
        delivered = True
        status = "delivered"
    except Exception as exc:
        delivered = False
        status = exc.__class__.__name__
    finally:
        if previous_config is None:
            os.environ.pop("TELEGRAM_NOTIFY_CONFIG", None)
        else:
            os.environ["TELEGRAM_NOTIFY_CONFIG"] = previous_config
    return NotificationResult(
        "telegram",
        "filesystem",
        True,
        delivered,
        status,
        "" if delivered else status,
    )


def _gib(value: int) -> str:
    return f"{value / 1024**3:.2f} GiB"


def notify_filesystem_free_changes(
    metrics: Iterable[Mapping[str, Any]],
    config: Mapping[str, Any],
    db: Any,
) -> list[NotificationResult]:
    """Notify cumulative free-space changes for each underlying filesystem."""

    threshold = int(
        float(
            config.get("notifications", {}).get(
                "filesystem_free_change_gib",
                1.0,
            )
        )
        * 1024**3
    )
    selected: dict[str, Mapping[str, Any]] = {}
    for metric in metrics:
        if metric.get("name") != "filesystem_free_bytes":
            continue
        details = metric.get("details")
        if not isinstance(details, Mapping):
            continue
        identity = str(details.get("filesystem_id") or metric.get("device_id") or "").strip()
        mount_point = str(details.get("mount_point") or "").strip()
        if not identity or not mount_point:
            continue
        try:
            free_bytes = int(metric.get("value"))
        except (TypeError, ValueError):
            continue
        if free_bytes < 0:
            continue
        current = dict(metric)
        current["value"] = free_bytes
        previous = selected.get(identity)
        if previous is None:
            selected[identity] = current
            continue
        previous_details = previous.get("details", {})
        previous_mount = str(previous_details.get("mount_point") or "")
        if (mount_point != "/", len(mount_point), mount_point) < (
            previous_mount != "/",
            len(previous_mount),
            previous_mount,
        ):
            selected[identity] = current

    results: list[NotificationResult] = []
    for identity, metric in sorted(
        selected.items(),
        key=lambda item: str(item[1].get("details", {}).get("mount_point") or ""),
    ):
        free_bytes = int(metric["value"])
        mount_point = str(metric.get("details", {}).get("mount_point") or "")
        state_key = f"filesystem-free:{identity}"
        state = db.get_state(state_key, None, namespace="notification")
        baseline = state.get("notified_free_bytes") if isinstance(state, Mapping) else None
        if not isinstance(baseline, int):
            db.set_state(
                state_key,
                {
                    "notified_free_bytes": free_bytes,
                    "last_observed_free_bytes": free_bytes,
                    "mount_point": mount_point,
                },
                namespace="notification",
            )
            continue
        delta = free_bytes - baseline
        delivered = False
        if abs(delta) >= threshold:
            sign = "+" if delta >= 0 else "-"
            message = f"💾 {mount_point}: libero {_gib(free_bytes)}; variazione {sign}{_gib(abs(delta))}"
            notification = send_telegram_message(config, message)
            results.append(notification)
            delivered = notification.delivered
        db.set_state(
            state_key,
            {
                "notified_free_bytes": free_bytes if delivered else baseline,
                "last_observed_free_bytes": free_bytes,
                "mount_point": mount_point,
            },
            namespace="notification",
        )
    return results


def endpoint_key(category: str) -> str:
    return {
        "filesystem": "storage",
        "hardware": "storage",
        "storage": "storage",
        "network": "network",
        "service": "services",
        "services": "services",
        "software": "software",
    }.get(category, "system")


def notify_signals(signals: Iterable[AlertSignal], config: dict[str, Any]) -> list[NotificationResult]:
    endpoints = _load_endpoints(config)
    timeout = float(config.get("notifications", {}).get("timeout_seconds", 5))
    results: list[NotificationResult] = []
    grouped: dict[str, list[AlertSignal]] = {}
    for signal in signals:
        grouped.setdefault(endpoint_key(signal.category), []).append(signal)
    for category, group in grouped.items():
        url = endpoints.get(category) or endpoints.get("heartbeat")
        if not url:
            results.append(NotificationResult("uptime-kuma", category, False, False, "not configured"))
            continue
        active = [signal for signal in group if signal.active]
        up = not active
        selected = active or group
        message = "; ".join(signal.message for signal in selected[:3])
        if up:
            message = f"RECOVERY: {message}"
        delivered, status = _push(url, up=up, message=message, ping_ms=None, timeout=timeout)
        results.append(NotificationResult("uptime-kuma", category, True, delivered, status, "" if delivered else status))
    return results


def send_heartbeat(config: dict[str, Any], *, healthy: bool, message: str, ping_ms: int | None = None) -> NotificationResult:
    endpoints = _load_endpoints(config)
    url = endpoints.get("system") or endpoints.get("heartbeat")
    if not url:
        return NotificationResult("uptime-kuma", "heartbeat", False, False, "not configured")
    delivered, status = _push(
        url,
        up=healthy,
        message=message,
        ping_ms=ping_ms,
        timeout=float(config.get("notifications", {}).get("timeout_seconds", 5)),
    )
    return NotificationResult("uptime-kuma", "heartbeat", True, delivered, status, "" if delivered else status)


def send_category_heartbeat(
    config: dict[str, Any],
    category: str,
    *,
    healthy: bool,
    message: str,
    ping_ms: int | None = None,
) -> NotificationResult:
    endpoints = _load_endpoints(config)
    category = endpoint_key(category)
    url = endpoints.get(category)
    if not url:
        return NotificationResult("uptime-kuma", category, False, False, "not configured")
    delivered, status = _push(
        url,
        up=healthy,
        message=message,
        ping_ms=ping_ms,
        timeout=float(config.get("notifications", {}).get("timeout_seconds", 5)),
    )
    return NotificationResult("uptime-kuma", category, True, delivered, status, "" if delivered else status)


__all__ = [
    "NotificationResult",
    "endpoint_key",
    "integration_status",
    "notify_filesystem_free_changes",
    "notify_signals",
    "send_category_heartbeat",
    "send_heartbeat",
    "send_telegram_message",
]
