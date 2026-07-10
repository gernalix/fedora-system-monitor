"""Optional, secret-safe Uptime Kuma push notifications."""

from __future__ import annotations

import os
import tomllib
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

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
    return Path(config.get("notifications", {}).get("uptime_kuma_credentials", "/etc/fedora-system-monitor/uptime-kuma.toml"))


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


__all__ = ["NotificationResult", "endpoint_key", "integration_status", "notify_signals", "send_category_heartbeat", "send_heartbeat"]
