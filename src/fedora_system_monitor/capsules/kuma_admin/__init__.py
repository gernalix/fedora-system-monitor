"""One-time, token-safe Uptime Kuma monitor provisioning via an authenticated Chrome session."""

from __future__ import annotations

import json
import os
import secrets
import string
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


@dataclass(frozen=True)
class KumaMonitorSpec:
    key: str
    name: str
    description: str
    interval: int
    retry_interval: int
    max_retries: int
    timeout: int = 48


DEFAULT_MONITORS = (
    KumaMonitorSpec("system", "Fedora Host", "Fedora host health: CPU, memory, swap, temperatures and critical kernel events.", 180, 60, 2),
    KumaMonitorSpec("storage", "Fedora Storage", "Fedora storage health: free space, inodes, read-only mounts, I/O errors and SMART.", 480, 180, 2),
    KumaMonitorSpec("network", "Fedora Network", "Fedora network health: Internet, gateway, Wi-Fi, addresses and VPN state.", 180, 60, 2),
    KumaMonitorSpec("services", "Fedora Services", "Fedora systemd health: essential services, failures, recoveries and restart loops.", 180, 60, 2),
    KumaMonitorSpec("software", "Fedora Software", "Fedora software health: package transactions, pending updates and inventory changes.", 5400, 900, 2),
)


def _varint(data: bytes, position: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        if position >= len(data):
            raise ValueError("truncated varint")
        byte = data[position]
        position += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, position
        shift += 7
    raise ValueError("invalid varint")


def _block_entries(data: bytes) -> Iterable[tuple[bytes, bytes]]:
    if len(data) < 4:
        return
    restart_count = int.from_bytes(data[-4:], "little")
    entries_end = len(data) - 4 * (restart_count + 1)
    position = 0
    previous = b""
    while 0 <= position < entries_end:
        try:
            shared, position = _varint(data, position)
            non_shared, position = _varint(data, position)
            value_length, position = _varint(data, position)
        except ValueError:
            return
        if shared > len(previous) or position + non_shared + value_length > entries_end:
            return
        key = previous[:shared] + data[position : position + non_shared]
        position += non_shared
        value = data[position : position + value_length]
        position += value_length
        previous = key
        yield key, value


def _read_block(file_data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size + 5 > len(file_data):
        raise ValueError("invalid LevelDB block")
    raw = file_data[offset : offset + size]
    compression = file_data[offset + size]
    if compression == 0:
        return raw
    if compression == 1:
        try:
            import snappy
        except ImportError as exc:
            raise RuntimeError("python3-snappy is required to read the Chrome session") from exc
        return snappy.decompress(raw)
    raise ValueError("unsupported LevelDB compression")


def _block_handle(data: bytes) -> tuple[int, int]:
    offset, position = _varint(data, 0)
    size, _ = _varint(data, position)
    return offset, size


def _decode_local_storage(raw: bytes) -> str:
    if not raw:
        return ""
    try:
        return raw[1:].decode("utf-16-le" if raw[0] == 0 else "utf-8")
    except (UnicodeDecodeError, IndexError):
        return ""


def recover_chrome_session_token(profile: str | Path, origin: str) -> str:
    """Recover only the Kuma JWT from Chrome LevelDB; the value never leaves memory."""
    profile_path = Path(profile)
    leveldb = profile_path / "Default/Local Storage/leveldb"
    prefix = b"_" + origin.rstrip("/").encode("utf-8") + b"\x00"
    latest: dict[str, tuple[int, int, bytes]] = {}
    for path in leveldb.glob("*.ldb"):
        try:
            file_data = path.read_bytes()
            footer = file_data[-48:]
            _, position = _varint(footer, 0)
            _, position = _varint(footer, position)
            index_offset, position = _varint(footer, position)
            index_size, _ = _varint(footer, position)
            index = _read_block(file_data, index_offset, index_size)
        except (OSError, ValueError, RuntimeError):
            continue
        for _, index_value in _block_entries(index) or ():
            try:
                offset, size = _block_handle(index_value)
                block = _read_block(file_data, offset, size)
            except (ValueError, RuntimeError):
                continue
            for internal_key, value in _block_entries(block) or ():
                if len(internal_key) < 8:
                    continue
                user_key = internal_key[:-8]
                if not user_key.startswith(prefix):
                    continue
                tag = int.from_bytes(internal_key[-8:], "little")
                sequence, record_type = tag >> 8, tag & 255
                key = _decode_local_storage(user_key[len(prefix) :])
                if key and (key not in latest or sequence > latest[key][0]):
                    latest[key] = (sequence, record_type, value)
    token_record = latest.get("token")
    token = _decode_local_storage(token_record[2]) if token_record and token_record[1] == 1 else ""
    if len(token) < 40 or len(token) > 4096:
        raise RuntimeError("authenticated Kuma session is not available in the Chrome profile")
    return token


def _monitor_payload(
    spec: KumaMonitorSpec,
    token: str,
    notification_ids: Mapping[str, bool],
    *,
    upside_down: bool = False,
) -> dict[str, Any]:
    return {
        "active": True,
        "type": "push",
        "name": spec.name,
        "description": spec.description,
        "parent": None,
        "url": "https://",
        "method": "GET",
        "protocol": None,
        "location": "world",
        "interval": spec.interval,
        "retryInterval": spec.retry_interval,
        "resendInterval": 0,
        "maxretries": spec.max_retries,
        "timeout": spec.timeout,
        "retryOnlyOnStatusCodeFailure": False,
        "notificationIDList": dict(notification_ids),
        "ignoreTls": False,
        "upsideDown": upside_down,
        "expiryNotification": False,
        "domainExpiryNotification": False,
        "maxredirects": 10,
        "accepted_statuscodes": ["200-299"],
        "saveResponse": False,
        "saveErrorResponse": True,
        "responseMaxLength": 1024,
        "dns_resolve_type": "A",
        "dns_resolve_server": "",
        "docker_container": "",
        "docker_host": None,
        "proxyId": None,
        "kafkaProducerBrokers": [],
        "kafkaProducerSaslOptions": {"mechanism": "None"},
        "kafkaProducerSsl": False,
        "kafkaProducerAllowAutoTopicCreation": False,
        "rabbitmqNodes": [],
        "conditions": [],
        "pushToken": token,
    }


def _default_notifications(raw: object) -> dict[str, bool]:
    items = list(raw.values()) if isinstance(raw, Mapping) else list(raw) if isinstance(raw, list) else []
    selected: dict[str, bool] = {}
    for item in items:
        if not isinstance(item, Mapping) or not item.get("active", True):
            continue
        if item.get("isDefault") or item.get("is_default"):
            selected[str(item["id"])] = True
    return selected


def _write_credentials(path: Path, base_url: str, tokens: Mapping[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    lines = ["[push]"]
    for key in sorted(tokens):
        url = f"{base_url.rstrip('/')}/api/push/{tokens[key]}"
        lines.append(f"{key} = {json.dumps(url)}")
    lines.extend(("", "[transport]", f"allow_insecure_http = {'true' if urlsplit(base_url).scheme == 'http' else 'false'}", ""))
    descriptor, temporary = tempfile.mkstemp(prefix=".uptime-kuma-", suffix=".toml", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary).unlink(missing_ok=True)
        raise


def _monitor_upside_down(current: Mapping[str, Any] | None) -> bool:
    """Preserve an existing Kuma inversion flag when reconciling monitors."""
    if not isinstance(current, Mapping):
        return False
    return bool(current.get("upsideDown", current.get("upside_down", False)))


def configure_push_monitors(
    *,
    base_url: str,
    chrome_profile: str | Path,
    credentials_path: str | Path,
    specs: Iterable[KumaMonitorSpec] = DEFAULT_MONITORS,
) -> dict[str, Any]:
    """Create/reuse a small exact-name monitor set and write root-only endpoints."""
    if urlsplit(base_url).scheme not in {"http", "https"}:
        raise ValueError("Kuma base URL must use HTTP or HTTPS")
    specs = tuple(specs)
    token = recover_chrome_session_token(chrome_profile, base_url)
    try:
        import socketio
    except ImportError as exc:
        raise RuntimeError("python3-socketio is required for Kuma configuration") from exc

    monitor_list: dict[str, dict[str, Any]] = {}
    notification_list: object = []
    monitor_ready = threading.Event()
    notification_ready = threading.Event()
    client = socketio.Client(logger=False, engineio_logger=False, reconnection=False, request_timeout=10)

    @client.on("monitorList")
    def receive_monitors(data: object) -> None:
        monitor_list.clear()
        if isinstance(data, Mapping):
            monitor_list.update({str(key): dict(value) for key, value in data.items() if isinstance(value, Mapping)})
        monitor_ready.set()

    @client.on("notificationList")
    def receive_notifications(data: object) -> None:
        nonlocal notification_list
        notification_list = data
        notification_ready.set()

    created: list[dict[str, Any]] = []
    reused: list[dict[str, Any]] = []
    tokens: dict[str, str] = {}
    try:
        client.connect(base_url, transports=["polling"], wait_timeout=20)
        login: object = None
        for attempt in range(2):
            try:
                login = client.call("loginByToken", token, timeout=30)
                break
            except Exception:
                if attempt == 0:
                    time.sleep(2)
        if not isinstance(login, Mapping) or not login.get("ok"):
            raise RuntimeError("Kuma rejected the authenticated Chrome session")
        monitor_ready.wait(5)
        client.call("getMonitorList", timeout=15)
        monitor_ready.wait(10)
        notification_ready.wait(5)
        notifications = _default_notifications(notification_list)

        for spec in specs:
            matches = [(monitor_id, item) for monitor_id, item in monitor_list.items() if item.get("name") == spec.name]
            if len(matches) > 1:
                raise RuntimeError(f"duplicate Kuma monitor name: {spec.name}")
            if matches:
                monitor_id, existing = matches[0]
                if existing.get("type") != "push" or not existing.get("pushToken"):
                    raise RuntimeError(f"existing Kuma monitor is not reusable push type: {spec.name}")
                existing_token = str(existing["pushToken"])
                details = client.call("getMonitor", int(monitor_id), timeout=15)
                current = details.get("monitor") if isinstance(details, Mapping) else None
                current_notifications = current.get("notificationIDList", {}) if isinstance(current, Mapping) else {}
                payload = _monitor_payload(
                    spec,
                    existing_token,
                    current_notifications or notifications,
                    upside_down=_monitor_upside_down(current),
                )
                payload["id"] = int(monitor_id)
                edited = client.call("editMonitor", payload, timeout=20)
                if not isinstance(edited, Mapping) or not edited.get("ok"):
                    raise RuntimeError(f"Kuma failed to update monitor: {spec.name}")
                tokens[spec.key] = existing_token
                reused.append({"id": int(monitor_id), "name": spec.name})
                continue
            push_token = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
            response = client.call("add", _monitor_payload(spec, push_token, notifications), timeout=20)
            if not isinstance(response, Mapping) or not response.get("ok"):
                raise RuntimeError(f"Kuma failed to create monitor: {spec.name}")
            monitor_id = int(response["monitorID"])
            tokens[spec.key] = push_token
            created.append({"id": monitor_id, "name": spec.name})

        _write_credentials(Path(credentials_path), base_url, tokens)
        monitor_ready.clear()
        client.call("getMonitorList", timeout=15)
        monitor_ready.wait(10)
        verified = [
            {"id": int(monitor_id), "name": item.get("name"), "active": bool(item.get("active")), "type": item.get("type")}
            for monitor_id, item in monitor_list.items()
            if item.get("name") in {spec.name for spec in specs}
        ]
        if len(verified) != len(specs) or not all(item["active"] and item["type"] == "push" for item in verified):
            raise RuntimeError("Kuma monitor verification failed after provisioning")
        return {
            "created": created,
            "reused": reused,
            "verified": sorted(verified, key=lambda item: item["id"]),
            "default_notifications_bound": bool(notifications),
            "credentials_path": str(credentials_path),
            "transport_secure": urlsplit(base_url).scheme == "https",
        }
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Kuma administration API failed: {exc.__class__.__name__}") from None
    finally:
        token = ""
        if client.connected:
            client.disconnect()


__all__ = [
    "DEFAULT_MONITORS",
    "KumaMonitorSpec",
    "configure_push_monitors",
    "recover_chrome_session_token",
]
