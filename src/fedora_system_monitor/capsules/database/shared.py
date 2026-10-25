"""Shared data and error contracts for SQLite persistence capsules."""

from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any

from ..config import redact_text

_SEVERITY_RANK = {"debug": 0, "info": 1, "warning": 2, "critical": 3, "emergency": 4}
_SECRET_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "credentials",
    "password",
    "passwd",
    "secret",
    "token",
}

class StorageError(RuntimeError):
    """Raised for unsupported schemas or invalid persistence operations."""


def _sanitize(value: Any, key: str | None = None) -> Any:
    if key is not None and key.lower().replace("-", "_") in _SECRET_KEYS:
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(item_key): _sanitize(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(value)


def _json_dumps(value: Any) -> str:
    return json.dumps(_sanitize(value), ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _json_loads(value: str | None, default: Any = None) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default
