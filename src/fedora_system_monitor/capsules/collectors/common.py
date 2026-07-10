"""Internal, dependency-free helpers for collector capsules."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import pwd
import time
from typing import Any

from ..command import CommandResult, run_command
from ..config import redact_text
from .model import CollectionResult, record


def config_value(
    config: Mapping[str, Any],
    *paths: Sequence[str],
    default: Any = None,
) -> Any:
    """Return the first configured value among compatible schema paths."""

    for path in paths:
        current: Any = config
        for component in path:
            if not isinstance(current, Mapping) or component not in current:
                break
            current = current[component]
        else:
            return current
    return default


def command_timeout(config: Mapping[str, Any], default: float = 12.0) -> float:
    value = config_value(
        config,
        ("monitor", "command_timeout_seconds"),
        ("general", "command_timeout_seconds"),
        default=default,
    )
    try:
        return max(0.1, float(value))
    except (TypeError, ValueError):
        return default


def external(
    config: Mapping[str, Any],
    args: Sequence[str],
    *,
    timeout: float | None = None,
    env: Mapping[str, str] | None = None,
    max_output: int = 2_000_000,
) -> CommandResult:
    return run_command(
        args,
        timeout=timeout if timeout is not None else command_timeout(config),
        env=env,
        max_output=max_output,
    )


def operator_identity(config: Mapping[str, Any]) -> tuple[str, Path, int]:
    user = str(config_value(config, ("monitor", "operator_user"), default="daniele"))
    configured_home = config_value(config, ("inventory", "user_home"), default=None)
    try:
        account = pwd.getpwnam(user)
        home = Path(str(configured_home or account.pw_dir))
        return user, home, account.pw_uid
    except KeyError:
        return user, Path(str(configured_home or f"/home/{user}")), -1


def operator_external(
    config: Mapping[str, Any],
    args: Sequence[str],
    *,
    timeout: float | None = None,
    max_output: int = 2_000_000,
    extra_env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run a read-only command in the operator's minimal environment."""

    user, home, uid = operator_identity(config)
    environment = [
        f"HOME={home}",
        f"USER={user}",
        f"LOGNAME={user}",
        f"XDG_CONFIG_HOME={home / '.config'}",
        f"XDG_DATA_HOME={home / '.local' / 'share'}",
        f"XDG_CACHE_HOME={home / '.cache'}",
        f"XDG_RUNTIME_DIR=/run/user/{uid}" if uid >= 0 else "XDG_RUNTIME_DIR=",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "LC_ALL=C.UTF-8",
    ]
    if extra_env:
        environment.extend(f"{key}={value}" for key, value in extra_env.items())
    try:
        current_user = pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        current_user = ""
    if current_user == user:
        command = ["env", "-i", *environment, *map(str, args)]
    else:
        command = ["runuser", "-u", user, "--", "env", "-i", *environment, *map(str, args)]
    return external(config, command, timeout=timeout, max_output=max_output)


def command_problem(result: CommandResult) -> str:
    """Return a bounded diagnostic that never includes argv or command output."""

    if result.missing:
        return "command unavailable"
    if result.timed_out:
        return "command timed out"
    return f"command exited with status {result.returncode}"


def failure_result(scope: str, source: str, message: object) -> CollectionResult:
    safe = redact_text(message)[:500]
    result = CollectionResult(scope)
    result.errors.append(f"{source}: {safe}")
    result.events.append(
        record(
            0,
            "collector",
            "collector_failure",
            1,
            "failure",
            severity="warning",
            source=source,
            details={"collector": source},
            outcome="error",
            error_message=safe,
        )
    )
    return result


def state_get(db: object, key: str, default: Any = None) -> Any:
    getter = getattr(db, "get_state", None)
    if getter is None:
        return default
    try:
        return getter(key, default, namespace="collector")
    except TypeError:
        try:
            return getter(key, default)
        except TypeError:
            value = getter(key)
            return default if value is None else value
    except Exception:
        return default


def state_set(db: object, key: str, value: Any) -> bool:
    setter = getattr(db, "set_state", None)
    if setter is None:
        return False
    try:
        setter(key, value, namespace="collector")
        return True
    except TypeError:
        setter(key, value)
        return True
    except Exception:
        return False


def json_output(result: CommandResult, default: Any = None) -> Any:
    if not result.ok:
        return default
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return default


def fingerprint(value: Any) -> str:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8", "replace")).hexdigest()


def stable_hash(value: str, prefix: str = "id") -> str:
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:20]
    return f"{prefix}:{digest}"


def hash_file(path: Path, max_bytes: int) -> str | None:
    try:
        stat = path.stat()
        if not path.is_file() or stat.st_size > max_bytes:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def bounded_metadata_snapshot(
    roots: Iterable[str | Path],
    *,
    previous: Mapping[str, Any] | None = None,
    max_depth: int = 4,
    max_hash_bytes: int = 16 * 1024 * 1024,
    suffixes: set[str] | None = None,
    include_executables: bool = True,
    max_entries: int = 20_000,
) -> tuple[dict[str, dict[str, Any]], bool]:
    """Collect progressive file metadata without following links or mount drift."""

    snapshot: dict[str, dict[str, Any]] = {}
    previous = previous or {}
    excluded = {".git", ".cache", "__pycache__", "node_modules", ".gradle"}
    truncated = False
    for configured_root in roots:
        root = Path(configured_root)
        if not root.exists():
            continue
        try:
            root_dev = root.stat().st_dev
        except OSError:
            continue
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            current = Path(directory)
            try:
                relative_depth = len(current.relative_to(root).parts)
            except ValueError:
                continue
            dirnames[:] = [
                name
                for name in dirnames
                if name not in excluded
                and relative_depth < max_depth
                and _same_device(current / name, root_dev)
            ]
            if relative_depth > max_depth:
                dirnames[:] = []
                continue
            for filename in filenames:
                path = current / filename
                try:
                    stat = path.lstat()
                except OSError:
                    continue
                if not path.is_file() or path.is_symlink():
                    continue
                if suffixes and path.suffix.lower() not in suffixes:
                    if not include_executables or not stat.st_mode & 0o111:
                        continue
                key = str(path)
                item: dict[str, Any] = {
                    "size_bytes": stat.st_size,
                    "mtime_ns": stat.st_mtime_ns,
                    "inode": stat.st_ino,
                }
                old = previous.get(key)
                identity = (stat.st_size, stat.st_mtime_ns, stat.st_ino)
                old_identity = None
                if isinstance(old, Mapping):
                    old_identity = (old.get("size_bytes"), old.get("mtime_ns"), old.get("inode"))
                if old_identity != identity:
                    content_hash = hash_file(path, max_hash_bytes)
                    if content_hash:
                        item["content_hash"] = content_hash
                elif isinstance(old, Mapping) and old.get("content_hash"):
                    item["content_hash"] = old["content_hash"]
                snapshot[key] = item
                if len(snapshot) >= max_entries:
                    truncated = True
                    return snapshot, truncated
    return snapshot, truncated


def _same_device(path: Path, expected_device: int) -> bool:
    try:
        return path.lstat().st_dev == expected_device and not path.is_symlink()
    except OSError:
        return False


def metadata_changes(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    limit: int = 250,
) -> tuple[list[tuple[str, str, Any]], bool]:
    changes: list[tuple[str, str, Any]] = []
    for path in sorted(set(current) - set(previous)):
        changes.append(("install", path, current[path]))
    for path in sorted(set(previous) - set(current)):
        changes.append(("remove", path, previous[path]))
    for path in sorted(set(current) & set(previous)):
        if current[path] != previous[path]:
            changes.append(("modify", path, current[path]))
    return changes[:limit], len(changes) > limit


def sustained_severity(
    db: object,
    state_key: str,
    value: float,
    *,
    warning: float,
    critical: float,
    duration_seconds: float,
    now: float | None = None,
) -> str:
    now = time.time() if now is None else now
    state = state_get(db, state_key, {})
    if not isinstance(state, Mapping):
        state = {}
    if value >= critical:
        state_set(db, state_key, {"since": state.get("since", now), "last": now})
        return "critical"
    if value >= warning:
        since = float(state.get("since", now))
        last = float(state.get("last", now))
        if now - last > max(duration_seconds, 120.0) * 2:
            since = now
        state_set(db, state_key, {"since": since, "last": now})
        return "warning" if now - since >= duration_seconds else "info"
    state_set(db, state_key, {})
    return "info"


__all__ = [
    "bounded_metadata_snapshot",
    "command_problem",
    "command_timeout",
    "config_value",
    "external",
    "failure_result",
    "fingerprint",
    "hash_file",
    "json_output",
    "metadata_changes",
    "operator_external",
    "operator_identity",
    "stable_hash",
    "state_get",
    "state_set",
    "sustained_severity",
]
