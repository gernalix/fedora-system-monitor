"""Software history, update, and inventory collectors."""

from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
import re
import time
import tomllib
from typing import Any
from xml.etree import ElementTree

from .common import (
    bounded_metadata_snapshot,
    command_problem,
    config_value,
    external,
    fingerprint,
    metadata_changes,
    operator_external as _operator_external,
    operator_identity as _operator_identity,
    state_get,
    state_set,
)
from .dnf import collect_history
from .model import CADENCE_SECONDS, CollectionResult, record


def _rpm_inventory(config: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    query = r"%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n"
    output = external(config, ["rpm", "-qa", "--qf", query], max_output=4_000_000)
    if not output.ok:
        return [], command_problem(output)
    items: list[dict[str, Any]] = []
    for line in output.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            continue
        name, version, architecture, vendor = fields
        items.append(
            {
                "category": "software",
                "name": name,
                "item_key": f"rpm:{name}:{architecture}",
                "version": version,
                "architecture": architecture,
                "repository": "rpmdb",
                "source": "rpm",
                "details": {"vendor": vendor},
            }
        )
    return items, None


def _flatpak_inventory(config: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    items: list[dict[str, Any]] = []
    errors: list[str] = []
    for installation in ("system", "user"):
        args = ["flatpak", "list", f"--{installation}", "--columns=application,version,branch,arch,origin,installation", "--json"]
        output = _operator_external(config, args, max_output=2_000_000) if installation == "user" else external(config, args, max_output=2_000_000)
        if output.missing:
            return [], []
        if not output.ok:
            # An absent user installation is normal on a system-only host.
            if installation == "system":
                errors.append(f"flatpak {installation}: {command_problem(output)}")
            continue
        try:
            payload = json.loads(output.stdout or "[]")
        except json.JSONDecodeError:
            errors.append(f"flatpak {installation}: invalid JSON")
            continue
        if not isinstance(payload, list):
            continue
        for entry in payload:
            if not isinstance(entry, Mapping):
                continue
            application = str(entry.get("application_id") or entry.get("application") or "")
            if not application:
                continue
            branch = str(entry.get("branch") or "")
            architecture = str(entry.get("arch") or "")
            items.append(
                {
                    "category": "software",
                    "name": application,
                    "item_key": f"flatpak:{installation}:{application}:{branch}:{architecture}",
                    "version": str(entry.get("version") or branch),
                    "architecture": architecture,
                    "repository": str(entry.get("origin") or ""),
                    "owner_user": _operator_identity(config)[0] if installation == "user" else "root",
                    "source": "flatpak",
                    "details": {"branch": branch, "installation": installation},
                }
            )
    return items, errors


def collect_package_snapshot(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    rpm_items, rpm_error = _rpm_inventory(config)
    flatpak_items, flatpak_errors = _flatpak_inventory(config)
    if rpm_error:
        result.errors.append(f"rpm inventory: {rpm_error}")
    result.errors.extend(flatpak_errors)
    summary = {
        "rpm_count": len(rpm_items),
        "flatpak_count": len(flatpak_items),
        "rpm_fingerprint": fingerprint([(item["item_key"], item["version"]) for item in rpm_items]),
        "flatpak_fingerprint": fingerprint([(item["item_key"], item["version"]) for item in flatpak_items]),
    }
    previous = state_get(db, "software.package_summary", None)
    state_set(db, "software.package_summary", summary)
    result.metrics.extend(
        [
            record(cadence, "software", "installed_rpm_count", len(rpm_items), "packages", source="rpm"),
            record(cadence, "software", "installed_flatpak_count", len(flatpak_items), "refs", source="flatpak"),
        ]
    )
    if isinstance(previous, Mapping) and previous != summary:
        result.events.append(
            record(
                cadence,
                "software",
                "software_snapshot_changed",
                1,
                "event",
                source="inventory_diff",
                details={
                    "rpm_count_before": previous.get("rpm_count"),
                    "rpm_count_after": len(rpm_items),
                    "flatpak_count_before": previous.get("flatpak_count"),
                    "flatpak_count_after": len(flatpak_items),
                },
                outcome="detected",
            )
        )
    return result


def _dnf_update_count(output: str) -> int:
    count = 0
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0].lower() not in {"upgrades", "package", "name"}:
            if "." in fields[0] and not fields[0].endswith(":"):
                count += 1
    return count


def collect_updates(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    del db
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    updates = external(config, ["dnf", "--cacheonly", "check-upgrade", "--quiet"], timeout=max(30, float(config_value(config, ("monitor", "command_timeout_seconds"), ("general", "command_timeout_seconds"), default=12)) * 2))
    if updates.returncode in {0, 100} and not updates.timed_out and not updates.missing:
        count = _dnf_update_count(updates.stdout)
        result.metrics.append(record(cadence, "update", "dnf_updates_available", count, "packages", source="dnf5_cache"))
    else:
        result.errors.append(f"dnf updates: {command_problem(updates)}")

    security = external(config, ["dnf", "--cacheonly", "advisory", "list", "--updates", "--security", "--json"], timeout=max(30, float(config_value(config, ("monitor", "command_timeout_seconds"), ("general", "command_timeout_seconds"), default=12)) * 2))
    if security.ok:
        try:
            advisories = json.loads(security.stdout or "[]")
            count = len(advisories) if isinstance(advisories, list) else 0
            important = sum(str(item.get("severity", "")).lower() in {"important", "critical"} for item in advisories if isinstance(item, Mapping)) if isinstance(advisories, list) else 0
            build_times = [float(item["buildtime"]) for item in advisories if isinstance(item, Mapping) and isinstance(item.get("buildtime"), (int, float))] if isinstance(advisories, list) else []
            oldest_age_days = max(0.0, (time.time() - min(build_times)) / 86400) if build_times else None
            overdue = oldest_age_days is not None and oldest_age_days >= 3
            result.metrics.append(record(cadence, "update", "security_updates_available", count, "advisories", severity="warning" if overdue else "info", source="dnf5_cache", details={"important_or_critical": important, "oldest_age_days": round(oldest_age_days, 2) if oldest_age_days is not None else None, "overdue_three_days": overdue}))
        except json.JSONDecodeError:
            result.errors.append("dnf security advisories: invalid JSON")

    for installation in ("system", "user"):
        args = ["flatpak", "remote-ls", f"--{installation}", "--cached", "--updates", "--json"]
        timeout = max(20, float(config_value(config, ("monitor", "command_timeout_seconds"), ("general", "command_timeout_seconds"), default=12)) * 2)
        flatpak = _operator_external(config, args, timeout=timeout) if installation == "user" else external(config, args, timeout=timeout)
        if flatpak.ok:
            try:
                payload = json.loads(flatpak.stdout or "[]")
                count = len(payload) if isinstance(payload, list) else 0
                result.metrics.append(record(cadence, "update", f"flatpak_{installation}_updates_available", count, "refs", source="flatpak_cache"))
                result.metrics.append(record(cadence, "update", f"flatpak_{installation}_update_cache_available", 1, "boolean", source="flatpak_cache"))
            except json.JSONDecodeError:
                result.errors.append(f"flatpak {installation} updates: invalid JSON")
        elif installation == "system" and not flatpak.missing:
            if re.search(r"no cached summary for remote", flatpak.stderr, re.I):
                result.metrics.append(record(cadence, "update", "flatpak_system_update_cache_available", 0, "boolean", source="flatpak_cache", outcome="skipped", error_message="cached remote summary unavailable"))
            else:
                result.errors.append(f"flatpak updates: {command_problem(flatpak)}")
    return result


def _flatpak_history(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    captured = 0
    for installation in ("system", "user"):
        args = ["flatpak", "history", f"--{installation}", "--columns=all", "--json"]
        timeout = max(20, float(config_value(config, ("monitor", "command_timeout_seconds"), ("general", "command_timeout_seconds"), default=12)) * 2)
        history = _operator_external(config, args, timeout=timeout) if installation == "user" else external(config, args, timeout=timeout)
        if history.missing:
            break
        if not history.ok:
            if installation == "system":
                result.errors.append(f"flatpak history: {command_problem(history)}")
            continue
        try:
            entries = json.loads(history.stdout or "[]")
        except json.JSONDecodeError:
            result.errors.append(f"flatpak {installation} history: invalid JSON")
            continue
        if not isinstance(entries, list):
            continue
        fingerprints = [
            fingerprint({key: entry.get(key) for key in ("time", "change", "application", "arch", "branch", "installation", "remote", "commit", "old_commit")})
            for entry in entries
            if isinstance(entry, Mapping)
        ]
        key = f"software.flatpak_seen.{installation}"
        seen = state_get(db, key, [])
        seen_set = set(seen) if isinstance(seen, list) else set()
        indexed = [(entry, event_id) for entry, event_id in zip(entries, fingerprints) if event_id not in seen_set][-100:]
        for entry, event_id in indexed:
            if not isinstance(entry, Mapping):
                continue
            application = str(entry.get("application") or "")
            change = str(entry.get("change") or "change").lower().replace(" ", "_")
            result.events.append(
                record(
                    cadence,
                    "software",
                    f"flatpak_{change}",
                    1,
                    "ref",
                    source="flatpak_history",
                    device_id=f"flatpak:{installation}:{application}" if application else f"flatpak:{installation}:remote",
                    details={
                        "application": application or None,
                        "operation": entry.get("change"),
                        "architecture": entry.get("arch"),
                        "branch": entry.get("branch"),
                        "installation": installation,
                        "repository": entry.get("remote"),
                        "new_commit": entry.get("commit"),
                        "previous_commit": entry.get("old_commit"),
                        "history_time": entry.get("time"),
                        "transaction_id": event_id,
                    },
                    outcome="ok",
                )
            )
            captured += 1
        state_set(db, key, fingerprints[-2000:])
    result.metrics.append(record(cadence, "software", "flatpak_history_events_captured", captured, "events", source="flatpak_history"))
    return result


def collect_software_history(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    result = CollectionResult(scope)
    result.merge(collect_history(scope, config, db))
    result.merge(_flatpak_history(scope, config, db))
    return result


def _metadata_config(config: Mapping[str, Any]) -> tuple[list[str], list[str], int, int]:
    manual = list(config_value(config, ("inventory", "manual_paths"), default=["/opt", "/usr/local", "/home/daniele/.local/opt", "/home/daniele/.local/bin"]))
    launchers = list(config_value(config, ("inventory", "launcher_paths"), default=["/usr/share/applications", "/usr/local/share/applications", "/home/daniele/.local/share/applications"]))
    appimages = list(config_value(config, ("inventory", "appimage_paths"), default=["/home/daniele/Applications", "/home/daniele/.local/opt", "/home/daniele/Downloads"]))
    user_home = Path(str(config_value(config, ("inventory", "user_home"), default="/home/daniele")))
    icons = list(config_value(config, ("inventory", "icon_paths"), default=["/usr/share/icons/hicolor", "/usr/local/share/icons", str(user_home / ".local" / "share" / "icons")]))
    roots = list(dict.fromkeys(str(path) for path in manual + launchers + appimages))
    depth = int(config_value(config, ("inventory", "max_scan_depth"), default=4))
    max_hash = int(config_value(config, ("inventory", "metadata_hash_max_bytes"), default=16 * 1024 * 1024))
    return roots, [str(path) for path in icons], depth, max_hash


def collect_manual_changes(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    roots, icon_roots, depth, max_hash = _metadata_config(config)
    previous = state_get(db, "software.metadata", {})
    previous = previous if isinstance(previous, Mapping) else {}
    current, scan_truncated = bounded_metadata_snapshot(
        roots,
        previous=previous,
        max_depth=depth,
        max_hash_bytes=max_hash,
        suffixes={".appimage", ".desktop", ".py", ".sh", ".jar"},
        include_executables=True,
    )
    icon_snapshot, icon_truncated = bounded_metadata_snapshot(
        icon_roots,
        previous=previous,
        max_depth=depth,
        max_hash_bytes=max_hash,
        suffixes={".png", ".svg", ".ico", ".xpm"},
        include_executables=False,
    )
    current.update(icon_snapshot)
    scan_truncated = scan_truncated or icon_truncated
    changes, changes_truncated = metadata_changes(previous, current)
    state_set(db, "software.metadata", current)
    result.metrics.extend(
        [
            record(cadence, "software", "tracked_manual_software_files", len(current), "files", source="metadata_snapshot", details={"scan_truncated": scan_truncated}),
            record(cadence, "software", "manual_software_changes", len(changes), "changes", source="metadata_snapshot", details={"changes_truncated": changes_truncated}),
        ]
    )
    # The first snapshot is a baseline, not thousands of synthetic installs.
    if previous:
        for operation, path, metadata in changes:
            suffix = Path(path).suffix.lower()
            kind = "launcher" if suffix == ".desktop" else "appimage" if suffix == ".appimage" else "application_icon" if suffix in {".png", ".svg", ".ico", ".xpm"} else "manual_software"
            result.events.append(
                record(
                    cadence,
                    "software",
                    f"{kind}_{operation}",
                    1,
                    "file",
                    source="metadata_snapshot",
                    device_id=f"path:{fingerprint(path)[:20]}",
                    details={"path": path, "operation": operation, **(dict(metadata) if isinstance(metadata, Mapping) else {})},
                    outcome="detected",
                )
            )
    if scan_truncated or changes_truncated:
        result.events.append(record(cadence, "collector", "software_snapshot_truncated", 1, "event", severity="warning", source="metadata_snapshot", details={"scan_truncated": scan_truncated, "changes_truncated": changes_truncated}, outcome="partial"))
    return result


def _optional_json_inventory(
    config: Mapping[str, Any],
    args: list[str],
    *,
    source: str,
    parser: Any,
    timeout: float | None = None,
    as_operator: bool = False,
) -> list[dict[str, Any]]:
    output = _operator_external(config, args, timeout=timeout, max_output=2_000_000) if as_operator else external(config, args, timeout=timeout, max_output=2_000_000)
    if not output.ok:
        return []
    try:
        payload = json.loads(output.stdout or "{}")
    except json.JSONDecodeError:
        return []
    return parser(payload, source)


def _pip_items(payload: Any, source: str) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        return []
    return [
        {"category": "software", "name": str(item.get("name")), "item_key": f"{source}:{item.get('name')}", "version": str(item.get("version") or ""), "source": source}
        for item in payload
        if isinstance(item, Mapping) and item.get("name")
    ]


def _pipx_items(payload: Any, source: str) -> list[dict[str, Any]]:
    environments = payload.get("venvs", {}) if isinstance(payload, Mapping) else {}
    if not isinstance(environments, Mapping):
        return []
    items: list[dict[str, Any]] = []
    for name, value in environments.items():
        metadata = value.get("metadata", {}) if isinstance(value, Mapping) else {}
        package = metadata.get("main_package", {}) if isinstance(metadata, Mapping) else {}
        version = package.get("package_version", "") if isinstance(package, Mapping) else ""
        items.append({"category": "software", "name": str(name), "item_key": f"pipx:{name}", "version": str(version), "source": source})
    return items


def _plain_tool_items(output: str, source: str, pattern: re.Pattern[str]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            name, version = match.group(1), match.group(2)
            items.append({"category": "software", "name": name, "item_key": f"{source}:{name}", "version": version, "source": source})
    return items


def _android_sdk_items(sdk_root: Path, owner: str) -> list[dict[str, Any]]:
    versions: dict[str, str] = {}
    packages_xml = sdk_root / "packages.xml"
    try:
        root = ElementTree.parse(packages_xml).getroot()
        for package in root.iter():
            if package.tag.rsplit("}", 1)[-1] != "localPackage":
                continue
            component = str(package.attrib.get("path") or "")
            if not component:
                continue
            revision = next((child for child in package if child.tag.rsplit("}", 1)[-1] == "revision"), None)
            parts: list[str] = []
            if revision is not None:
                for child in revision:
                    if child.tag.rsplit("}", 1)[-1] in {"major", "minor", "micro", "preview"} and child.text:
                        parts.append(child.text.strip())
            versions[component] = ".".join(parts)
    except (OSError, ElementTree.ParseError):
        pass
    candidates = [sdk_root / "platforms", sdk_root / "build-tools", sdk_root / "cmdline-tools"]
    for parent in candidates:
        if not parent.is_dir():
            continue
        for path in parent.iterdir():
            if path.is_dir():
                versions.setdefault(str(path.relative_to(sdk_root)).replace(os.sep, ";"), "")
    for component in ("platform-tools", "emulator"):
        if (sdk_root / component).is_dir():
            versions.setdefault(component, "")
    for component in list(versions):
        properties = sdk_root / Path(component.replace(";", os.sep)) / "source.properties"
        try:
            for line in properties.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("Pkg.Revision="):
                    versions[component] = line.split("=", 1)[1].strip()
                    break
        except OSError:
            pass
    return [
        {"category": "software", "name": component, "item_key": f"android-sdk:{component}", "version": version, "source": "android-sdk-metadata", "owner_user": owner}
        for component, version in sorted(versions.items())
    ]


def _npm_metadata_items(operator_home: Path, operator: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    roots = (
        (operator_home / ".local" / "lib" / "node_modules", operator),
        (Path("/usr/local/lib/node_modules"), "root"),
        (Path("/usr/lib/node_modules"), "root"),
        (Path("/usr/lib64/node_modules"), "root"),
    )
    for root, owner in roots:
        if not root.is_dir():
            continue
        candidates: list[Path] = []
        for path in root.iterdir():
            if path.name.startswith("@") and path.is_dir():
                candidates.extend(child for child in path.iterdir() if child.is_dir())
            elif path.is_dir():
                candidates.append(path)
        for package in candidates:
            try:
                metadata = json.loads((package / "package.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(metadata, Mapping):
                continue
            name = str(metadata.get("name") or package.name)
            items.append({"category": "software", "name": name, "item_key": f"npm-global:{owner}:{name}", "version": str(metadata.get("version") or ""), "source": "npm-metadata", "owner_user": owner, "path": str(package)})
    return items


def _cargo_metadata_items(operator_home: Path, operator: str) -> list[dict[str, Any]]:
    crates_file = operator_home / ".cargo" / ".crates.toml"
    try:
        payload = tomllib.loads(crates_file.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    crates = payload.get("v1", {}) if isinstance(payload, Mapping) else {}
    items: list[dict[str, Any]] = []
    if isinstance(crates, Mapping):
        for specification in crates:
            match = re.match(r"^([^\s]+)\s+([^\s]+)", str(specification))
            if match:
                items.append({"category": "software", "name": match.group(1), "item_key": f"cargo-install:{match.group(1)}", "version": match.group(2), "source": "cargo-metadata", "owner_user": operator})
    return items


def collect_full_software_inventory(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    items, rpm_error = _rpm_inventory(config)
    flatpak_items, flatpak_errors = _flatpak_inventory(config)
    items.extend(flatpak_items)
    if rpm_error:
        result.errors.append(f"rpm inventory: {rpm_error}")
    result.errors.extend(flatpak_errors)

    operator, operator_home, _ = _operator_identity(config)
    items.extend(_optional_json_inventory(config, ["python3", "-m", "pip", "list", "--format=json"], source="pip-system", parser=_pip_items))
    items.extend(_optional_json_inventory(config, ["python3", "-m", "pip", "list", "--user", "--format=json"], source="pip-user", parser=_pip_items, as_operator=True))
    items.extend(_optional_json_inventory(config, ["pipx", "list", "--json"], source="pipx", parser=_pipx_items, as_operator=True))
    items.extend(_npm_metadata_items(operator_home, operator))

    uv_output = _operator_external(config, ["uv", "tool", "list"], timeout=20)
    if uv_output.ok:
        items.extend(_plain_tool_items(uv_output.stdout, "uv-tool", re.compile(r"^([A-Za-z0-9_.-]+)\s+v?([^\s]+)")))
    items.extend(_cargo_metadata_items(operator_home, operator))

    sdk_root = Path(str(config_value(config, ("inventory", "android_sdk"), default="/home/daniele/Android/Sdk")))
    if sdk_root.is_dir():
        items.extend(_android_sdk_items(sdk_root, operator))

    extension_items: list[dict[str, Any]] = []
    for extension_root, owner in (
        (operator_home / ".local" / "share" / "gnome-shell" / "extensions", operator),
        (Path("/usr/share/gnome-shell/extensions"), "root"),
    ):
        if not extension_root.is_dir():
            continue
        for extension_path in extension_root.iterdir():
            if not extension_path.is_dir():
                continue
            version = ""
            metadata_path = extension_path / "metadata.json"
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                version = str(metadata.get("version") or "") if isinstance(metadata, Mapping) else ""
            except (OSError, json.JSONDecodeError):
                pass
            extension_items.append({"category": "software", "name": extension_path.name, "item_key": f"gnome-extension:{owner}:{extension_path.name}", "version": version, "source": "gnome-extension-path", "owner_user": owner, "path": str(extension_path)})
    if not extension_items:
        extensions = _operator_external(config, ["gnome-extensions", "list"], timeout=15)
        if extensions.ok:
            for extension in extensions.stdout.splitlines():
                extension = extension.strip()
                if extension:
                    extension_items.append({"category": "software", "name": extension, "item_key": f"gnome-extension:{operator}:{extension}", "version": "", "source": "gnome-extensions", "owner_user": operator})
    items.extend(extension_items)

    roots, icon_roots, depth, max_hash = _metadata_config(config)
    previous = state_get(db, "software.metadata", {})
    previous = previous if isinstance(previous, Mapping) else {}
    metadata, truncated = bounded_metadata_snapshot(
        roots,
        previous=previous,
        max_depth=depth,
        max_hash_bytes=max_hash,
        suffixes={".appimage", ".desktop", ".py", ".sh", ".jar"},
        include_executables=True,
    )
    icon_metadata, icon_truncated = bounded_metadata_snapshot(
        icon_roots,
        previous=previous,
        max_depth=depth,
        max_hash_bytes=max_hash,
        suffixes={".png", ".svg", ".ico", ".xpm"},
        include_executables=False,
    )
    metadata.update(icon_metadata)
    truncated = truncated or icon_truncated
    state_set(db, "software.metadata", metadata)
    for path, values in metadata.items():
        suffix = Path(path).suffix.lower()
        source = "appimage" if suffix == ".appimage" else "desktop-launcher" if suffix == ".desktop" else "application-icon" if suffix in {".png", ".svg", ".ico", ".xpm"} else "manual"
        items.append(
            {
                "category": "software",
                "name": Path(path).name,
                "item_key": f"{source}:{path}",
                "version": "",
                "owner_user": operator if path.startswith(f"/home/{operator}/") else "root",
                "path": path,
                "size_bytes": values.get("size_bytes"),
                "mtime_ns": values.get("mtime_ns"),
                "inode": values.get("inode"),
                "content_hash": values.get("content_hash"),
                "source": source,
            }
        )

    user_sources = {"pip-user", "pipx", "uv-tool", "npm-metadata", "cargo-metadata", "android-sdk-metadata", "gnome-extensions", "gnome-extension-path"}
    for item in items:
        source = str(item.get("source") or "")
        if source in user_sources and not item.get("owner_user"):
            item["owner_user"] = operator
        elif source in {"rpm", "pip-system"} and not item.get("owner_user"):
            item["owner_user"] = "root"

    # Preserve one item per stable key if two tools report the same environment.
    unique = {str(item["item_key"]): item for item in items if item.get("item_key")}
    result.software_inventory.extend(unique.values())
    counts: dict[str, int] = {}
    for item in unique.values():
        source = str(item.get("source") or "unknown")
        counts[source] = counts.get(source, 0) + 1
    result.metrics.append(record(cadence, "software", "software_inventory_item_count", len(unique), "items", source="inventory", details={"counts_by_source": counts, "metadata_scan_truncated": truncated}))
    state_set(db, "software.full_fingerprint", fingerprint([(key, value.get("version"), value.get("mtime_ns"), value.get("content_hash")) for key, value in sorted(unique.items())]))
    return result


__all__ = [
    "collect_full_software_inventory",
    "collect_manual_changes",
    "collect_package_snapshot",
    "collect_software_history",
    "collect_updates",
]
