#!/usr/bin/env python3
"""Keep fragile USB-NVMe bridges out of smartd's unattended poll loop."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile

BEGIN = "# BEGIN fedora-system-monitor managed SMART exclusions"
END = "# END fedora-system-monitor managed SMART exclusions"
DEFAULT_GLOBS = ("usb-Samsung_PSSD_T7_Shield_*-0:0",)


def discover_paths(by_id_root: Path, patterns: tuple[str, ...]) -> list[str]:
    paths: set[str] = set()
    if not by_id_root.is_dir():
        return []
    for pattern in patterns:
        for candidate in by_id_root.glob(pattern):
            if "-part" in candidate.name:
                continue
            if candidate.is_symlink() and candidate.exists():
                paths.add(str(candidate))
    return sorted(paths)


def _managed_paths(text: str) -> set[str]:
    inside = False
    paths: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == BEGIN:
            inside = True
            continue
        if stripped == END:
            inside = False
            continue
        if inside and stripped.endswith(" -d ignore"):
            path = stripped[: -len(" -d ignore")].strip()
            if Path(path).is_absolute():
                paths.add(path)
    return paths


def reconcile_text(text: str, discovered: list[str]) -> str:
    retained = _managed_paths(text)
    retained.update(discovered)

    clean: list[str] = []
    inside = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == BEGIN:
            inside = True
            continue
        if stripped == END:
            inside = False
            continue
        if not inside:
            clean.append(line)

    if not retained:
        return "\n".join(clean).rstrip() + "\n"

    block = [BEGIN, *(f"{path} -d ignore" for path in sorted(retained)), END]
    insertion = next(
        (index for index, line in enumerate(clean) if line.strip().startswith("DEVICESCAN")),
        len(clean),
    )
    merged = clean[:insertion] + block + clean[insertion:]
    return "\n".join(merged).rstrip() + "\n"


def apply(config_path: Path, backup_dir: Path, by_id_root: Path, patterns: tuple[str, ...]) -> dict[str, object]:
    if not config_path.exists():
        return {"changed": False, "reason": "smartd_config_missing", "config": str(config_path)}

    current = config_path.read_text(encoding="utf-8")
    discovered = discover_paths(by_id_root, patterns)
    updated = reconcile_text(current, discovered)
    if updated == current:
        return {
            "changed": False,
            "config": str(config_path),
            "discovered": discovered,
            "managed": sorted(_managed_paths(current)),
        }

    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = backup_dir / f"smartd-{stamp}.conf"
    shutil.copy2(config_path, backup)

    stat = config_path.stat()
    fd, temp_name = tempfile.mkstemp(prefix=".smartd.conf.", dir=str(config_path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, stat.st_mode & 0o7777)
        try:
            os.chown(temp_name, stat.st_uid, stat.st_gid)
        except PermissionError:
            pass
        os.replace(temp_name, config_path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)

    return {
        "changed": True,
        "config": str(config_path),
        "backup": str(backup),
        "discovered": discovered,
        "managed": sorted(_managed_paths(updated)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/smartmontools/smartd.conf"))
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--by-id-root", type=Path, default=Path("/dev/disk/by-id"))
    parser.add_argument("--match", action="append", default=[])
    args = parser.parse_args()
    patterns = tuple(args.match) if args.match else DEFAULT_GLOBS
    result = apply(args.config, args.backup_dir, args.by_id_root, patterns)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
