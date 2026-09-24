#!/usr/bin/python3
"""Oracle-side probes provisioned and owned by Fedora System Monitor."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def systemd_properties(unit: str) -> dict[str, str]:
    result = subprocess.run(
        ["systemctl", "show", unit, "--property=ActiveState,SubState,Result,ExecMainStatus,ExecMainExitTimestampMonotonic,NRestarts"],
        text=True, capture_output=True, timeout=10, check=True,
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def check_job(unit: str, freshness_seconds: int, now_monotonic: float, now_wall: float, state: dict) -> tuple[bool, str]:
    props = systemd_properties(unit)
    try:
        ended = int(props.get("ExecMainExitTimestampMonotonic", "0")) / 1_000_000
        exit_status = int(props.get("ExecMainStatus", "1"))
    except ValueError:
        return False, f"{unit}: invalid systemd result"
    saved = state.get(f"job:{unit}", {})
    last_success_wall = float(saved.get("last_success_wall", 0))
    if props.get("Result") == "success" and exit_status == 0 and 0 < ended <= now_monotonic:
        last_success_wall = max(last_success_wall, now_wall - (now_monotonic - ended))
        state[f"job:{unit}"] = {"last_success_wall": last_success_wall}
    age = now_wall - last_success_wall if last_success_wall > 0 else None
    good = props.get("Result") == "success" and exit_status == 0 and age is not None and 0 <= age <= freshness_seconds
    return good, f"{unit}: result={props.get('Result', 'unknown')} age={round(age) if age is not None else 'missing'}s limit={freshness_seconds}s"


def check_daemon(unit: str, now_wall: float, state: dict) -> tuple[bool, str]:
    props = systemd_properties(unit)
    restarts = int(props.get("NRestarts", "0") or 0)
    prior = state.get(unit, {})
    events = [float(t) for t in prior.get("restart_events", []) if 0 <= now_wall - float(t) <= 900]
    delta = max(0, restarts - int(prior.get("restart_count", restarts)))
    events.extend([now_wall] * min(delta, 4))
    state[unit] = {"restart_count": restarts, "restart_events": events}
    good = props.get("ActiveState") == "active" and props.get("SubState") == "running" and len(events) < 3
    return good, f"{unit}: {props.get('ActiveState', 'unknown')}/{props.get('SubState', 'unknown')} restarts_15m={len(events)}"


def check_http(url: str) -> tuple[bool, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "fedora-system-monitor/oracle-probe"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status = response.status
            response.read(256)
    except Exception as exc:
        return False, f"HTTP probe failed: {type(exc).__name__}"
    return status == 200, f"HTTP API status={status}"


def push(url: str, healthy: bool, message: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http" or parts.hostname != "127.0.0.1" or parts.port != 3002 or not parts.path.startswith("/api/push/"):
        raise ValueError("Oracle push endpoint must use the local Kuma listener")
    query = urllib.parse.urlencode({"status": "up" if healthy else "down", "msg": message[:200]})
    request = urllib.request.Request(urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")))
    with urllib.request.urlopen(request, timeout=8) as response:
        if response.status != 200 or json.load(response).get("ok") is not True:
            raise RuntimeError("Kuma rejected Oracle probe")


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".oracle-probe-")
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(state, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def run(config_path: Path, state_path: Path) -> dict[str, object]:
    config = json.loads(config_path.read_text())
    credential_path = Path(os.environ["CREDENTIALS_DIRECTORY"]) / "oracle_push.toml"
    lines = credential_path.read_text().splitlines()
    if not lines or lines[0] != "[push]":
        raise ValueError("invalid Oracle probe credential format")
    endpoints = {}
    for line in lines[1:]:
        key, value = line.split(" = ", 1)
        endpoints[key] = json.loads(value)
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    now_wall = time.time()
    now_monotonic = time.monotonic()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results = []
    for target in config["targets"]:
        key = target["key"]
        if target["kind"] == "http":
            healthy, reason = check_http(target["url"])
        elif target["kind"] == "daemon":
            healthy, reason = check_daemon(target["unit"], now_wall, state)
        elif target["kind"] == "jobs":
            checks = [check_job(item["unit"], item["freshness_seconds"], now_monotonic, now_wall, state) for item in target["jobs"]]
            healthy = all(ok for ok, _ in checks)
            reason = "; ".join(message for _, message in checks)
        else:
            raise ValueError("unsupported Oracle probe kind")
        try:
            push(endpoints[key], healthy, f"run_id={run_id}; {reason}")
            delivered = True
        except (OSError, ValueError, RuntimeError):
            delivered = False
        results.append({"key": key, "healthy": healthy, "delivered": delivered})
    save_state(state_path, state)
    return {"run_id": run_id, "results": results}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, default=Path("/var/lib/fedora-system-monitor-oracle-probe/state.json"))
    args = parser.parse_args()
    result = run(args.config, args.state)
    print(json.dumps(result, sort_keys=True))
    return 0 if all(item["healthy"] and item["delivered"] for item in result["results"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
