"""Explicit, non-interactive adapters for authorized remote executions.

No target discovery beyond connected ADB devices, no credentials, environment,
stdin, conversations, browser data or runner secrets are persisted.  SSH and ADB
streams are captured only on explicit opt-in; GitHub ingestion targets one run.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shlex
import shutil
import signal
import sqlite3
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from . import Archive, atomic_json
from .capture import OUTPUT_DENY, exclusion, preferences

STORAGE_ERRORS = (OSError, ValueError, RuntimeError, sqlite3.Error)
NAME = re.compile(r"^[A-Za-z0-9_.:+-]{1,200}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RUNNER_SECRET = re.compile(rb"(?m)(?:^|[\s=:])\*{3,}(?:$|[\s])|::add-mask::")
TAIL = 512
PENDING_HIGH = 8192
PENDING_LOW = 4096
Run = Callable[..., subprocess.CompletedProcess]


def _run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=False, **kwargs)


def remote_inventory() -> dict:
    return {
        "schema": "fedora-system-monitor.remote-execution-inventory.v1",
        "sources": [
            {"source": "ssh", "present": shutil.which("ssh") is not None,
             "coverage": "local transport PID+parent+timestamp+exit; filtered remote command; optional authentic separated stdout/stderr+timing; remote PID NOT COVERED"},
            {"source": "github-actions", "present": shutil.which("gh") is not None,
             "coverage": "run metadata/digest/reference; optional bounded runner log; stdin/raw stream timing/replay NOT COVERED"},
            {"source": "adb", "present": shutil.which("adb") is not None,
             "coverage": "local transport PID+parent+timestamp+exit; hashed device identity; filtered command; optional authentic separated stdout/stderr+timing; Android process PID NOT COVERED"},
        ],
        "excluded": ["credentials", "environment", "hidden stdin", "runner masked secrets",
                     "ChatGPT conversations", "Codex prompts/transcripts", "browser content",
                     "private device files"],
        "scheduler": "none; explicit invocation only",
    }


def _command_name(argv: list[str]) -> str:
    return Path(argv[0]).name[:80] if argv else "unknown"


def _adb_serial(device_sha256: str | None, runner: Run = _run) -> tuple[str, str]:
    if device_sha256 is not None and not SHA256.fullmatch(device_sha256):
        raise ValueError("invalid device digest")
    result = runner(["adb", "devices"], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError("adb unavailable")
    devices = []
    for line in result.stdout.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "device":
            digest = hashlib.sha256(fields[0].encode()).hexdigest()
            if device_sha256 is None or digest == device_sha256:
                devices.append((fields[0], digest))
    if len(devices) != 1:
        raise ValueError("exactly one authorized connected device required")
    return devices[0]


def _transport_argv(transport: str, command: list[str], *, target: str | None,
                    device_sha256: str | None, runner: Run = _run) -> tuple[list[str], dict]:
    if not command or any(not item or "\0" in item for item in command):
        raise ValueError("remote command required")
    if transport == "ssh":
        if target is None or not NAME.fullmatch(target) or "@" in target or ":" in target:
            raise ValueError("configured SSH alias required")
        # OpenSSH sends a remote command string, not an argv vector.  Quote the
        # explicit argv locally so the remote shell reconstructs exact boundaries.
        return (["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "--", target,
                 shlex.join(command)],
                {"remote_host": target, "remote_identity": "configured-ssh-alias",
                 "remote_pid": "not-provided-by-ssh"})
    if transport == "adb":
        serial, digest = _adb_serial(device_sha256, runner)
        return (["adb", "-s", serial, "shell", shlex.join(command)],
                {"device_serial_sha256": digest, "remote_identity": "connected-adb-device",
                 "remote_pid": "not-provided-by-adb-shell"})
    raise ValueError("unsupported remote transport")


def _plain(argv: list[str]) -> int:
    try:
        code = subprocess.call(argv, stdin=subprocess.DEVNULL)
    except OSError:
        return 127
    return code if code >= 0 else 128 - code


def run_remote(root: Path | None, transport: str, command: list[str], *,
               target: str | None = None, device_sha256: str | None = None,
               include_output: bool = False, runner: Run = _run) -> int:
    """Execute through SSH/ADB while keeping the command functional on archive failure."""
    argv, remote = _transport_argv(transport, command, target=target,
                                   device_sha256=device_sha256, runner=runner)
    archive = manifest = None
    reason = "content-not-selected"
    try:
        archive = Archive(root)
        if not archive.enabled():
            return _plain(argv)
        if include_output:
            reason = exclusion(shlex.join(command), os.getcwd(), preferences(archive))
        consent = None if reason else {"explicit": True, "scope": f"exact-{transport}-command",
                                       "action": f"ea remote {transport} --include-output",
                                       "at": time.time(), "input": False}
        manifest = archive.begin(kind="execution", source=transport, label="remote-process",
                                 pid=os.getpid(), capture=consent is not None, consent=consent)
        manifest.update(parent_pid=os.getppid(), command_name="excluded" if reason and include_output else _command_name(command),
                        input="closed-not-recorded", streams="stdout-stderr-separated-and-combined" if consent else "excluded",
                        coverage="remote-streams" if consent else "metadata-only",
                        content_gaps=True, content_gap=reason or "remote-pid-and-stdin-not-recorded",
                        residual_risk=consent is not None, schema_version=5,
                        metadata=remote | {"command": "excluded" if reason and include_output else _command_name(command),
                                           "argv": "filtered-to-executable-basename",
                                           "remote_process": "metadata-only"})
        atomic_json(archive.events / manifest["id"] / "manifest.json", manifest)
    except STORAGE_ERRORS:
        archive = manifest = None

    capture = bool(manifest and manifest.get("coverage") == "remote-streams")
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE if capture else None,
                                 stderr=subprocess.PIPE if capture else None, close_fds=True)
    except OSError:
        if archive and manifest:
            try:
                archive.finish(manifest, 127)
            except STORAGE_ERRORS:
                pass
        return 127
    if manifest:
        manifest["pid"] = child.pid
        manifest["transport_pid"] = child.pid
        try:
            atomic_json(archive.events / manifest["id"] / "manifest.json", manifest)
        except STORAGE_ERRORS:
            pass

    previous_handlers = {}
    def forward(signum, _frame):
        try:
            child.send_signal(signum)
        except ProcessLookupError:
            pass
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous_handlers[signum] = signal.signal(signum, forward)

    storage_failed = False
    sensitive = False
    pending: list[tuple[str, bytes, float]] = []
    pending_bytes = 0
    tails = {"stdout": b"", "stderr": b""}
    previous = {"output": time.monotonic(), "stdout": time.monotonic(), "stderr": time.monotonic()}

    def store(stream: str, data: bytes, stamp: float) -> None:
        nonlocal storage_failed
        if storage_failed or sensitive or not archive or not manifest:
            return
        try:
            archive.append(manifest, data, max(0, stamp - previous["output"]), stream="output")
            previous["output"] = stamp
            archive.append(manifest, data, max(0, stamp - previous[stream]), stream=stream)
            previous[stream] = stamp
        except STORAGE_ERRORS:
            storage_failed = True

    def flush(target_bytes: int = 0) -> None:
        nonlocal pending_bytes
        while pending and pending_bytes > target_bytes:
            stream, data, stamp = pending.pop(0)
            pending_bytes -= len(data)
            store(stream, data, stamp)

    if capture:
        selector = selectors.DefaultSelector()
        assert child.stdout is not None and child.stderr is not None
        selector.register(child.stdout, selectors.EVENT_READ, ("stdout", 1))
        selector.register(child.stderr, selectors.EVENT_READ, ("stderr", 2))
        while selector.get_map():
            for key, _mask in selector.select(.1):
                stream, fd = key.data
                data = os.read(key.fd, 4096)
                if not data:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                if sensitive or storage_failed:
                    continue
                sample = tails[stream] + data
                tails[stream] = sample[-TAIL:]
                if OUTPUT_DENY.search(sample):
                    sensitive = True
                    pending.clear()
                    pending_bytes = 0
                    try:
                        archive.drop_content(manifest, "recognizable-sensitive-output")
                    except STORAGE_ERRORS:
                        storage_failed = True
                    continue
                pending.append((stream, data, time.monotonic()))
                pending_bytes += len(data)
                if pending_bytes > PENDING_HIGH:
                    flush(PENDING_LOW)
        flush()
    code = child.wait()
    normalized = code if code >= 0 else 128 - code
    for signum, handler in previous_handlers.items():
        signal.signal(signum, handler)
    if archive and manifest:
        try:
            if storage_failed:
                manifest["content_gaps"] = True
                manifest["content_gap"] = "storage-failure"
            archive.finish(manifest, normalized)
        except STORAGE_ERRORS:
            pass
    return normalized


def _github_metadata(repo: str, run_id: int, runner: Run) -> dict:
    result = runner(["gh", "api", f"repos/{repo}/actions/runs/{run_id}"],
                    capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("GitHub run metadata unavailable")
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or int(value.get("id", 0)) != run_id:
        raise ValueError("GitHub run identity mismatch")
    return value


def ingest_github_run(a: Archive, *, repo: str, run_id: int, include_logs: bool = False,
                      runner: Run = _run) -> dict:
    if not REPO.fullmatch(repo) or run_id <= 0:
        raise ValueError("exact GitHub repository and run ID required")
    if not a.enabled():
        return {"source": "github-actions", "skipped": "archive-disabled"}
    value = _github_metadata(repo, run_id, runner)
    attempt = int(value.get("run_attempt") or 1)
    updated = str(value.get("updated_at") or value.get("created_at") or "")
    identity = f"{repo}:{run_id}:{attempt}:{updated}"
    payload = None
    gap = "runner log not selected"
    coverage = "metadata-only"
    log_sha256 = ""
    if include_logs:
        logs = runner(["gh", "run", "view", str(run_id), "--repo", repo, "--log"],
                      capture_output=True, timeout=60)
        raw = logs.stdout if isinstance(logs.stdout, bytes) else str(logs.stdout or "").encode()
        if logs.returncode:
            gap = "runner log unavailable"
        elif len(raw) > a.config["event_bytes"]:
            gap = "runner log exceeds event limit"
        elif OUTPUT_DENY.search(raw) or RUNNER_SECRET.search(raw):
            gap = "runner log contains sensitive or masked material"
        else:
            payload = raw
            coverage = "runner-log"
            gap = "runner log only; stdout/stderr/raw timing not provided by API"
            log_sha256 = hashlib.sha256(raw).hexdigest()
    started_text = str(value.get("run_started_at") or value.get("created_at") or "")
    try:
        started = datetime.fromisoformat(started_text.replace("Z", "+00:00")).timestamp()
    except (ValueError, OverflowError):
        started = time.time()
    metadata = {
        "repo": repo, "run_id": str(run_id), "run_attempt": attempt,
        "workflow": str(value.get("name") or "")[:200],
        "event": str(value.get("event") or "")[:80],
        "status": str(value.get("status") or "")[:40],
        "conclusion": str(value.get("conclusion") or "")[:40],
        "head_sha": str(value.get("head_sha") or "")[:64],
        "created_at": str(value.get("created_at") or "")[:40],
        "updated_at": updated[:40],
        "reference": f"github-actions:{repo}:{run_id}:{attempt}",
        "log_sha256": log_sha256,
        "stdout_stderr": "not-separated-by-GitHub-run-log",
    }
    manifest, created = a.record_external(
        source="github-actions", label="workflow-run", identity=identity,
        correlation_key=f"{repo}:{run_id}:{attempt}", started=started, metadata=metadata,
        output=payload, coverage=coverage, content_gap=gap)
    return {"source": "github-actions", "repo": repo, "run_id": run_id,
            "inserted": int(created), "duplicates": int(not created),
            "coverage": manifest["coverage"], "log_sha256": metadata["log_sha256"],
            "reference": metadata["reference"]}


__all__ = ["ingest_github_run", "remote_inventory", "run_remote"]
