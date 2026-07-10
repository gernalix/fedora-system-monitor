"""Bounded process execution, locking, and structured logging."""

from __future__ import annotations

import fcntl
import json
import logging
import os
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Sequence


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    missing: bool = False

    @property
    def ok(self) -> bool:
        return not self.timed_out and not self.missing and self.returncode == 0


class LockUnavailable(RuntimeError):
    pass


def run_command(
    args: Sequence[str],
    *,
    timeout: float = 12,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
    max_output: int = 2_000_000,
) -> CommandResult:
    """Run a command without a shell and return a bounded, non-raising result."""
    command = tuple(str(value) for value in args)
    started = time.monotonic()
    process_env = os.environ.copy()
    if env:
        process_env.update({str(key): str(value) for key, value in env.items()})
    process: subprocess.Popen[bytes] | None = None
    stdout_parts: list[bytes] = []
    stderr_parts: list[bytes] = []

    def drain(stream: object, parts: list[bytes]) -> None:
        retained = 0
        while True:
            chunk = stream.read(65536)  # type: ignore[attr-defined]
            if not chunk:
                break
            if retained < max_output:
                kept = chunk[: max_output - retained]
                parts.append(kept)
                retained += len(kept)

    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=process_env,
            start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        stdout_thread = threading.Thread(target=drain, args=(process.stdout, stdout_parts), daemon=True)
        stderr_thread = threading.Thread(target=drain, args=(process.stderr, stderr_parts), daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        if input_text is not None and process.stdin is not None:
            try:
                process.stdin.write(input_text.encode("utf-8"))
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
            returncode = 124
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        process.stdout.close()
        process.stderr.close()
        stdout = b"".join(stdout_parts).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_parts).decode("utf-8", errors="replace")
        return CommandResult(
            args=command,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            duration_ms=int((time.monotonic() - started) * 1000),
            timed_out=timed_out,
        )
    except FileNotFoundError:
        return CommandResult(command, 127, "", "command unavailable", int((time.monotonic() - started) * 1000), missing=True)
    except OSError as exc:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        return CommandResult(command, 126, "", str(exc)[:1000], int((time.monotonic() - started) * 1000))


@contextmanager
def exclusive_lock(path: str | Path, timeout: float = 25) -> Iterator[None]:
    """Hold an advisory lock, waiting briefly so coalesced timers run in order."""
    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o640)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockUnavailable(f"collector lock busy: {lock_path}")
                time.sleep(0.1)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(message)s")


def log_record(logger: logging.Logger, event: str, **fields: object) -> None:
    """Emit one compact JSON object suitable for journald."""
    payload = {"event": event, **fields}
    logger.info(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str))


__all__ = [
    "CommandResult",
    "LockUnavailable",
    "configure_logging",
    "exclusive_lock",
    "log_record",
    "run_command",
]
