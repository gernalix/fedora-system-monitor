"""Transparent process boundary for supported RDC and Codex shell adapters.

The command is used only in memory.  It is never written to the archive, logs,
or hook output.  Recognizable sensitive commands are metadata-only.  stdin is
forwarded by inheritance and deliberately not copied because neither source
marks secret input reliably.
"""
from __future__ import annotations

import argparse
import os
import re
import selectors
import shlex
import signal
import sqlite3
import subprocess
import time
import uuid
from pathlib import Path

from . import Archive, atomic_json, private_file
from .capture import OUTPUT_DENY, exclusion, preferences

STORAGE_ERRORS = (OSError, ValueError, RuntimeError, sqlite3.Error)
TAIL = 512
PENDING_HIGH = 8192
PENDING_LOW = 4096


def _command_name(command: str) -> str:
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return "shell"
    if not words:
        return "shell"
    while words:
        word = words.pop(0)
        if word in {"exec", "command", "env", "nohup"}:
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", word):
            continue
        return Path(word).name[:80] or "shell"
    return "shell"


def _effective_command(source: str, command: str) -> str:
    """Classify the inner Codex command, not our own trusted adapter pathname."""
    if source != "rdc":
        return command
    try:
        words = shlex.split(command, posix=True)
        adapter = next(i for i, word in enumerate(words)
                       if Path(word).name == "fsm-ea-codex-bash")
        option = next(i for i in range(adapter + 1, len(words)) if words[i] in {"-c", "-lc"})
        return words[option + 1]
    except (StopIteration, IndexError, ValueError):
        return command


def _nested_origin(a: Archive, source: str) -> bool:
    event = os.environ.get("FSM_EA_PROCESS_EVENT")
    if not event:
        return False
    try:
        event = str(uuid.UUID(event))
        path = a.events / event
        if not path.is_dir():
            return False
        with private_file(path / f"origin-{source}"):
            pass
        return True
    except (OSError, ValueError):
        return False


def _origins(a: Archive, m: dict, initial: str) -> list[str]:
    found = {initial}
    path = a.events / m["id"]
    for source in ("rdc", "codex"):
        if (path / f"origin-{source}").is_file():
            found.add(source)
    return sorted(found)


def _exec_plain(args: list[str]) -> None:
    os.execv("/bin/bash", ["bash", *args])


def run(source: str, args: list[str], root: Path | None = None) -> int:
    command = args[-1] if len(args) >= 2 and args[-2] in {"-c", "-lc"} else ""
    effective_command = _effective_command(source, command)
    try:
        archive = Archive(root)
        if not archive.enabled():
            _exec_plain(args)
        if _nested_origin(archive, source):
            _exec_plain(args)
        reason = exclusion(effective_command, os.getcwd(), preferences(archive)) if command else "unknown-command-shape"
        consent = None if reason else {
            "explicit": True, "scope": "P35-supported-process-adapter",
            "action": "installed RDC/Codex execution capture", "at": time.time(), "input": False,
        }
        m = archive.begin(kind="command", source=source, label="process", pid=os.getpid(),
                          capture=reason is None, consent=consent)
        m.update(parent_pid=os.getppid(),
                 command_name="excluded" if reason else _command_name(effective_command),
                 origins=[source], input="forwarded-not-recorded",
                 streams="stdout-stderr-separated-and-combined" if consent else "excluded",
                 coverage="process-streams" if consent else "metadata-only",
                 content_gaps=True, content_gap=reason or "stdin-not-recorded",
                 residual_risk=consent is not None, schema_version=3)
        atomic_json(archive.events / m["id"] / "manifest.json", m)
    except STORAGE_ERRORS:
        _exec_plain(args)

    env = os.environ | {"FSM_EA_PROCESS_EVENT": m["id"],
                        "FSM_EA_CORRELATION": m["correlation"]}
    capture = consent is not None
    try:
        child = subprocess.Popen(["/bin/bash", *args], stdin=None,
                                 stdout=subprocess.PIPE if capture else None,
                                 stderr=subprocess.PIPE if capture else None,
                                 env=env, close_fds=True)
    except OSError:
        try:
            archive.finish(m, 127)
        except STORAGE_ERRORS:
            pass
        return 127
    m["child_pid"] = child.pid
    initial_storage_failed = False
    try:
        atomic_json(archive.events / m["id"] / "manifest.json", m)
    except STORAGE_ERRORS:
        initial_storage_failed = True

    previous_handlers = {}
    def forward(signum, _frame):
        try:
            child.send_signal(signum)
        except ProcessLookupError:
            pass
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous_handlers[signum] = signal.signal(signum, forward)

    storage_failed = initial_storage_failed
    sensitive = False
    pending: list[tuple[str, bytes, float]] = []
    pending_bytes = 0
    tails = {"stdout": b"", "stderr": b""}
    previous = {"output": time.monotonic(), "stdout": time.monotonic(), "stderr": time.monotonic()}

    def store(stream: str, data: bytes, stamp: float) -> None:
        nonlocal storage_failed
        if storage_failed or sensitive:
            return
        try:
            archive.append(m, data, max(0, stamp - previous["output"]), stream="output")
            previous["output"] = stamp
            archive.append(m, data, max(0, stamp - previous[stream]), stream=stream)
            previous[stream] = stamp
        except STORAGE_ERRORS:
            storage_failed = True

    def flush(target: int = 0) -> None:
        nonlocal pending_bytes
        while pending and pending_bytes > target:
            stream, data, stamp = pending.pop(0)
            pending_bytes -= len(data)
            store(stream, data, stamp)

    if capture:
        sel = selectors.DefaultSelector()
        assert child.stdout is not None and child.stderr is not None
        sel.register(child.stdout, selectors.EVENT_READ, ("stdout", 1))
        sel.register(child.stderr, selectors.EVENT_READ, ("stderr", 2))
        while sel.get_map():
            for key, _mask in sel.select(.1):
                stream, target_fd = key.data
                data = os.read(key.fd, 4096)
                if not data:
                    sel.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                # Preserve the operation before attempting any recorder work.
                view = memoryview(data)
                while view:
                    view = view[os.write(target_fd, view):]
                if sensitive or storage_failed:
                    continue
                sample = tails[stream] + data
                tails[stream] = sample[-TAIL:]
                if OUTPUT_DENY.search(sample):
                    sensitive = True
                    pending.clear()
                    pending_bytes = 0
                    try:
                        archive.drop_content(m, "recognizable-sensitive-output")
                    except STORAGE_ERRORS:
                        storage_failed = True
                    continue
                pending.append((stream, data, time.monotonic()))
                pending_bytes += len(data)
                if pending_bytes > PENDING_HIGH:
                    flush(PENDING_LOW)
        flush()
    code = child.wait()
    code = code if code >= 0 else 128 - code
    for signum, handler in previous_handlers.items():
        signal.signal(signum, handler)
    try:
        m["origins"] = _origins(archive, m, source)
        if "codex" in m["origins"]:
            m["source"] = "codex"
        if storage_failed:
            m["content_gaps"] = True
            m["content_gap"] = "storage-failure"
        archive.finish(m, code)
    except STORAGE_ERRORS:
        pass
    return code


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--source", choices=("rdc", "codex"), required=True)
    p.add_argument("--root", type=Path)
    p.add_argument("args", nargs=argparse.REMAINDER)
    ns = p.parse_args(argv)
    args = ns.args[1:] if ns.args[:1] == ["--"] else ns.args
    if not args:
        return 2
    return run(ns.source, args, ns.root)


if __name__ == "__main__":
    raise SystemExit(main())
