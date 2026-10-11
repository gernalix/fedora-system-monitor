"""Execution archive CLI and terminal PTY boundary. Never record the shell PTY."""
from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import pty
import select
import signal
import sqlite3
import subprocess
import sys
import termios
import time
import tty
from pathlib import Path

from . import Archive, SAFE, atomic_json, private_file, root_path


def _copy_size(fd: int) -> None:
    if sys.stdin.isatty():
        size = fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, size)


def relay(argv: list[str], archive: Archive | None, m: dict | None,
          *, shell: bool = False, login: bool = False) -> int:
    """Forward input without storing it; only approved child output reaches disk.

    Bash sessions have an entirely unrecorded PTY. Command metadata arrives on
    a separate bounded pipe containing ONLY event, PID, exit code and fixed label.
    """
    rfd, wfd = os.pipe2(os.O_NONBLOCK)
    os.set_inheritable(wfd, True)
    attrs = termios.tcgetattr(0) if sys.stdin.isatty() else None
    pid, master = pty.fork()
    if pid == 0:
        os.close(rfd)
        if attrs is not None:
            termios.tcsetattr(0, termios.TCSANOW, attrs)
        if shell:
            os.environ["FSM_EA_ACTIVE"] = "1"
            os.environ["FSM_EA_FD"] = str(wfd)
            if m:
                os.environ["FSM_EA_SESSION"] = m["id"]
            else:
                os.environ.pop("FSM_EA_SESSION", None)
            os.execv("/bin/bash", ["bash"] + (["-l"] if login else []) + ["-i"])
        os.close(wfd)
        # Disable kernel echo: even input at an unexpected prompt stays off disk.
        child_attrs = termios.tcgetattr(0)
        child_attrs[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(0, termios.TCSANOW, child_attrs)
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "TERM": "xterm-256color"}
        os.execve(argv[0], argv, env)
    os.close(wfd)
    if m and archive:
        m["pid"] = pid
        atomic_json(archive.events / m["id"] / "manifest.json", m)
    _copy_size(master)
    previous_winch = signal.signal(signal.SIGWINCH, lambda *_: _copy_size(master))
    old_signals = {}
    for sig in (signal.SIGTERM, signal.SIGHUP):
        old_signals[sig] = signal.signal(sig, lambda s, _f: os.killpg(pid, s))
    if attrs is not None:
        tty.setraw(0)
    active_command = None
    metadata_buffer = b""
    previous = time.monotonic()
    watched = {master, rfd, 0}
    storage_failed = False

    def finish_command(code):
        nonlocal active_command
        if active_command and archive:
            archive.finish(active_command, code)
        active_command = None

    try:
        while master in watched:
            ready, _, _ = select.select(list(watched), [], [], 0.5)
            for fd in ready:
                try:
                    data = os.read(fd, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO and fd == master:
                        data = b""
                    elif exc.errno == errno.EAGAIN:
                        continue
                    else:
                        raise
                if not data:
                    watched.discard(fd)
                    continue
                if fd == 0:
                    os.write(master, data)  # no input logger, buffer or index
                elif fd == master:
                    view = memoryview(data)
                    while view:
                        view = view[os.write(1, view):]
                    now = time.monotonic()
                    if not shell and archive and m and not storage_failed:
                        try:
                            archive.append(m, data, now - previous)
                        except (OSError, ValueError, RuntimeError, sqlite3.Error):
                            storage_failed = True
                            m["coverage"] = "truncated"
                    previous = now
                else:
                    metadata_buffer += data
                    if len(metadata_buffer) > 65536:
                        metadata_buffer = b""  # fail closed on malformed protocol
                    while b"\n" in metadata_buffer:
                        line, metadata_buffer = metadata_buffer.split(b"\n", 1)
                        fields = line.split(b"\t")
                        if (not shell or not archive or not m or storage_failed or
                                len(fields) != 3 or fields[0] not in (b"B", b"E")):
                            continue
                        try:
                            shell_pid, code = map(int, fields[1:])
                            if shell_pid != pid or not 0 <= code <= 255:
                                continue
                            finish_command(code)
                            if fields[0] == b"B":
                                active_command = archive.begin(kind="command", source="bash",
                                                               label="excluded", pid=pid, parent=m["id"])
                        except (OSError, ValueError, RuntimeError, sqlite3.Error):
                            storage_failed = True
    finally:
        if attrs is not None:
            termios.tcsetattr(0, termios.TCSADRAIN, attrs)
        signal.signal(signal.SIGWINCH, previous_winch)
        for sig, handler in old_signals.items():
            signal.signal(sig, handler)
        os.close(master)
        os.close(rfd)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    code = code if code >= 0 else 128 - code
    if archive and m:
        try:
            finish_command(code)
            archive.finish(m, code)
        except (OSError, ValueError, RuntimeError, sqlite3.Error):
            pass  # durable manifest/spool recovered on the next successful run
    return code


def demo_argv() -> list[str]:
    # Fixed program, no external script/input/env reads. Tests replay screen updates
    # and merged stderr without authorizing arbitrary script content for recording.
    program = ("import os,time; "
               "os.write(1,b'FSM public diagnostic\\n'); "
               "os.write(2,b'FSM stderr fixture\\n'); "
               "os.write(1,b'\\x1b[2J\\x1b[Hframe 1\\n'); time.sleep(.05); "
               "os.write(1,b'\\x1b[Hframe 2\\n')")
    return [sys.executable, "-I", "-c", program]


def run_command(args, archive: Archive) -> int:
    argv = list(args.argv)
    if argv and argv[0] == "--":
        argv.pop(0)
    if not argv:
        raise ValueError("missing command")
    safe = SAFE.get(tuple(argv))
    if argv == ["demo"]:
        safe = demo_argv()
    label = argv[0] if safe else "excluded"
    if label not in {"date", "uname", "uptime", "true", "false", "demo"}:
        label = "excluded"
    if not archive.enabled():
        # Disable restores normal execution; demo still uses its fixed program.
        return subprocess.call(list(safe or argv))
    parent = os.environ.get("FSM_EA_SESSION")
    try:
        m = archive.begin(kind="command", source="diagnostic" if safe else "manual",
                          label=label, pid=os.getpid(), parent=parent, capture=bool(safe))
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        return subprocess.call(list(safe or argv))
    if safe:
        return relay(list(safe), archive, m)
    # No wrapper PTY for unknown commands and no stdout/stderr interception.
    # This keeps password prompts, full-screen apps and ordinary I/O unchanged.
    try:
        child = subprocess.Popen(argv)
        m["pid"] = child.pid
        try:
            atomic_json(archive.events / m["id"] / "manifest.json", m)
        except OSError:
            pass
        code = child.wait()
    except OSError:
        archive.finish(m, 127)
        raise ValueError("command unavailable") from None
    try:
        archive.finish(m, code if code >= 0 else 128 - code)
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        pass
    return code if code >= 0 else 128 - code


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ea", description="Private Fedora execution archive")
    p.add_argument("--root", type=Path, default=None, help="isolated test archive root")
    p.add_argument("--json", action="store_true", help="machine output without an interactive NV banner")
    sub = p.add_subparsers(dest="operation", required=True)
    sub.add_parser("status")
    search = sub.add_parser("search")
    search.add_argument("query", nargs="?", default="")
    search.add_argument("--source", choices=("bash", "manual", "diagnostic"))
    search.add_argument("--since-hours", type=float, default=0)
    search.add_argument("--limit", type=int, default=20)
    for name in ("show", "replay"):
        cmd = sub.add_parser(name)
        cmd.add_argument("id")
        if name == "replay":
            cmd.add_argument("--speed", type=float, default=1)
    recover = sub.add_parser("recover")
    recover.add_argument("--rebuild-index", action="store_true")
    sub.add_parser("maintain")
    sub.add_parser("disable")
    sub.add_parser("enable")
    configure = sub.add_parser("configure")
    for k in ("quota-bytes", "retention-days", "event-bytes"):
        configure.add_argument("--" + k, type=int)
    run = sub.add_parser("run")
    run.add_argument("argv", nargs=argparse.REMAINDER)
    shell = sub.add_parser("shell", help=argparse.SUPPRESS)
    shell.add_argument("--login", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if sys.stdout.isatty() and not args.json and args.operation not in {"run", "shell", "replay"}:
        candidates = (Path(__file__).parents[1] / "NV.txt", Path(__file__).parents[4] / "NV.txt")
        for candidate in candidates:
            if candidate.is_file():
                print("NV " + candidate.read_text().strip())
                break
    # Shell fail-open means ordinary terminal usage survives unavailable storage.
    if args.operation == "shell":
        archive, m = None, None
        try:
            candidate = Archive(args.root)
            if candidate.enabled():
                candidate.recover()
                archive = candidate
                m = archive.begin(kind="session", source="bash", label="shell", pid=os.getpid())
        except (OSError, ValueError, RuntimeError, sqlite3.Error):
            pass
        if m is None:
            os.environ["FSM_EA_ACTIVE"] = "1"
            os.execv("/bin/bash", ["bash"] + (["-l"] if args.login else []) + ["-i"])
        return relay([], archive, m, shell=True, login=args.login)
    try:
        try:
            a = Archive(args.root)
        except (OSError, ValueError, RuntimeError, sqlite3.Error):
            if args.operation == "run":
                argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
                safe = demo_argv() if argv == ["demo"] else SAFE.get(tuple(argv))
                return subprocess.call(list(safe or argv))
            raise
        op = args.operation
        if op == "run":
            return run_command(args, a)
        if op == "status":
            result = a.status()
        elif op == "search":
            since = time.time() - args.since_hours * 3600 if args.since_hours else 0
            result = a.query(args.query, source=args.source, since=since, limit=args.limit)
        elif op in {"show", "replay"}:
            import uuid
            event_id = str(uuid.UUID(args.id))
            result = json.loads((a.events / event_id / "manifest.json").read_text())
            if op == "replay":
                if "output" not in result["files"]:
                    raise ValueError("metadata-only event has no replay")
                if not 0 < args.speed <= 1000:
                    raise ValueError("invalid replay speed")
                raw, timing = a.read(result, "output"), a.read(result, "timing")
                offset = 0
                for line in timing.decode().splitlines():
                    delay, size = line.split()
                    n = int(size)
                    time.sleep(float(delay) / args.speed)
                    sys.stdout.buffer.write(raw[offset:offset + n])
                    sys.stdout.buffer.flush()
                    offset += n
                return 0
        elif op in {"recover", "maintain"}:
            result = {"recovered": a.recover(rebuild=getattr(args, "rebuild_index", False))}
        elif op in {"enable", "disable"}:
            with a.lock():
                if op == "enable":
                    (a.root / "disabled").unlink(missing_ok=True)
                else:
                    with private_file(a.root / "disabled"):
                        pass
            result = {"enabled": a.enabled()}
        else:
            limits = {k: getattr(args, k) for k in a.config if getattr(args, k, None) is not None}
            if not limits or any(v <= 0 for v in limits.values()):
                raise ValueError("positive limits required")
            if limits.get("event_bytes", 0) > 32 * 1024 * 1024:
                raise ValueError("event limit too large")
            with a.lock():
                atomic_json(a.root / "config.json", a.config | limits)
            result = a.config | limits
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        # No exception values/argv/environment in logs or user output.
        print(json.dumps({"ok": False, "error_type": type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
