"""PTY forwarding, guard handshake and session control. Never controls desktop focus."""
import errno
import fcntl
import os
import pty
import select
import signal
import sqlite3
import sys
import termios
import time
import tty

from . import atomic_json
from .capture import SessionCapture

STORAGE_ERRORS = (OSError, ValueError, RuntimeError, sqlite3.Error)


def _copy_size(fd):
    if sys.stdin.isatty():
        size = fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, size)


def _write(fd, data):
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
            view = view[n:]
        except BlockingIOError:
            select.select([], [fd], [], .1)


def relay(argv, archive, m, *, shell=False, login=False, profile="default"):
    rfd, wfd = os.pipe2(os.O_NONBLOCK)
    ack_read, ack_write = os.pipe2(os.O_NONBLOCK)
    for fd in (wfd, ack_read):
        os.set_inheritable(fd, True)
    attrs = termios.tcgetattr(0) if sys.stdin.isatty() else None
    pid, master = pty.fork()
    if pid == 0:
        os.close(rfd)
        os.close(ack_write)
        if attrs is not None:
            termios.tcsetattr(0, termios.TCSANOW, attrs)
        if shell:
            os.environ.update(FSM_EA_ACTIVE="1", FSM_EA_FD=str(wfd), FSM_EA_ACK=str(ack_read))
            if m:
                os.environ["FSM_EA_SESSION"] = m["id"]
            else:
                os.environ.pop("FSM_EA_SESSION", None)
            os.execv("/bin/bash", ["bash"] + (["-l"] if login else []) + ["-i"])
        os.close(wfd)
        os.close(ack_read)
        child_attrs = termios.tcgetattr(0)
        child_attrs[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(0, termios.TCSANOW, child_attrs)
        os.execve(argv[0], argv, {"PATH": "/usr/bin:/bin", "LANG": "C", "TERM": "xterm-256color"})
    os.close(wfd)
    os.close(ack_read)
    capture = None
    if m and archive:
        m["pid"] = pid
        try:
            atomic_json(archive.events / m["id"] / "manifest.json", m)
            if shell:
                capture = SessionCapture(archive, m, profile)
        except STORAGE_ERRORS:
            pass
    _copy_size(master)
    os.set_blocking(master, False)
    previous_winch = signal.signal(signal.SIGWINCH, lambda *_: _copy_size(master))
    old_signals = {s: signal.signal(s, lambda signum, _f: os.killpg(pid, signum))
                   for s in (signal.SIGTERM, signal.SIGHUP)}
    if attrs is not None:
        tty.setraw(0)
    active_command = None
    metadata_buffer = b""
    previous = time.monotonic()
    watched = {master, rfd, 0}
    if capture:
        watched.add(capture.sock.fileno())
    storage_failed = False

    def echo_state():
        try:
            return bool(termios.tcgetattr(master)[3] & termios.ECHO)
        except OSError:
            return None

    def storage_error():
        nonlocal storage_failed
        storage_failed = True
        if capture:
            capture.allowed = False
            capture.instrumented = False
            capture.pending.clear()

    def finish_command(code):
        nonlocal active_command
        if active_command and archive:
            archive.finish(active_command, code)
        active_command = None

    def output(data):
        nonlocal previous
        _write(1, data)  # original is always forwarded before any storage operation
        now = time.monotonic()
        try:
            if not storage_failed:
                if capture:
                    capture.output(data, echo_state())
                elif not shell and archive and m:
                    archive.append(m, data, now - previous)
        except STORAGE_ERRORS:
            storage_error()
        previous = now

    def drain():
        # Drain prior command output before processing its end/begin metadata.
        # This prevents a sensitive command's tail entering the next prompt cache.
        for _ in range(64):
            try:
                data = os.read(master, 65536)
                if not data:
                    return
                output(data)
            except OSError as exc:
                if exc.errno in (errno.EIO, errno.EAGAIN):
                    return
                raise
        if capture:
            capture.block("output-boundary-overflow")

    try:
        while master in watched:
            ready, _, _ = select.select(list(watched), [], [], .1)
            # Guard changes must precede command output when both are ready.
            ready.sort(key=lambda fd: 0 if fd == rfd else 1)
            for fd in ready:
                if capture and fd == capture.sock.fileno():
                    try:
                        capture.control()
                    except STORAGE_ERRORS:
                        storage_error()
                    continue
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
                    if capture and not storage_failed:
                        try:
                            capture.input(data, echo_state())
                        except STORAGE_ERRORS:
                            storage_error()
                    _write(master, data)
                elif fd == master:
                    output(data)
                else:
                    metadata_buffer += data
                    if len(metadata_buffer) > 131072:
                        metadata_buffer = b""
                        if capture:
                            capture.event("F")
                    while metadata_buffer.count(b"\0") >= 5:
                        fields = metadata_buffer.split(b"\0", 5)
                        metadata_buffer = fields.pop()
                        event = fields[0].decode("ascii", "ignore")
                        try:
                            shell_pid, code = map(int, fields[1:3])
                            if not shell or shell_pid != pid or not 0 <= code <= 255:
                                continue
                            if event in {"B", "E"}:
                                drain()
                            if capture and not storage_failed:
                                capture.event(event, fields[4].decode("utf-8", "replace"),
                                              fields[3].decode("utf-8", "replace"), code)
                            # Raw command/cwd do not leave this in-memory boundary.
                            if event in {"B", "E"} and archive and not storage_failed:
                                finish_command(code)
                                if event == "B":
                                    active_command = archive.begin(kind="command", source="bash",
                                                                   label="excluded", pid=pid, parent=m["id"])
                        except STORAGE_ERRORS:
                            storage_error()
                        finally:
                            if event in {"B", "E", "H"}:
                                try:
                                    os.write(ack_write, b"R" if not storage_failed else b"F")
                                except OSError:
                                    storage_error()
    finally:
        if attrs is not None:
            termios.tcsetattr(0, termios.TCSADRAIN, attrs)
        signal.signal(signal.SIGWINCH, previous_winch)
        for sig, handler in old_signals.items():
            signal.signal(sig, handler)
        for fd in (master, rfd, ack_write):
            os.close(fd)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    code = code if code >= 0 else 128 - code
    if archive and m:
        try:
            if capture:
                capture.close()
            finish_command(code)
            archive.finish(m, code)
        except STORAGE_ERRORS:
            pass
    return code
