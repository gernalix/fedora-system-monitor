"""Explicit consent and conservative gates for visible terminal content.

No raw command/cwd is persisted. Recognizable sources are refused, not redacted.
These guards cannot prove that arbitrary authorized output contains no secret.
"""
import fnmatch
import json
import os
import re
import socket
import struct
import time
import uuid

from . import atomic_json, fingerprint

DENY = re.compile(r"(?i)(chatgpt|codex|bitwarden|\bbw\b|secret|password|passwd|token|"
                  r"credential|authorization|printenv|\benv\b|\bexport\b|\bset\b|"
                  r"\bdeclare\b|\bsudo\b|\bssh\b|\bgpg\b|\bread\b.*\s-[^\s;]*s|"
                  r"getpass|termios|stty|\.config|\.mozilla|\.local/share/(?:keyrings|.*browser)|"
                  r"(?:google-chrome|chromium)|(?:chat|session|conversation).*\.(?:jsonl|sqlite|db)|"
                  r"backup|archive.*chat)")
OUTPUT_DENY = re.compile(rb"(?i)(password|token|secret|api[_ -]?key|authorization)\s*[:=]|"
                         rb"codex://|ChatGPT|BEGIN (?:RSA |OPENSSH )?PRIVATE KEY")


def preferences(a):
    p = a.root / "capture-policy.json"
    value = json.loads(p.read_text()) if p.exists() else {}
    if not isinstance(value, dict):
        raise ValueError("invalid policy")
    return value


def exclusion(command, cwd, prefs):
    # All values are ephemeral within this local boundary, never hashed or logged.
    if DENY.search(command) or DENY.search(cwd):
        return "sensitive-source"
    for pattern in prefs.get("exclude_commands", []):
        if fnmatch.fnmatchcase(command, pattern):
            return "configured-command"
    for path in prefs.get("sensitive_paths", []):
        if cwd == path or cwd.startswith(path.rstrip("/") + "/") or path in command:
            return "configured-path"
    return None


def request(a, session, message):
    session = str(uuid.UUID(session))
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(2)
        s.connect("\0fsm-ea:" + str(os.getuid()) + ":" + session)
        s.sendall(json.dumps(message).encode() + b"\n")
        s.shutdown(socket.SHUT_WR)
        data = s.recv(8192)
        return json.loads(data)
    finally:
        s.close()


class SessionCapture:
    def __init__(self, a, session, profile="default"):
        self.a, self.session = a, session
        self.path = a.events / session["id"]
        self.profile = profile
        self.prefs = preferences(a)
        consent = self.prefs.get("profiles", {}).get(profile) or self.prefs.get("global_consent")
        self.consent = consent if isinstance(consent, dict) and consent.get("explicit") else None
        self.level = "full" if self.consent else "safe"
        self.paused = False
        self.instrumented = False
        self.phase = "startup"
        self.allowed = False
        self.reason = "shell-guard-unavailable"
        self.segment = None
        self.pending = []
        self.pending_size = 0
        self.previous = {"output": time.monotonic(), "input": time.monotonic()}
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind("\0fsm-ea:" + str(os.getuid()) + ":" + session["id"])
        self.sock.listen(4)
        self.sock.setblocking(False)
        self.state()

    def state(self):
        value = dict(session=self.session["id"], profile=self.profile, level=self.level,
                     paused=self.paused, guard=self.instrumented, phase=self.phase,
                     content_enabled=self.active(), reason=self.reason, consent=self.consent,
                     residual_risk=self.level == "full", input="echo-on-only" if
                     self.consent and self.consent.get("input") else "visible-echo-only",
                     owner_pid=os.getpid(), owner_fingerprint=fingerprint(os.getpid()))
        atomic_json(self.path / "capture-state.json", value)
        return value

    def active(self):
        return bool(self.level == "full" and self.consent and self.instrumented and
                    self.allowed and not self.paused and self.a.enabled())

    def finish(self, code=None):
        if self.segment:
            self.a.finish(self.segment, code)
            self.segment = None

    def block(self, reason):
        self.finish()
        self.allowed = False
        self.reason = reason
        self.pending.clear()
        self.pending_size = 0
        self.state()

    def event(self, event, command="", cwd="", code=None):
        if event == "H":
            self.instrumented = True
            self.phase = "prompt"
            self.reason = "awaiting-command"
        elif event in {"B", "E"}:
            self.finish(code)
            self.allowed = False
            if event == "B":
                self.prefs = preferences(self.a)
                self.phase = "pending"
                self.reason = exclusion(command, cwd, self.prefs) or "awaiting-ack"
                if self.reason != "awaiting-ack":
                    self.pending.clear()
                    self.pending_size = 0
            else:
                self.phase = "prompt"
                self.reason = "awaiting-command"
                self.pending.clear()
                self.pending_size = 0
        elif event == "A":
            self.phase = "command"
            self.allowed = self.reason == "awaiting-ack"
            if self.allowed:
                self.reason = "authorized" if self.level == "full" else "safe-metadata-only"
                if self.active():
                    if OUTPUT_DENY.search(b"".join(data for _stamp, data in self.pending)):
                        self.block("recognizable-sensitive-prompt")
                        return
                    for stamp, data in self.pending:
                        self.record(data, stamp=stamp)
            self.pending.clear()
            self.pending_size = 0
        elif event == "F":
            self.instrumented = False
            self.block("shell-control-failed")
        self.state()

    def record(self, data, *, stream="output", stamp=None):
        if not self.active():
            return
        if self.segment is None:
            self.segment = self.a.begin(kind="session", source="bash", label="shell",
                                        pid=self.session["pid"], parent=self.session["id"],
                                        capture=True, consent=self.consent)
        now = stamp if stamp is not None else time.monotonic()
        self.a.append(self.segment, data, max(0, now - self.previous[stream]), stream=stream)
        self.previous[stream] = now
        if self.segment["coverage"] == "truncated":
            self.block("quota-truncated")

    def output(self, data, echo):
        if self.level != "full" or self.paused or not self.instrumented:
            return
        if self.phase == "prompt":
            # Bash Readline echoes itself with ECHO off. Delay all prompt/line echo
            # until a command has been classified; never save an unapproved line.
            if self.pending_size + len(data) <= 65536:
                self.pending.append((time.monotonic(), data))
                self.pending_size += len(data)
            else:
                self.pending.clear()
                self.pending_size = 65537
            return
        if self.phase != "command" or not self.allowed:
            return
        if echo is not True:
            self.block("non-echo-or-unknown-tty")
        elif OUTPUT_DENY.search(data):
            self.block("recognizable-sensitive-output")
        else:
            self.record(data)

    def input(self, data, echo):
        # Prompt keyboard input cannot be distinguished safely from secret command
        # arguments. Only explicitly opted-in application input with ECHO on.
        if self.phase != "command" or not self.active():
            return
        if echo is not True:
            self.block("non-echo-input")
        elif OUTPUT_DENY.search(data):
            self.block("recognizable-sensitive-input")
        elif self.consent.get("input"):
            self.record(data, stream="input")

    def control(self):
        conn, _ = self.sock.accept()
        try:
            conn.settimeout(.15)
            _pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.getuid():
                raise ValueError("foreign peer")
            raw = conn.recv(4096)
            message = json.loads(raw)
            action = message.get("action")
            if action == "on":
                if not self.instrumented:
                    raise ValueError("shell guard unavailable")
                self.finish()
                self.consent = dict(explicit=True, scope="session", action="ea capture on",
                                    at=time.time(), input=message.get("input") is True)
                self.level, self.paused = "full", False
            elif action == "off":
                self.finish()
                self.level, self.consent, self.paused = "safe", None, False
            elif action == "pause":
                self.finish()
                self.paused = True
            elif action == "resume":
                if not self.instrumented:
                    raise ValueError("shell guard unavailable")
                self.paused = False
            elif action != "status":
                raise ValueError("invalid control")
            self.pending.clear()
            self.pending_size = 0
            result = self.state() | {"ok": True}
        except (ValueError, OSError):
            result = {"ok": False, "reason": "capture-control-refused"}
        finally:
            try:
                conn.sendall(json.dumps(result).encode())
            finally:
                conn.close()

    def close(self):
        self.finish()
        self.sock.close()
