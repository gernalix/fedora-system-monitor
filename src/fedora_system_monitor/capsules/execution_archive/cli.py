"""Execution archive CLI and terminal PTY boundary. Safe defaults and explicitly consented visible PTY capture."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from . import Archive, SAFE, SOURCES, atomic_json, private_file


from .terminal import relay
from .capture import request, preferences
from .local_sources import collect_journal, collect_podman, inventory, run_wrapped

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
    capture = sub.add_parser("capture", help="explicit opt-in to potentially sensitive visible output")
    capture.add_argument("action", choices=("on", "off", "status"))
    capture.add_argument("--session")
    capture.add_argument("--input", action="store_true", help="also allow ordinary ECHO-on application input")
    capture.add_argument("--new-sessions", action="store_true")
    capture.add_argument("--profile", help="named startup profile; omit for all future sessions")
    capture.add_argument("--consent", action="store_true", help="required for persistent future-session consent")
    for name in ("pause", "resume"):
        control = sub.add_parser(name)
        control.add_argument("--session")
    policy = sub.add_parser("policy")
    policy.add_argument("--exclude-command", action="append", default=[])
    policy.add_argument("--sensitive-path", action="append", default=[])
    search = sub.add_parser("search")
    search.add_argument("query", nargs="?", default="")
    search.add_argument("--source", choices=sorted(SOURCES))
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
    sources = sub.add_parser("sources", help="bounded native local execution sources")
    source_sub = sources.add_subparsers(dest="source_operation", required=True)
    source_sub.add_parser("inventory", help="read-only presence and coverage matrix")
    journal = source_sub.add_parser("collect-journal", help="consume one exact unit with a private cursor")
    journal.add_argument("--scope", choices=("system", "user"), required=True)
    journal.add_argument("--unit", required=True)
    journal.add_argument("--since", default="-15min")
    journal.add_argument("--include-output", action="store_true",
                         help="exact-unit journal stream; stdout/stderr remain combined")
    podman = source_sub.add_parser("collect-podman", help="consume native Podman lifecycle metadata")
    podman.add_argument("--since", default="-15m")
    wrapped = source_sub.add_parser("run", help="explicit metadata-only lifecycle wrapper")
    wrapped.add_argument("--source", choices=("git-hook", "ide", "launcher"), required=True)
    wrapped.add_argument("--name", required=True)
    wrapped.add_argument("argv", nargs=argparse.REMAINDER)
    shell = sub.add_parser("shell", help=argparse.SUPPRESS)
    shell.add_argument("--login", action="store_true")
    shell.add_argument("--profile", default=os.environ.get("FSM_EA_PROFILE", os.environ.get("PTYXIS_PROFILE", "default")))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if sys.stdout.isatty() and not args.json and args.operation not in {"run", "shell", "replay"}:
        candidates = (Path(__file__).parents[1] / "NV.txt", Path(__file__).parents[4] / "NV.txt")
        for candidate in candidates:
            if candidate.is_file():
                print("NV " + candidate.read_text().strip())
                break
    if args.operation == "sources" and args.source_operation == "inventory":
        print(json.dumps(inventory(), sort_keys=True))
        return 0
    if args.operation == "sources" and args.source_operation == "run":
        wrapped_argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        try:
            return run_wrapped(args.root, args.source, args.name, wrapped_argv)
        except ValueError:
            print(json.dumps({"ok": False, "error_type": "ValueError"}), file=sys.stderr)
            return 1
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
        return relay([], archive, m, shell=True, login=args.login, profile=args.profile)
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
        if op in {"capture", "pause", "resume"}:
            action = args.action if op == "capture" else op
            if op == "capture" and args.new_sessions:
                if action not in {"on", "off"} or (action == "on" and not args.consent):
                    raise ValueError("persistent full needs explicit --consent")
                with a.lock():
                    prefs = preferences(a)
                    if action == "on":
                        consent = dict(explicit=True, scope="profile" if args.profile else "new-sessions",
                                       at=time.time(), input=args.input, action="ea capture on --new-sessions --consent")
                    else:
                        consent = None
                    if args.profile:
                        if not args.profile.replace("-", "").replace("_", "").isalnum():
                            raise ValueError("invalid profile")
                        profiles = prefs.setdefault("profiles", {})
                        if consent:
                            profiles[args.profile] = consent
                        else:
                            profiles.pop(args.profile, None)
                    elif consent:
                        prefs["global_consent"] = consent
                    else:
                        prefs.pop("global_consent", None)
                    atomic_json(a.root / "capture-policy.json", prefs)
                result = {"new_sessions": action, "profile": args.profile,
                          "existing_sessions_unchanged": True, "risk": "arbitrary output may contain private content"}
            else:
                session = args.session or os.environ.get("FSM_EA_SESSION")
                if not session:
                    raise ValueError("run inside a newly instrumented terminal or use --session")
                result = request(a, session, {"action": action, "input": getattr(args, "input", False)})
                if not result.get("ok"):
                    raise ValueError("control refused")
        elif op == "policy":
            with a.lock():
                prefs = preferences(a)
                for key, additions in (("exclude_commands", args.exclude_command), ("sensitive_paths", args.sensitive_path)):
                    existing = prefs.setdefault(key, [])
                    for item in additions:
                        if not item or "\0" in item or len(item) > 4096:
                            raise ValueError("invalid exclusion")
                        if item not in existing:
                            existing.append(item)
                atomic_json(a.root / "capture-policy.json", prefs)
            result = prefs
        elif op == "run":
            return run_command(args, a)
        elif op == "sources":
            if args.source_operation == "collect-journal":
                result = collect_journal(a, scope=args.scope, unit=args.unit,
                                         include_output=args.include_output, since=args.since)
            elif args.source_operation == "collect-podman":
                result = collect_podman(a, since=args.since)
            else:
                raise ValueError("unsupported source operation")
        elif op == "status":
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
