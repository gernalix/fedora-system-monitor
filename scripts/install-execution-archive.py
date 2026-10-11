#!/usr/bin/python3
"""Install only the private user archive; never restart the Fedora monitor.

Rollback removes our exact blocks, preserving independent shell customizations.
"""
import argparse
import hashlib
import json
import os
import shutil
import secrets
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUNTIME = Path.home() / ".local/libexec/fsm-execution-archive"
STATE = Path.home() / ".local/state/fedora-system-monitor/executions"
ENTRY = '# BEGIN FSM EXECUTION ARCHIVE ENTRY\nsource "$HOME/.local/libexec/fsm-execution-archive/entry.bash"\n# END FSM EXECUTION ARCHIVE ENTRY\n'
LEGACY_METADATA = '\n# BEGIN FSM EXECUTION ARCHIVE METADATA\nsource "$HOME/.local/libexec/fsm-execution-archive/metadata.bash"\n# END FSM EXECUTION ARCHIVE METADATA\n'
METADATA = LEGACY_METADATA.replace('metadata.bash"\n', 'metadata.bash" "$(trap -p DEBUG)"\n')
CLI = '''#!/usr/bin/python3 -I
import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / ".local/libexec/fsm-execution-archive"))
from execution_archive.cli import main
raise SystemExit(main())
'''


def write(path, data, mode=0o600):
    if path.is_symlink():
        raise ValueError("symlink refused")
    tmp = path.with_name(path.name + ".install-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rollback", action="store_true")
    args = p.parse_args()
    if os.getuid() == 0:
        raise ValueError("install as the desktop user, never root")
    bashrc = Path.home() / ".bashrc"
    if bashrc.is_symlink() or not bashrc.is_file() or bashrc.stat().st_uid != os.getuid():
        raise ValueError("regular owned bashrc required")
    original = bashrc.read_bytes()
    text = original.decode()
    if args.rollback:
        for block in (ENTRY, METADATA, LEGACY_METADATA):
            text = text.replace(block, "")
        write(bashrc, text.encode(), bashrc.stat().st_mode & 0o777)
        if STATE.is_dir():
            write(STATE / "disabled", b"")
        print("Archive hooks removed; originals and private runtime preserved.")
        return
    text = text.replace(LEGACY_METADATA, METADATA)
    cli_path = Path.home() / ".local/bin/ea"
    if cli_path.exists() and (cli_path.is_symlink() or cli_path.read_text() != CLI):
        raise ValueError("existing ea belongs to another owner")
    for marker, block in (("# BEGIN FSM EXECUTION ARCHIVE ENTRY", ENTRY),
                          ("# BEGIN FSM EXECUTION ARCHIVE METADATA", METADATA)):
        if marker in text and block not in text:
            raise ValueError("modified shell block refused")
    for path in (STATE.parent, STATE, RUNTIME.parent, Path.home() / ".local/bin"):
        if path.is_symlink():
            raise ValueError("symlink root refused")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.parent.chmod(0o700)
    STATE.chmod(0o700)
    if RUNTIME.is_symlink():
        raise ValueError("symlink runtime refused")
    stage = Path(tempfile.mkdtemp(prefix=".fsm-ea-", dir=RUNTIME.parent))
    try:
        package = stage / "execution_archive"
        package.mkdir(mode=0o700)
        for name in ("__init__.py", "cli.py", "capture.py", "terminal.py"):
            write(package / name, (REPO / "src/fedora_system_monitor/capsules/execution_archive" / name).read_bytes())
        for source, target in (("entry", "entry"), ("metadata", "metadata")):
            write(stage / f"{target}.bash", (REPO / f"hooks/execution-archive-{source}.bash").read_bytes())
        write(stage / "NV.txt", (REPO / "NV.txt").read_bytes())
        old = RUNTIME.with_name(RUNTIME.name + ".previous")
        if old.exists():
            old = RUNTIME.with_name(RUNTIME.name + ".previous-" + secrets.token_hex(4))
        if old.is_symlink():
            raise ValueError("symlink backup refused")
        if RUNTIME.exists():
            os.replace(RUNTIME, old)
        try:
            os.replace(stage, RUNTIME)
            write(Path.home() / ".local/bin/ea", CLI.encode(), 0o700)
        except Exception:
            if old.exists() and not RUNTIME.exists():
                os.replace(old, RUNTIME)
            raise
        # No shell contents are printed, indexed, exported or sent to Git.
        if ENTRY not in text:
            text = ENTRY + text
        if METADATA not in text:
            text = text + METADATA
        write(bashrc, text.encode(), bashrc.stat().st_mode & 0o777)
        write(STATE / "install-receipt.json", (json.dumps({
            "bashrc_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "bashrc_original_sha256": hashlib.sha256(original).hexdigest(),
            "runtime": str(RUNTIME), "nv": int((REPO / "NV.txt").read_text()),
            "rollback": "python3 scripts/install-execution-archive.py --rollback",
        }, sort_keys=True) + "\n").encode())
        print("Installed ea and Bash hooks. New interactive terminals only; ea disable/enable.")
    finally:
        if stage.exists():
            shutil.rmtree(stage)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print("Install refused: " + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
