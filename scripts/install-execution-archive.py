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
ADAPTER = '''#!/usr/bin/python3 -I
import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / ".local/libexec/fsm-execution-archive"))
from execution_archive.process_adapter import main
raise SystemExit(main(["--source", "SOURCE", "--", *sys.argv[1:]]))
'''
CODEX_HOOK_COMMAND = "/usr/bin/python3 " + str(Path.home() / ".local/libexec/fsm-execution-archive/codex-hook.py")
RDC_ADAPTER = str(Path.home() / ".local/bin/fsm-ea-rdc-bash")


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
    receipt_path = STATE / "install-receipt.json"
    old_receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else {}
    rdc_config = Path.home() / ".claude-server-commander/config.json"
    codex_hooks = Path.home() / ".codex/hooks.json"
    if not args.rollback:
        if rdc_config.is_symlink() or not rdc_config.is_file() or rdc_config.stat().st_uid != os.getuid():
            raise ValueError("regular owned RDC config required")
        rdc = json.loads(rdc_config.read_text())
        if codex_hooks.is_symlink() or (codex_hooks.exists() and codex_hooks.stat().st_uid != os.getuid()):
            raise ValueError("regular owned Codex hooks required")
        hooks_doc = json.loads(codex_hooks.read_text()) if codex_hooks.exists() else {
            "description": "Fedora System Monitor execution archive adapter", "hooks": {}}
        if not isinstance(hooks_doc.get("hooks", {}), dict):
            raise ValueError("invalid Codex hooks")
    if args.rollback:
        for block in (ENTRY, METADATA, LEGACY_METADATA):
            text = text.replace(block, "")
        write(bashrc, text.encode(), bashrc.stat().st_mode & 0o777)
        if STATE.is_dir():
            write(STATE / "disabled", b"")
        if rdc_config.is_file() and not rdc_config.is_symlink():
            rdc = json.loads(rdc_config.read_text())
            if rdc.get("defaultShell") == RDC_ADAPTER and old_receipt.get("rdc_default_shell_original"):
                rdc["defaultShell"] = old_receipt["rdc_default_shell_original"]
                write(rdc_config, (json.dumps(rdc, indent=2) + "\n").encode(), rdc_config.stat().st_mode & 0o777)
        if codex_hooks.is_file() and not codex_hooks.is_symlink():
            hooks_doc = json.loads(codex_hooks.read_text())
            groups = hooks_doc.get("hooks", {}).get("PreToolUse", [])
            kept = []
            for group in groups:
                handlers = [h for h in group.get("hooks", []) if h.get("command") != CODEX_HOOK_COMMAND]
                if handlers:
                    kept.append(group | {"hooks": handlers})
            if "hooks" in hooks_doc:
                if kept:
                    hooks_doc["hooks"]["PreToolUse"] = kept
                else:
                    hooks_doc["hooks"].pop("PreToolUse", None)
            write(codex_hooks, (json.dumps(hooks_doc, indent=2) + "\n").encode(), codex_hooks.stat().st_mode & 0o777)
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
        for name in ("__init__.py", "cli.py", "capture.py", "terminal.py", "process_adapter.py"):
            write(package / name, (REPO / "src/fedora_system_monitor/capsules/execution_archive" / name).read_bytes())
        for source, target in (("entry", "entry"), ("metadata", "metadata")):
            write(stage / f"{target}.bash", (REPO / f"hooks/execution-archive-{source}.bash").read_bytes())
        write(stage / "codex-hook.py", (REPO / "hooks/execution-archive-codex.py").read_bytes(), 0o700)
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
            write(Path.home() / ".local/bin/fsm-ea-rdc-bash", ADAPTER.replace("SOURCE", "rdc").encode(), 0o700)
            write(Path.home() / ".local/bin/fsm-ea-codex-bash", ADAPTER.replace("SOURCE", "codex").encode(), 0o700)
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
        rdc_original = old_receipt.get("rdc_default_shell_original")
        if not rdc_original and rdc.get("defaultShell") != RDC_ADAPTER:
            rdc_original = rdc.get("defaultShell")
        rdc["defaultShell"] = RDC_ADAPTER
        write(rdc_config, (json.dumps(rdc, indent=2) + "\n").encode(), rdc_config.stat().st_mode & 0o777)
        codex_hooks.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        groups = hooks_doc.setdefault("hooks", {}).setdefault("PreToolUse", [])
        if not any(h.get("command") == CODEX_HOOK_COMMAND for g in groups for h in g.get("hooks", [])):
            groups.append({"matcher": "Bash", "hooks": [{"type": "command",
                           "command": CODEX_HOOK_COMMAND, "timeout": 3}]})
        write(codex_hooks, (json.dumps(hooks_doc, indent=2) + "\n").encode(),
              codex_hooks.stat().st_mode & 0o777 if codex_hooks.exists() else 0o600)
        write(receipt_path, (json.dumps({
            "bashrc_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "bashrc_original_sha256": hashlib.sha256(original).hexdigest(),
            "runtime": str(RUNTIME), "nv": int((REPO / "NV.txt").read_text()),
            "rdc_default_shell_original": rdc_original,
            "rdc_default_shell": RDC_ADAPTER,
            "codex_hook_command": CODEX_HOOK_COMMAND,
            "rollback": "python3 scripts/install-execution-archive.py --rollback",
        }, sort_keys=True) + "\n").encode())
        print("Installed ea, Bash hooks, RDC adapter, and Codex hook. ea disable/enable controls capture.")
    finally:
        if stage.exists():
            shutil.rmtree(stage)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print("Install refused: " + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
