#!/usr/bin/python3 -I
"""Codex PreToolUse adapter: wrap only Bash, never inspect transcript_path."""
import json
import shlex
import sys
from pathlib import Path

ADAPTER = str(Path.home() / ".local/bin/fsm-ea-codex-bash")


def main():
    try:
        event = json.load(sys.stdin)
        command = event.get("tool_input", {}).get("command")
        if event.get("hook_event_name") != "PreToolUse" or event.get("tool_name") != "Bash":
            return 0
        if not isinstance(command, str) or not command or ADAPTER in command:
            return 0
        updated = "exec " + shlex.quote(ADAPTER) + " -lc " + shlex.quote(command)
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "allow",
            "updatedInput": {"command": updated}}}, separators=(",", ":")))
        return 0
    except (OSError, ValueError, TypeError):
        # Hook failure is intentionally silent and fail-open for the original tool.
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
