#!/usr/bin/env python3
"""Incrementally mirror one Telegram peer into a private text-only Git archive."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("invalid environment config")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError("invalid environment config")
        values[key] = value
    return values


def utc_iso(value: Any) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def message_record(message: Any) -> dict[str, Any]:
    media: dict[str, Any] | None = None
    document = getattr(message, "document", None)
    photo = getattr(message, "photo", None)
    if document is not None:
        media = {"kind": "document"}
        mime = getattr(document, "mime_type", None)
        size = getattr(document, "size", None)
        if mime:
            media["mime_type"] = mime
        if size is not None:
            media["size"] = size
        for attr in getattr(document, "attributes", ()) or ():
            name = getattr(attr, "file_name", None)
            if name:
                media["file_name"] = name
                break
    elif photo is not None:
        media = {"kind": "photo"}
    elif getattr(message, "media", None) is not None:
        media = {"kind": "other"}
    record: dict[str, Any] = {
        "message_id": int(message.id),
        "date_utc": utc_iso(message.date),
        "text": getattr(message, "message", None) or "",
    }
    if media is not None:
        record["media"] = media
    reply_id = getattr(getattr(message, "reply_to", None), "reply_to_msg_id", None)
    if reply_id is not None:
        record["reply_to_message_id"] = int(reply_id)
    return record


def read_state(path: Path) -> int:
    if not path.exists():
        return 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    last_id = payload.get("last_message_id")
    if not isinstance(last_id, int) or last_id < 0:
        raise ValueError("invalid collector state")
    return last_id


def serialize_changes(root: Path, last_id: int, records: list[dict[str, Any]]) -> list[Path]:
    """Write ordered new records and bounded latest view; return changed paths."""
    if not records:
        return []
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    records = sorted(records, key=lambda item: item["message_id"])
    archive: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        month = record["date_utc"][:7]
        archive.setdefault(month, []).append(record)
    changes: list[Path] = []
    all_records: list[dict[str, Any]] = []
    for file in sorted(root.glob("messages-????-??.jsonl")):
        for line in file.read_text(encoding="utf-8").splitlines():
            if line:
                all_records.append(json.loads(line))
    seen = {item["message_id"] for item in all_records}
    for month, items in archive.items():
        path = root / f"messages-{month}.jsonl"
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        additions = [item for item in items if item["message_id"] not in seen]
        if additions:
            separator = "" if not existing or existing.endswith("\n") else "\n"
            path.write_text(existing + separator + "".join(
                json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
                for item in additions
            ), encoding="utf-8")
            os.chmod(path, 0o600)
            changes.append(path)
            all_records.extend(additions)
            seen.update(item["message_id"] for item in additions)
    if not seen:
        return changes
    new_last_id = max(last_id, max(seen))
    state_path = root / "state.json"
    state_text = json.dumps({"last_message_id": new_last_id}, sort_keys=True, indent=2) + "\n"
    if not state_path.exists() or state_path.read_text(encoding="utf-8") != state_text:
        state_path.write_text(state_text, encoding="utf-8")
        os.chmod(state_path, 0o600)
        changes.append(state_path)
    all_records.sort(key=lambda item: item["message_id"])
    latest = all_records[-100:]
    md = ["# Latest technical Telegram messages", "", f"Showing {len(latest)} latest archived messages.", ""]
    for item in latest:
        md.extend([f"## {item['message_id']} · {item['date_utc']}", "", item.get("text", "") or "*(no text)*", ""])
        if item.get("media"):
            md.extend([f"Media: `{json.dumps(item['media'], ensure_ascii=False, sort_keys=True)}`", ""])
    view_path = root / "latest.md"
    rendered = "\n".join(md)
    if not view_path.exists() or view_path.read_text(encoding="utf-8") != rendered:
        view_path.write_text(rendered, encoding="utf-8")
        os.chmod(view_path, 0o600)
        changes.append(view_path)
    return changes


def collect(client: Any, peer: str, last_id: int) -> list[dict[str, Any]]:
    configured_peer: str | int = int(peer) if re.fullmatch(r"-?\d+", peer) else peer
    entity = client.get_entity(configured_peer)
    records = []
    for message in client.iter_messages(entity, min_id=last_id, reverse=True):
        records.append(message_record(message))
    return sorted((item for item in records if item["message_id"] > last_id), key=lambda item: item["message_id"])


def git(repo: Path, *args: str) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never")
    result = subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    return result.stdout.strip()


def transaction_file(repo: Path) -> Path:
    path = Path(git(repo, "rev-parse", "--git-path", "telegram-history-transaction.json"))
    return path if path.is_absolute() else repo / path


def write_transaction(repo: Path, base: str, branch: str) -> Path:
    marker = transaction_file(repo)
    marker.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker.parent.chmod(0o700)
    payload = json.dumps({"base": base, "branch": branch}, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=marker.parent, prefix=".telegram-history-",
                                     delete=False) as stream:
        temp_path = Path(stream.name)
        os.chmod(temp_path, 0o600)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp_path, marker)
    dir_fd = os.open(marker.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return marker


def recover_transaction(repo: Path) -> None:
    marker = transaction_file(repo)
    marker.with_name(marker.name + ".tmp").unlink(missing_ok=True)
    if not marker.exists():
        return
    payload = json.loads(marker.read_text(encoding="utf-8"))
    base = payload["base"]
    branch = payload["branch"]
    git(repo, "fetch", "origin")
    remote_ref = f"origin/{branch}"
    remote_head = git(repo, "rev-parse", remote_ref)
    ancestry = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", base, remote_ref],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    if ancestry != 0:
        raise RuntimeError("remote archive diverged during interrupted transaction")
    git(repo, "reset", "--hard", remote_head)
    git(repo, "clean", "-fd", "--", "archive")
    marker.unlink(missing_ok=True)


def sync(config: dict[str, str], client: Any) -> int:
    repo = Path(config["DATA_REPO"]).expanduser()
    archive = repo / "archive"
    if repo.exists():
        os.chmod(repo, 0o700)
    expected_remote = config.get("DATA_REMOTE", "https://github.com/gernalix/telegram-notification-history.git")
    if not (repo / ".git").exists() or git(repo, "remote", "get-url", "origin") != expected_remote:
        raise RuntimeError("data repository path or origin mismatch")
    recover_transaction(repo)
    if git(repo, "status", "--porcelain"):
        raise RuntimeError("data repository has local changes")
    git(repo, "fetch", "origin")
    branch = git(repo, "branch", "--show-current")
    remote_ref = f"origin/{branch}"
    git(repo, "merge", "--ff-only", remote_ref)
    if git(repo, "rev-list", "--count", f"{remote_ref}..HEAD") != "0":
        # A prior push may have succeeded while its response was lost.
        git(repo, "push", "origin", branch)
    base = git(repo, "rev-parse", "HEAD")
    state_path = archive / "state.json"
    cursor = read_state(state_path)
    records = collect(client, config["TELEGRAM_CHAT"], cursor)
    if not records:
        return 0
    marker = write_transaction(repo, base, branch)
    try:
        changes = serialize_changes(archive, cursor, records)
        if not changes:
            marker.unlink(missing_ok=True)
            return 0
        git(repo, "add", "archive")
        if not git(repo, "diff", "--cached", "--name-only"):
            recover_transaction(repo)
            return 0
        git(repo, "-c", "user.name=Telegram history sync", "-c", "user.email=telegram-history@localhost",
            "commit", "-m", f"Archive Telegram messages through {read_state(state_path)}")
        git(repo, "push", "origin", branch)
    except Exception:
        # The marker lets the next timer run recover even after SIGKILL or power loss.
        recover_transaction(repo)
        raise
    marker.unlink(missing_ok=True)
    return len(records)


def telegram_client(config: dict[str, str], *, interactive: bool) -> Any:
    try:
        from telethon.sync import TelegramClient
    except ImportError as exc:
        raise RuntimeError("Telethon dependency is not installed") from exc
    session_path = Path(config["SESSION_FILE"]).expanduser()
    session_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(session_path.parent, 0o700)
    client = TelegramClient(str(session_path), int(config["TELEGRAM_API_ID"]), config["TELEGRAM_API_HASH"])
    if interactive:
        phone = config.get("TELEGRAM_PHONE")
        if phone:
            client.start(phone=phone)
        else:
            client.start()
    else:
        client.connect()
        if not client.is_user_authorized():
            client.disconnect()
            raise RuntimeError("Telegram session is not authorized")
    os.chmod(session_path.parent, 0o700)
    session_file = Path(str(session_path) + ".session")
    if session_file.exists():
        os.chmod(session_file, 0o600)
    return client


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("login", "sync"))
    parser.add_argument("--config", default="~/.config/fedora-telegram-history/collector.env")
    args = parser.parse_args(argv)
    config_path = Path(args.config).expanduser()
    if not config_path.is_file():
        print("Collector config is missing.", file=sys.stderr)
        return 2
    try:
        config = load_env(config_path)
        os.chmod(config_path, 0o600)
        required = ("TELEGRAM_API_ID", "TELEGRAM_API_HASH", "TELEGRAM_CHAT", "SESSION_FILE", "DATA_REPO")
        if any(not config.get(key) for key in required):
            raise ValueError("required configuration is incomplete")
        if not config["TELEGRAM_API_ID"].isdigit():
            raise ValueError("invalid API id")
        os.umask(0o077)
        client = telegram_client(config, interactive=args.command == "login")
        try:
            if args.command == "login":
                if not client.is_user_authorized():
                    raise RuntimeError("Telegram login was not completed")
                print("Telegram session is authorized.")
                return 0
            count = sync(config, client)
            print(f"Telegram history sync complete; new_messages={count}.")
            return 0
        finally:
            client.disconnect()
    except Exception as exc:
        print(f"Telegram history sync failed ({type(exc).__name__}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
