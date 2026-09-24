#!/usr/bin/env python3
"""Incrementally preserve one Telegram auto-delete chat in a local SQLite archive."""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

UTC = dt.timezone.utc


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"invalid environment config line in {path}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"invalid environment config key in {path}")
        values[key] = value
    base = values.get("BASE_CONFIG", "").strip()
    if base:
        base_values = load_env(Path(base).expanduser())
        base_values.update(values)
        values = base_values
    return values


def utc_now() -> dt.datetime:
    return dt.datetime.now(tz=UTC)


def iso_utc(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def ensure_private_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)


def open_archive(path: Path) -> sqlite3.Connection:
    ensure_private_parent(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS messages (
            peer_id INTEGER NOT NULL,
            message_id INTEGER NOT NULL,
            date_utc TEXT NOT NULL,
            sender_id INTEGER,
            text TEXT NOT NULL DEFAULT '',
            edit_date_utc TEXT,
            reply_to_message_id INTEGER,
            media_kind TEXT,
            media_remote_id TEXT,
            media_path TEXT,
            media_sha256 TEXT,
            current_revision INTEGER NOT NULL DEFAULT 1,
            first_seen_at_utc TEXT NOT NULL,
            last_seen_at_utc TEXT NOT NULL,
            deleted_at_utc TEXT,
            deletion_reason TEXT,
            PRIMARY KEY (peer_id, message_id)
        );
        CREATE TABLE IF NOT EXISTS revisions (
            peer_id INTEGER NOT NULL,
            message_id INTEGER NOT NULL,
            revision_no INTEGER NOT NULL,
            captured_at_utc TEXT NOT NULL,
            text TEXT NOT NULL DEFAULT '',
            edit_date_utc TEXT,
            reply_to_message_id INTEGER,
            media_kind TEXT,
            media_remote_id TEXT,
            media_path TEXT,
            media_sha256 TEXT,
            PRIMARY KEY (peer_id, message_id, revision_no),
            FOREIGN KEY (peer_id, message_id)
                REFERENCES messages(peer_id, message_id)
                ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_messages_date
            ON messages(peer_id, date_utc);
        CREATE INDEX IF NOT EXISTS idx_messages_deleted
            ON messages(peer_id, deleted_at_utc);
        """
    )
    os.chmod(path, 0o600)
    return conn


def media_identity(message: Any) -> tuple[str | None, str | None]:
    document = getattr(message, "document", None)
    if document is not None:
        return "document", f"document:{getattr(document, 'id', '')}"
    photo = getattr(message, "photo", None)
    if photo is not None:
        return "photo", f"photo:{getattr(photo, 'id', '')}"
    media = getattr(message, "media", None)
    if media is not None:
        return type(media).__name__.lower(), f"{type(media).__name__}:{getattr(media, 'id', '')}"
    return None, None


def snapshot_from_message(message: Any) -> dict[str, Any]:
    reply_id = getattr(getattr(message, "reply_to", None), "reply_to_msg_id", None)
    kind, remote_id = media_identity(message)
    sender_id = getattr(message, "sender_id", None)
    return {
        "message_id": int(message.id),
        "date_utc": iso_utc(message.date),
        "sender_id": int(sender_id) if sender_id is not None else None,
        "text": getattr(message, "message", None) or "",
        "edit_date_utc": iso_utc(getattr(message, "edit_date", None)),
        "reply_to_message_id": int(reply_id) if reply_id is not None else None,
        "media_kind": kind,
        "media_remote_id": remote_id,
    }


CONTENT_FIELDS = (
    "text",
    "edit_date_utc",
    "reply_to_message_id",
    "media_kind",
    "media_remote_id",
    "media_path",
    "media_sha256",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


async def preserve_media(
    client: Any,
    message: Any,
    media_root: Path,
    peer_id: int,
    previous: sqlite3.Row | None,
) -> tuple[str | None, str | None]:
    kind, remote_id = media_identity(message)
    if kind is None:
        return None, None
    if (
        previous is not None
        and previous["media_remote_id"] == remote_id
        and previous["media_path"]
        and Path(previous["media_path"]).is_file()
    ):
        return str(previous["media_path"]), previous["media_sha256"]

    safe_remote = re.sub(r"[^A-Za-z0-9_.-]+", "_", remote_id or "media")
    target_dir = media_root / str(peer_id) / str(int(message.id)) / safe_remote
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target_dir, 0o700)
    downloaded = await client.download_media(message, file=str(target_dir))
    if not downloaded:
        return None, None
    path = Path(downloaded)
    if path.is_file():
        os.chmod(path, 0o600)
        return str(path.resolve()), sha256_file(path)
    return None, None


def store_snapshot(
    conn: sqlite3.Connection,
    peer_id: int,
    snapshot: dict[str, Any],
    seen_at: str,
    media_path: str | None,
    media_sha256: str | None,
) -> str:
    message_id = int(snapshot["message_id"])
    current = conn.execute(
        "SELECT * FROM messages WHERE peer_id=? AND message_id=?",
        (peer_id, message_id),
    ).fetchone()
    material = dict(snapshot, media_path=media_path, media_sha256=media_sha256)

    if current is None:
        conn.execute(
            """
            INSERT INTO messages (
                peer_id,message_id,date_utc,sender_id,text,edit_date_utc,
                reply_to_message_id,media_kind,media_remote_id,media_path,
                media_sha256,current_revision,first_seen_at_utc,last_seen_at_utc,
                deleted_at_utc,deletion_reason
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?,NULL,NULL)
            """,
            (
                peer_id, message_id, material["date_utc"], material["sender_id"],
                material["text"], material["edit_date_utc"],
                material["reply_to_message_id"], material["media_kind"],
                material["media_remote_id"], material["media_path"],
                material["media_sha256"], seen_at, seen_at,
            ),
        )
        conn.execute(
            """
            INSERT INTO revisions (
                peer_id,message_id,revision_no,captured_at_utc,text,edit_date_utc,
                reply_to_message_id,media_kind,media_remote_id,media_path,media_sha256
            ) VALUES (?,?,1,?,?,?,?,?,?,?,?)
            """,
            (
                peer_id, message_id, seen_at, material["text"],
                material["edit_date_utc"], material["reply_to_message_id"],
                material["media_kind"], material["media_remote_id"],
                material["media_path"], material["media_sha256"],
            ),
        )
        return "inserted"

    changed = any(current[field] != material[field] for field in CONTENT_FIELDS)
    if changed:
        revision = int(current["current_revision"]) + 1
        conn.execute(
            """
            INSERT INTO revisions (
                peer_id,message_id,revision_no,captured_at_utc,text,edit_date_utc,
                reply_to_message_id,media_kind,media_remote_id,media_path,media_sha256
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                peer_id, message_id, revision, seen_at, material["text"],
                material["edit_date_utc"], material["reply_to_message_id"],
                material["media_kind"], material["media_remote_id"],
                material["media_path"], material["media_sha256"],
            ),
        )
        conn.execute(
            """
            UPDATE messages SET
                sender_id=?, text=?, edit_date_utc=?, reply_to_message_id=?,
                media_kind=?, media_remote_id=?, media_path=?, media_sha256=?,
                current_revision=?, last_seen_at_utc=?,
                deleted_at_utc=NULL, deletion_reason=NULL
            WHERE peer_id=? AND message_id=?
            """,
            (
                material["sender_id"], material["text"], material["edit_date_utc"],
                material["reply_to_message_id"], material["media_kind"],
                material["media_remote_id"], material["media_path"],
                material["media_sha256"], revision, seen_at, peer_id, message_id,
            ),
        )
        return "updated"

    conn.execute(
        """
        UPDATE messages
        SET last_seen_at_utc=?, deleted_at_utc=NULL, deletion_reason=NULL
        WHERE peer_id=? AND message_id=?
        """,
        (seen_at, peer_id, message_id),
    )
    return "unchanged"


def mark_missing_deleted(
    conn: sqlite3.Connection,
    peer_id: int,
    cutoff_utc: str,
    seen_ids: set[int],
    deleted_at: str,
) -> int:
    candidates = conn.execute(
        """
        SELECT message_id FROM messages
        WHERE peer_id=? AND deleted_at_utc IS NULL AND date_utc>=?
        """,
        (peer_id, cutoff_utc),
    ).fetchall()
    missing = [int(row["message_id"]) for row in candidates if int(row["message_id"]) not in seen_ids]
    for message_id in missing:
        conn.execute(
            """
            UPDATE messages
            SET deleted_at_utc=?, deletion_reason='remote_missing'
            WHERE peer_id=? AND message_id=? AND deleted_at_utc IS NULL
            """,
            (deleted_at, peer_id, message_id),
        )
    return len(missing)


async def resolve_entity(client: Any, configured_peer: str | int) -> Any:
    if isinstance(configured_peer, str) and re.fullmatch(r"-?\d+", configured_peer):
        configured_peer = int(configured_peer)
    try:
        return await client.get_entity(configured_peer)
    except ValueError:
        real_peer_id = None
        if isinstance(configured_peer, int):
            if configured_peer <= -1_000_000_000_000:
                real_peer_id = -configured_peer - 1_000_000_000_000
            elif configured_peer < 0:
                real_peer_id = -configured_peer
            else:
                real_peer_id = configured_peer
        async for dialog in client.iter_dialogs():
            entity_id = getattr(dialog.entity, "id", None)
            if dialog.id == configured_peer or entity_id == real_peer_id:
                return dialog.entity
        raise


async def full_ttl(client: Any, entity: Any) -> int | None:
    from telethon.tl import functions, types
    if isinstance(entity, types.User):
        return getattr((await client(functions.users.GetFullUserRequest(entity))).full_user, "ttl_period", None)
    if isinstance(entity, types.Chat):
        return getattr((await client(functions.messages.GetFullChatRequest(entity.id))).full_chat, "ttl_period", None)
    if isinstance(entity, types.Channel):
        return getattr((await client(functions.channels.GetFullChannelRequest(entity))).full_chat, "ttl_period", None)
    return None


async def discover_ttl_peers(client: Any, ttl_seconds: int, limit: int) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    async for dialog in client.iter_dialogs(limit=limit):
        try:
            ttl = await full_ttl(client, dialog.entity)
        except Exception:
            continue
        if ttl == ttl_seconds:
            matches.append({
                "peer_id": int(dialog.id),
                "title": (dialog.name or "").replace("\n", " ")[:120],
                "kind": type(dialog.entity).__name__,
                "ttl_seconds": int(ttl),
            })
    return matches


async def resolve_target(client: Any, config: dict[str, str], state_dir: Path) -> tuple[Any, int]:
    from telethon import utils

    configured = config.get("TELEGRAM_CHAT", "").strip()
    resolved_path = state_dir / "resolved-peer.json"
    if configured:
        entity = await resolve_entity(client, configured)
        return entity, int(utils.get_peer_id(entity))

    if resolved_path.is_file():
        payload = json.loads(resolved_path.read_text(encoding="utf-8"))
        entity = await resolve_entity(client, int(payload["peer_id"]))
        return entity, int(utils.get_peer_id(entity))

    ttl_seconds = int(config.get("AUTO_DELETE_TTL_SECONDS", "86400"))
    limit = int(config.get("DISCOVERY_LIMIT", "50"))
    matches = await discover_ttl_peers(client, ttl_seconds, limit)
    if len(matches) != 1:
        detail = ", ".join(f"{m['peer_id']}:{m['title']!r}" for m in matches)
        raise RuntimeError(
            f"expected exactly one {ttl_seconds}s auto-delete peer in recent dialogs; "
            f"found {len(matches)} ({detail})"
        )
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    resolved_path.write_text(json.dumps(matches[0], ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(resolved_path, 0o600)
    entity = await resolve_entity(client, int(matches[0]["peer_id"]))
    return entity, int(matches[0]["peer_id"])


async def reconcile(
    client: Any,
    entity: Any,
    peer_id: int,
    conn: sqlite3.Connection,
    media_root: Path,
    horizon_seconds: int,
) -> dict[str, int]:
    now = utc_now()
    seen_at = iso_utc(now)
    cutoff = now - dt.timedelta(seconds=horizon_seconds)
    cutoff_iso = iso_utc(cutoff)
    seen_ids: set[int] = set()
    counts = {"inserted": 0, "updated": 0, "unchanged": 0, "deleted": 0}
    initial_backfill = conn.execute(
        "SELECT 1 FROM messages WHERE peer_id=? LIMIT 1",
        (peer_id,),
    ).fetchone() is None

    async for message in client.iter_messages(entity):
        if not initial_backfill and message.date is not None:
            message_date = message.date if message.date.tzinfo else message.date.replace(tzinfo=UTC)
            if message_date.astimezone(UTC) < cutoff:
                break
        snapshot = snapshot_from_message(message)
        seen_ids.add(int(snapshot["message_id"]))
        previous = conn.execute(
            "SELECT * FROM messages WHERE peer_id=? AND message_id=?",
            (peer_id, int(snapshot["message_id"])),
        ).fetchone()
        media_path, media_hash = await preserve_media(client, message, media_root, peer_id, previous)
        status = store_snapshot(conn, peer_id, snapshot, seen_at, media_path, media_hash)
        counts[status] += 1

    counts["deleted"] = mark_missing_deleted(conn, peer_id, cutoff_iso, seen_ids, seen_at)
    conn.commit()
    return counts


async def telegram_client(config: dict[str, str]) -> Any:
    try:
        from telethon import TelegramClient
    except ImportError as exc:
        raise RuntimeError("Telethon dependency is not installed") from exc
    required = ("TELEGRAM_API_ID", "TELEGRAM_API_HASH", "SESSION_FILE")
    if any(not config.get(key) for key in required):
        raise ValueError("Telegram credentials/session configuration is incomplete")
    if not config["TELEGRAM_API_ID"].isdigit():
        raise ValueError("invalid TELEGRAM_API_ID")
    session_path = Path(config["SESSION_FILE"]).expanduser()
    session_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(session_path.parent, 0o700)
    client = TelegramClient(str(session_path), int(config["TELEGRAM_API_ID"]), config["TELEGRAM_API_HASH"])
    await client.connect()
    if not await client.is_user_authorized():
        await client.disconnect()
        raise RuntimeError("Telegram session is not authorized")
    return client


async def run_discover(config: dict[str, str]) -> int:
    client = await telegram_client(config)
    try:
        ttl_seconds = int(config.get("AUTO_DELETE_TTL_SECONDS", "86400"))
        limit = int(config.get("DISCOVERY_LIMIT", "50"))
        matches = await discover_ttl_peers(client, ttl_seconds, limit)
        print(json.dumps(matches, ensure_ascii=False, sort_keys=True, indent=2))
        return 0 if matches else 3
    finally:
        await client.disconnect()


async def run_sync(config: dict[str, str]) -> int:
    archive_db = Path(config.get(
        "ARCHIVE_DB", "~/.local/share/fedora-telegram-autodelete/archive.sqlite3"
    )).expanduser()
    state_dir = Path(config.get(
        "STATE_DIR", "~/.local/share/fedora-telegram-autodelete"
    )).expanduser()
    media_root = Path(config.get(
        "MEDIA_DIR", "~/.local/share/fedora-telegram-autodelete/media"
    )).expanduser()
    horizon_seconds = int(config.get("RECONCILE_HORIZON_SECONDS", "108000"))
    if horizon_seconds < int(config.get("AUTO_DELETE_TTL_SECONDS", "86400")):
        raise ValueError("RECONCILE_HORIZON_SECONDS must cover the auto-delete TTL")

    os.umask(0o077)
    client = await telegram_client(config)
    conn = open_archive(archive_db)
    try:
        entity, peer_id = await resolve_target(client, config, state_dir)
        counts = await reconcile(client, entity, peer_id, conn, media_root, horizon_seconds)
        print(
            "Telegram auto-delete archive sync complete; "
            + " ".join(f"{key}={value}" for key, value in counts.items())
            + f" peer_id={peer_id}."
        )
        return 0
    finally:
        conn.close()
        await client.disconnect()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("discover", "sync"))
    parser.add_argument(
        "--config",
        default="~/.config/fedora-telegram-autodelete/collector.env",
    )
    args = parser.parse_args(argv)
    config_path = Path(args.config).expanduser()
    if not config_path.is_file():
        print("Collector config is missing.", file=sys.stderr)
        return 2
    if config_path.stat().st_mode & 0o077:
        print("Collector config permissions are too broad.", file=sys.stderr)
        return 2
    try:
        config = load_env(config_path)
        if args.command == "discover":
            return asyncio.run(run_discover(config))
        return asyncio.run(run_sync(config))
    except Exception as exc:
        print(
            f"Telegram auto-delete archive failed ({type(exc).__name__}: {exc}).",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
