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


def ensure_columns(
    conn: sqlite3.Connection,
    table: str,
    columns: dict[str, str],
) -> None:
    existing = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, declaration in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")


def human_time_sql(column: str) -> str:
    return f"""CASE
                WHEN date({column}, 'localtime') = date('now', 'localtime')
                    THEN 'oggi ' || CAST(strftime('%H', {column}, 'localtime') AS INTEGER)
                         || ':' || strftime('%M', {column}, 'localtime')
                WHEN date({column}, 'localtime') = date('now', 'localtime', '-1 day')
                    THEN 'ieri ' || CAST(strftime('%H', {column}, 'localtime') AS INTEGER)
                         || ':' || strftime('%M', {column}, 'localtime')
                ELSE
                    CASE strftime('%w', {column}, 'localtime')
                        WHEN '0' THEN 'dom' WHEN '1' THEN 'lun'
                        WHEN '2' THEN 'mar' WHEN '3' THEN 'mer'
                        WHEN '4' THEN 'gio' WHEN '5' THEN 'ven'
                        WHEN '6' THEN 'sab'
                    END || ' '
                    || CAST(strftime('%d', {column}, 'localtime') AS INTEGER) || '/'
                    || CAST(strftime('%m', {column}, 'localtime') AS INTEGER) || '/'
                    || substr(strftime('%Y', {column}, 'localtime'), 3, 2) || ' '
                    || CAST(strftime('%H', {column}, 'localtime') AS INTEGER)
                    || ':' || strftime('%M', {column}, 'localtime')
            END"""


def create_human_view(conn: sqlite3.Connection) -> None:
    message_time = human_time_sql("date_utc")
    event_time = human_time_sql("event_time_utc")
    conn.executescript(
        f"""
        DROP VIEW IF EXISTS chat_human;
        DROP VIEW IF EXISTS relationship_events_human;
        DROP VIEW IF EXISTS messages_human;
        DROP VIEW IF EXISTS _messages_human_rows;

        CREATE VIEW _messages_human_rows AS
        SELECT
            date_utc AS sort_utc,
            {message_time} AS quando,
            COALESCE(
                NULLIF(sender_name, ''),
                (
                    SELECT NULLIF(m2.sender_name, '')
                    FROM messages AS m2
                    WHERE m2.sender_id = messages.sender_id
                      AND m2.sender_name IS NOT NULL
                      AND m2.sender_name <> ''
                    LIMIT 1
                ),
                CASE WHEN sender_id IS NULL THEN 'Sistema' ELSE 'Sconosciuto' END
            ) AS mittente,
            CASE
                WHEN text <> '' THEN text
                WHEN action_text IS NOT NULL AND action_text <> '' THEN action_text
                WHEN media_kind = 'photo' THEN '[Foto]'
                WHEN media_kind = 'document' THEN '[Documento]'
                WHEN media_kind IS NOT NULL THEN '[' || media_kind || ']'
                ELSE '(messaggio senza testo)'
            END AS messaggio,
            CASE
                WHEN media_kind = 'photo' THEN 'foto'
                WHEN media_kind = 'document' THEN 'documento'
                WHEN media_kind IS NOT NULL THEN media_kind
                ELSE ''
            END AS media,
            CASE
                WHEN deleted_at_utc IS NOT NULL THEN 'eliminato da Telegram'
                WHEN edit_date_utc IS NOT NULL THEN 'modificato'
                ELSE ''
            END AS stato
        FROM messages;

        CREATE VIEW messages_human AS
        SELECT quando, mittente, messaggio, media, stato
        FROM _messages_human_rows
        ORDER BY sort_utc DESC;

        CREATE VIEW relationship_events_human AS
        SELECT
            {event_time} AS quando,
            'Sistema' AS mittente,
            summary AS messaggio,
            '' AS media,
            CASE confidence
                WHEN 'certain' THEN 'certo'
                WHEN 'inferred' THEN 'inferito'
                ELSE confidence
            END AS stato
        FROM relationship_events
        ORDER BY event_time_utc DESC;

        CREATE VIEW chat_human AS
        SELECT quando, mittente, messaggio, media, stato
        FROM (
            SELECT sort_utc, quando, mittente, messaggio, media, stato
            FROM _messages_human_rows
            UNION ALL
            SELECT
                event_time_utc AS sort_utc,
                {event_time} AS quando,
                'Sistema' AS mittente,
                summary AS messaggio,
                '' AS media,
                CASE confidence
                    WHEN 'certain' THEN 'certo'
                    WHEN 'inferred' THEN 'inferito'
                    ELSE confidence
                END AS stato
            FROM relationship_events
        )
        ORDER BY sort_utc DESC;
        """
    )


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

        CREATE TABLE IF NOT EXISTS relationship_state (
            peer_id INTEGER PRIMARY KEY,
            peer_name TEXT,
            own_blocked INTEGER NOT NULL,
            peer_status_type TEXT NOT NULL,
            peer_status_label TEXT NOT NULL,
            peer_status_json TEXT NOT NULL,
            observed_at_utc TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS relationship_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_id INTEGER NOT NULL,
            event_time_utc TEXT NOT NULL,
            observed_at_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            confidence TEXT NOT NULL,
            summary TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            UNIQUE(peer_id, event_type, event_time_utc, summary)
        );
        CREATE INDEX IF NOT EXISTS idx_relationship_events_time
            ON relationship_events(peer_id, event_time_utc);
        """
    )
    ensure_columns(
        conn,
        "messages",
        {
            "sender_name": "TEXT",
            "action_type": "TEXT",
            "action_text": "TEXT",
            "action_json": "TEXT",
        },
    )
    ensure_columns(
        conn,
        "revisions",
        {
            "sender_name": "TEXT",
            "action_type": "TEXT",
            "action_text": "TEXT",
            "action_json": "TEXT",
        },
    )
    create_human_view(conn)
    conn.commit()
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


def entity_display_name(entity: Any) -> str | None:
    if entity is None:
        return None
    parts = [
        str(value).strip()
        for value in (
            getattr(entity, "first_name", None),
            getattr(entity, "last_name", None),
        )
        if value and str(value).strip()
    ]
    if parts:
        return " ".join(parts)
    for attr in ("title", "username"):
        value = getattr(entity, attr, None)
        if value and str(value).strip():
            return str(value).strip()
    return None


STATUS_LABELS = {
    "UserStatusOnline": "online",
    "UserStatusOffline": "last_seen_exact",
    "UserStatusRecently": "recently",
    "UserStatusLastWeek": "last_week",
    "UserStatusLastMonth": "last_month",
    "UserStatusEmpty": "long_time_ago",
}


def peer_status_snapshot(status: Any) -> dict[str, Any]:
    status_type = type(status).__name__ if status is not None else "UserStatusEmpty"
    payload = (
        status.to_dict()
        if status is not None and hasattr(status, "to_dict")
        else {"_": status_type}
    )
    was_online = getattr(status, "was_online", None) if status is not None else None
    return {
        "type": status_type,
        "label": STATUS_LABELS.get(status_type, status_type),
        "long_time_ago": status_type == "UserStatusEmpty",
        "was_online_utc": iso_utc(was_online) if was_online is not None else None,
        "raw": payload,
    }


def status_was_recent(snapshot: dict[str, Any], observed_at_utc: str) -> bool:
    status_type = snapshot.get("type")
    if status_type in {"UserStatusOnline", "UserStatusRecently"}:
        return True
    if status_type != "UserStatusOffline" or not snapshot.get("was_online_utc"):
        return False
    try:
        age = parse_iso(observed_at_utc) - parse_iso(str(snapshot["was_online_utc"]))
    except (TypeError, ValueError):
        return False
    return dt.timedelta(0) <= age <= dt.timedelta(days=3)


def insert_relationship_event(
    conn: sqlite3.Connection,
    *,
    peer_id: int,
    event_time_utc: str,
    observed_at_utc: str,
    event_type: str,
    confidence: str,
    summary: str,
    evidence: dict[str, Any],
) -> int:
    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO relationship_events (
            peer_id,event_time_utc,observed_at_utc,event_type,
            confidence,summary,evidence_json
        ) VALUES (?,?,?,?,?,?,?)
        """,
        (
            peer_id,
            event_time_utc,
            observed_at_utc,
            event_type,
            confidence,
            summary,
            json.dumps(evidence, ensure_ascii=False, sort_keys=True, default=str),
        ),
    )
    return max(cursor.rowcount, 0)


def record_relationship_observation(
    conn: sqlite3.Connection,
    *,
    peer_id: int,
    peer_name: str,
    own_blocked: bool,
    own_block_date_utc: str | None,
    peer_status: dict[str, Any],
    observed_at_utc: str,
) -> int:
    previous = conn.execute(
        "SELECT * FROM relationship_state WHERE peer_id=?",
        (peer_id,),
    ).fetchone()
    events = 0

    if previous is None:
        if own_blocked:
            event_time = own_block_date_utc or observed_at_utc
            events += insert_relationship_event(
                conn,
                peer_id=peer_id,
                event_time_utc=event_time,
                observed_at_utc=observed_at_utc,
                event_type="my_block",
                confidence="certain",
                summary=f"Hai bloccato {peer_name}",
                evidence={
                    "blocked": True,
                    "timestamp_source": (
                        "telegram_blocklist_date"
                        if own_block_date_utc
                        else "first_observation"
                    ),
                },
            )
    else:
        previous_blocked = bool(previous["own_blocked"])
        if previous_blocked != own_blocked:
            if own_blocked:
                event_time = own_block_date_utc or observed_at_utc
                event_type = "my_block"
                summary = f"Hai bloccato {peer_name}"
                timestamp_source = (
                    "telegram_blocklist_date"
                    if own_block_date_utc
                    else "observation"
                )
            else:
                event_time = observed_at_utc
                event_type = "my_unblock"
                summary = f"Hai sbloccato {peer_name}"
                timestamp_source = "observation"
            events += insert_relationship_event(
                conn,
                peer_id=peer_id,
                event_time_utc=event_time,
                observed_at_utc=observed_at_utc,
                event_type=event_type,
                confidence="certain",
                summary=summary,
                evidence={
                    "previous_blocked": previous_blocked,
                    "blocked": own_blocked,
                    "timestamp_source": timestamp_source,
                },
            )

        try:
            previous_status = json.loads(str(previous["peer_status_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            previous_status = {
                "type": str(previous["peer_status_type"]),
                "label": str(previous["peer_status_label"]),
                "long_time_ago": str(previous["peer_status_type"]) == "UserStatusEmpty",
            }
        current_long = bool(peer_status.get("long_time_ago"))
        previous_long = bool(previous_status.get("long_time_ago"))
        if not previous_long and current_long and status_was_recent(
            previous_status, str(previous["observed_at_utc"])
        ):
            events += insert_relationship_event(
                conn,
                peer_id=peer_id,
                event_time_utc=observed_at_utc,
                observed_at_utc=observed_at_utc,
                event_type="peer_block_inferred",
                confidence="inferred",
                summary=f"Probabile blocco da {peer_name}",
                evidence={
                    "previous_status": previous_status,
                    "current_status": peer_status,
                    "reason": "recent_visibility_to_long_time_ago",
                },
            )
        elif previous_long and not current_long and status_was_recent(
            peer_status, observed_at_utc
        ):
            events += insert_relationship_event(
                conn,
                peer_id=peer_id,
                event_time_utc=observed_at_utc,
                observed_at_utc=observed_at_utc,
                event_type="peer_unblock_inferred",
                confidence="inferred",
                summary=f"Probabile sblocco da {peer_name}",
                evidence={
                    "previous_status": previous_status,
                    "current_status": peer_status,
                    "reason": "long_time_ago_to_recent_visibility",
                },
            )

    conn.execute(
        """
        INSERT INTO relationship_state (
            peer_id,peer_name,own_blocked,peer_status_type,
            peer_status_label,peer_status_json,observed_at_utc
        ) VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(peer_id) DO UPDATE SET
            peer_name=excluded.peer_name,
            own_blocked=excluded.own_blocked,
            peer_status_type=excluded.peer_status_type,
            peer_status_label=excluded.peer_status_label,
            peer_status_json=excluded.peer_status_json,
            observed_at_utc=excluded.observed_at_utc
        """,
        (
            peer_id,
            peer_name,
            int(own_blocked),
            str(peer_status["type"]),
            str(peer_status["label"]),
            json.dumps(peer_status, ensure_ascii=False, sort_keys=True, default=str),
            observed_at_utc,
        ),
    )
    return events


async def fetch_relationship_observation(
    client: Any,
    entity: Any,
) -> tuple[str, bool, str | None, dict[str, Any]]:
    from telethon.tl import functions

    response = await client(functions.users.GetFullUserRequest(entity))
    full = response.full_user
    user = next(
        (
            item
            for item in response.users
            if getattr(item, "id", None) == getattr(entity, "id", None)
        ),
        entity,
    )
    peer_name = entity_display_name(user) or entity_display_name(entity) or "contatto"
    own_blocked = bool(getattr(full, "blocked", False))
    block_date_utc: str | None = None

    if own_blocked:
        offset = 0
        while True:
            blocked = await client(
                functions.contacts.GetBlockedRequest(offset=offset, limit=100)
            )
            entries = list(getattr(blocked, "blocked", ()) or ())
            match = next(
                (
                    item
                    for item in entries
                    if getattr(getattr(item, "peer_id", None), "user_id", None)
                    == getattr(user, "id", None)
                ),
                None,
            )
            if match is not None:
                block_date_utc = iso_utc(getattr(match, "date", None))
                break
            if not entries or len(entries) < 100:
                break
            offset += len(entries)

    return (
        peer_name,
        own_blocked,
        block_date_utc,
        peer_status_snapshot(getattr(user, "status", None)),
    )


async def observe_relationship_state(
    client: Any,
    entity: Any,
    peer_id: int,
    conn: sqlite3.Connection,
) -> int:
    observed_at = iso_utc(utc_now())
    peer_name, own_blocked, block_date, peer_status = (
        await fetch_relationship_observation(client, entity)
    )
    events = record_relationship_observation(
        conn,
        peer_id=peer_id,
        peer_name=peer_name,
        own_blocked=own_blocked,
        own_block_date_utc=block_date,
        peer_status=peer_status,
        observed_at_utc=observed_at,
    )
    conn.commit()
    return events


async def sender_name_for_message(
    message: Any,
    cache: dict[int, str | None],
) -> str | None:
    sender_id = getattr(message, "sender_id", None)
    if sender_id is None:
        return None
    sender_id = int(sender_id)
    if sender_id in cache:
        return cache[sender_id]
    sender = getattr(message, "sender", None)
    if sender is None:
        getter = getattr(message, "get_sender", None)
        if getter is not None:
            sender = await getter()
    name = entity_display_name(sender)
    cache[sender_id] = name
    return name


def phone_call_text(message: Any, action: Any) -> str:
    reason_name = type(getattr(action, "reason", None)).__name__
    outgoing = bool(getattr(message, "out", False))
    if reason_name == "PhoneCallDiscardReasonMissed":
        label = "Chiamata annullata" if outgoing else "Chiamata persa"
    elif reason_name == "PhoneCallDiscardReasonBusy":
        label = "Chiamata rifiutata" if outgoing else "Chiamata non risposta (occupato)"
    elif reason_name == "PhoneCallDiscardReasonDisconnect":
        label = "Chiamata interrotta"
    elif reason_name == "PhoneCallDiscardReasonHangup":
        label = "Chiamata terminata"
    else:
        label = "Chiamata"
    duration = getattr(action, "duration", None)
    if duration:
        minutes, seconds = divmod(int(duration), 60)
        elapsed = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"
        label += f" · {elapsed}"
    if bool(getattr(action, "video", False)):
        label = label.replace("Chiamata", "Videochiamata", 1)
    return label


def action_details(message: Any) -> tuple[str | None, str | None, str | None]:
    action = getattr(message, "action", None)
    if action is None:
        return None, None, None
    action_type = type(action).__name__
    if action_type == "MessageActionPhoneCall":
        action_text = phone_call_text(message, action)
    else:
        action_text = action_type.removeprefix("MessageAction")
    payload = action.to_dict() if hasattr(action, "to_dict") else {"type": action_type}
    return (
        action_type,
        action_text,
        json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str),
    )


def snapshot_from_message(
    message: Any,
    *,
    sender_name: str | None = None,
) -> dict[str, Any]:
    reply_id = getattr(getattr(message, "reply_to", None), "reply_to_msg_id", None)
    kind, remote_id = media_identity(message)
    sender_id = getattr(message, "sender_id", None)
    action_type, action_text, action_json = action_details(message)
    return {
        "message_id": int(message.id),
        "date_utc": iso_utc(message.date),
        "sender_id": int(sender_id) if sender_id is not None else None,
        "sender_name": sender_name,
        "text": getattr(message, "message", None) or "",
        "edit_date_utc": iso_utc(getattr(message, "edit_date", None)),
        "reply_to_message_id": int(reply_id) if reply_id is not None else None,
        "media_kind": kind,
        "media_remote_id": remote_id,
        "action_type": action_type,
        "action_text": action_text,
        "action_json": action_json,
    }


CONTENT_FIELDS = (
    "sender_name",
    "text",
    "edit_date_utc",
    "reply_to_message_id",
    "media_kind",
    "media_remote_id",
    "media_path",
    "media_sha256",
    "action_type",
    "action_text",
    "action_json",
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
                peer_id,message_id,date_utc,sender_id,sender_name,text,edit_date_utc,
                reply_to_message_id,media_kind,media_remote_id,media_path,media_sha256,
                action_type,action_text,action_json,current_revision,
                first_seen_at_utc,last_seen_at_utc,deleted_at_utc,deletion_reason
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,NULL,NULL)
            """,
            (
                peer_id, message_id, material["date_utc"], material["sender_id"],
                material["sender_name"], material["text"], material["edit_date_utc"],
                material["reply_to_message_id"], material["media_kind"],
                material["media_remote_id"], material["media_path"],
                material["media_sha256"], material["action_type"],
                material["action_text"], material["action_json"], seen_at, seen_at,
            ),
        )
        conn.execute(
            """
            INSERT INTO revisions (
                peer_id,message_id,revision_no,captured_at_utc,sender_name,text,
                edit_date_utc,reply_to_message_id,media_kind,media_remote_id,
                media_path,media_sha256,action_type,action_text,action_json
            ) VALUES (?,?,1,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                peer_id, message_id, seen_at, material["sender_name"], material["text"],
                material["edit_date_utc"], material["reply_to_message_id"],
                material["media_kind"], material["media_remote_id"],
                material["media_path"], material["media_sha256"],
                material["action_type"], material["action_text"], material["action_json"],
            ),
        )
        return "inserted"

    changed = any(current[field] != material[field] for field in CONTENT_FIELDS)
    if changed:
        revision = int(current["current_revision"]) + 1
        conn.execute(
            """
            INSERT INTO revisions (
                peer_id,message_id,revision_no,captured_at_utc,sender_name,text,
                edit_date_utc,reply_to_message_id,media_kind,media_remote_id,
                media_path,media_sha256,action_type,action_text,action_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                peer_id, message_id, revision, seen_at, material["sender_name"],
                material["text"], material["edit_date_utc"],
                material["reply_to_message_id"], material["media_kind"],
                material["media_remote_id"], material["media_path"],
                material["media_sha256"], material["action_type"],
                material["action_text"], material["action_json"],
            ),
        )
        conn.execute(
            """
            UPDATE messages SET
                sender_id=?, sender_name=?, text=?, edit_date_utc=?,
                reply_to_message_id=?, media_kind=?, media_remote_id=?,
                media_path=?, media_sha256=?, action_type=?, action_text=?,
                action_json=?, current_revision=?, last_seen_at_utc=?,
                deleted_at_utc=NULL, deletion_reason=NULL
            WHERE peer_id=? AND message_id=?
            """,
            (
                material["sender_id"], material["sender_name"], material["text"],
                material["edit_date_utc"], material["reply_to_message_id"],
                material["media_kind"], material["media_remote_id"],
                material["media_path"], material["media_sha256"],
                material["action_type"], material["action_text"],
                material["action_json"], revision, seen_at, peer_id, message_id,
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
    sender_cache: dict[int, str | None] = {}
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
        sender_name = await sender_name_for_message(message, sender_cache)
        snapshot = snapshot_from_message(message, sender_name=sender_name)
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
        relationship_events = await observe_relationship_state(
            client, entity, peer_id, conn
        )
        counts = await reconcile(client, entity, peer_id, conn, media_root, horizon_seconds)
        print(
            "Telegram auto-delete archive sync complete; "
            + " ".join(f"{key}={value}" for key, value in counts.items())
            + f" relationship_events={relationship_events} peer_id={peer_id}."
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
