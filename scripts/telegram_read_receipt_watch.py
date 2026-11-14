#!/usr/bin/env python3
"""One-shot Telegram outbox read receipt watch. No incoming message reads."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

STATE_DIR = Path.home() / ".local/state/telegram-read-receipt-watch"
TIMER = "telegram-read-receipt-watch.timer"


def read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError("Invalid monitor state")
    return result


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                     prefix=".receipt-", delete=False) as handle:
        pending = Path(handle.name)
        os.chmod(pending, 0o600)
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(pending, path)


def was_read(max_id: int, message_id: int) -> bool:
    """Server outbox threshold includes every outgoing message up to max_id."""
    return int(max_id) >= int(message_id)


def read_max_outbox(peer_id: int, owner_id: int) -> int:
    from telethon.sync import TelegramClient
    from telethon.tl import functions, types

    api_id = os.environ["TELEGRAM_API_ID"]
    api_hash = os.environ["TELEGRAM_API_HASH"]
    if not api_id.isdecimal() or not api_hash:
        raise ValueError("Telegram API credentials missing")
    session = str(Path.home() / ".local/share/fedora-telegram-history/account")
    with TelegramClient(session, int(api_id), api_hash,
                        receive_updates=False, catch_up=False,
                        flood_sleep_threshold=0, request_retries=1,
                        connection_retries=1, timeout=15) as client:
        if not client.is_user_authorized():
            raise RuntimeError("Telegram user session unauthorized")
        if client.get_me().id != owner_id:
            raise RuntimeError("Telegram account differs from notification recipient")
        peer = client.get_input_entity(peer_id)
        result = client(functions.messages.GetPeerDialogsRequest(
            peers=[types.InputDialogPeer(peer=peer)]))
        if len(result.dialogs) != 1:
            raise RuntimeError("Telegram dialog not found")
        return int(result.dialogs[0].read_outbox_max_id)


def notify_bot(owner_id: int, content: str) -> int:
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    if not token or "/" in token or any(c.isspace() for c in token):
        raise ValueError("Telegram bot credentials unavailable")
    request = urllib.request.Request(
        "https://api.telegram.org/bot" + token + "/sendMessage",
        data=json.dumps({
            "chat_id": owner_id,
            "text": content,
            "disable_notification": False,
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.load(response)
    if (result.get("ok") is not True
            or int(result.get("result", {}).get("chat", {}).get("id", 0)) != owner_id):
        raise RuntimeError("Telegram notification not confirmed")
    return int(result["result"]["message_id"])


def disable_timer() -> None:
    subprocess.run(["/usr/bin/systemctl", "--user", "disable", "--now", TIMER],
                   check=True, timeout=15, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def run() -> int:
    target = read_json(STATE_DIR / "target.json")
    if target is None:
        raise RuntimeError("Missing verified target message")
    peer_id = int(target["peer_id"])
    message_id = int(target["message_id"])
    if peer_id <= 0 or message_id <= 0:
        raise ValueError("Invalid Telegram target")
    owner = os.environ["TELEGRAM_INSERT_BOT_ALLOWED_USER_ID"]
    if not owner.isdecimal() or int(owner) <= 0:
        raise ValueError("Invalid authorized Telegram notification recipient")
    owner_id = int(owner)
    label = target["label"]
    sent_at = target["sent_at_local"]
    if (not isinstance(label, str) or not label or len(label) > 80
            or not isinstance(sent_at, str) or not sent_at or len(sent_at) > 80):
        raise ValueError("Invalid target display metadata")
    receipt_file = STATE_DIR / "delivery.json"
    receipt = read_json(receipt_file)
    if receipt is not None:
        if receipt.get("message_id") != message_id or receipt.get("peer_id") != peer_id:
            raise RuntimeError("Receipt belongs to another message")
        if receipt.get("status") == "sent":
            disable_timer()
            print("status=sent timer=disabled")
            return 0
        raise RuntimeError("Previous Telegram delivery outcome uncertain; not resending")

    max_id = read_max_outbox(peer_id, owner_id)
    if not was_read(max_id, message_id):
        print(f"status=waiting read_outbox_max_id={max_id} target_id={message_id}")
        return 0

    # Persist before the network request: an ambiguous timeout must never
    # automatically generate a second notification.
    atomic_json(receipt_file, {
        "peer_id": peer_id, "message_id": message_id, "status": "in_flight",
        "attempt_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    })
    text = (f"Conferma di lettura Telegram: {label} ha letto il tuo "
            f"messaggio inviato il {sent_at} (ID {message_id}).")
    delivered_id = notify_bot(owner_id, text)
    atomic_json(receipt_file, {
        "peer_id": peer_id, "message_id": message_id, "status": "sent",
        "notification_id": delivered_id,
        "confirmed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    })
    print(f"status=sent message_id={message_id} notification_id={delivered_id}")
    disable_timer()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(run())
    except Exception as exc:
        # Provider exceptions can contain a credential-bearing URL. Never log them.
        print("telegram_read_receipt_watch error_type=" + type(exc).__name__,
              file=sys.stderr)
        sys.exit(1)
