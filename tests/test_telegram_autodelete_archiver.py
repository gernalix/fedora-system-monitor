import datetime as dt
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import telegram_autodelete_archiver as archiver

UTC = dt.timezone.utc


class Document:
    def __init__(self, document_id=700):
        self.id = document_id


class PhoneCallDiscardReasonMissed:
    pass


class MessageActionPhoneCall:
    def __init__(self, *, duration=None, video=False):
        self.reason = PhoneCallDiscardReasonMissed()
        self.duration = duration
        self.video = video

    def to_dict(self):
        return {
            "_": "MessageActionPhoneCall",
            "reason": {"_": "PhoneCallDiscardReasonMissed"},
            "duration": self.duration,
            "video": self.video,
        }


class Message:
    def __init__(
        self,
        message_id,
        text,
        *,
        when=None,
        edit_date=None,
        sender_id=10,
        sender_name=None,
        document=None,
        reply_to_id=None,
        action=None,
        out=False,
    ):
        self.id = message_id
        self.date = when or dt.datetime.now(tz=UTC)
        self.message = text
        self.edit_date = edit_date
        self.sender_id = sender_id
        self.sender = (
            type("Sender", (), {"first_name": sender_name, "last_name": None})()
            if sender_name is not None
            else None
        )
        self.document = document
        self.photo = None
        self.media = document
        self.action = action
        self.out = out
        self.reply_to = (
            type("Reply", (), {"reply_to_msg_id": reply_to_id})()
            if reply_to_id is not None
            else None
        )


class FakeClient:
    def __init__(self, messages, media_bytes=b"fixture-media"):
        self.messages = list(messages)
        self.media_bytes = media_bytes
        self.download_count = 0

    def iter_messages(self, entity):
        async def generate():
            for message in self.messages:
                yield message
        return generate()

    async def download_media(self, message, file):
        self.download_count += 1
        target = Path(file)
        target.mkdir(parents=True, exist_ok=True)
        output = target / f"{message.id}.bin"
        output.write_bytes(self.media_bytes)
        return str(output)


class TelegramAutodeleteArchiveTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "archive.sqlite3"
        self.media_root = self.root / "media"
        self.conn = archiver.open_archive(self.db_path)
        self.peer_id = -1001234567890

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def row(self, message_id):
        return self.conn.execute(
            "SELECT * FROM messages WHERE peer_id=? AND message_id=?",
            (self.peer_id, message_id),
        ).fetchone()

    def revisions(self, message_id):
        return self.conn.execute(
            """
            SELECT * FROM revisions
            WHERE peer_id=? AND message_id=?
            ORDER BY revision_no
            """,
            (self.peer_id, message_id),
        ).fetchall()

    async def test_incremental_sync_is_duplicate_free(self):
        now = dt.datetime.now(tz=UTC)
        client = FakeClient([
            Message(2, "second", when=now),
            Message(1, "first", when=now - dt.timedelta(minutes=1)),
        ])
        first = await archiver.reconcile(
            client, object(), self.peer_id, self.conn, self.media_root, 108000
        )
        self.assertEqual(first["inserted"], 2)
        self.assertEqual(first["updated"], 0)
        self.assertEqual(
            self.conn.execute("SELECT count(*) FROM messages").fetchone()[0], 2
        )

        second = await archiver.reconcile(
            client, object(), self.peer_id, self.conn, self.media_root, 108000
        )
        self.assertEqual(second["inserted"], 0)
        self.assertEqual(second["updated"], 0)
        self.assertEqual(second["unchanged"], 2)
        self.assertEqual(
            self.conn.execute("SELECT count(*) FROM messages").fetchone()[0], 2
        )
        self.assertEqual(len(self.revisions(1)), 1)
        self.assertEqual(len(self.revisions(2)), 1)

    async def test_edit_updates_current_and_preserves_revisions(self):
        now = dt.datetime.now(tz=UTC)
        original = Message(11, "before", when=now)
        await archiver.reconcile(
            FakeClient([original]), object(), self.peer_id, self.conn, self.media_root, 108000
        )

        edited = Message(
            11,
            "after",
            when=now,
            edit_date=now + dt.timedelta(minutes=2),
        )
        result = await archiver.reconcile(
            FakeClient([edited]), object(), self.peer_id, self.conn, self.media_root, 108000
        )
        self.assertEqual(result["updated"], 1)
        row = self.row(11)
        self.assertEqual(row["text"], "after")
        self.assertEqual(row["current_revision"], 2)
        revisions = self.revisions(11)
        self.assertEqual([item["text"] for item in revisions], ["before", "after"])

    async def test_missing_message_gets_tombstone_without_content_loss(self):
        now = dt.datetime.now(tz=UTC)
        message = Message(21, "must survive delete", when=now)
        await archiver.reconcile(
            FakeClient([message]), object(), self.peer_id, self.conn, self.media_root, 108000
        )
        result = await archiver.reconcile(
            FakeClient([]), object(), self.peer_id, self.conn, self.media_root, 108000
        )
        self.assertEqual(result["deleted"], 1)
        row = self.row(21)
        self.assertEqual(row["text"], "must survive delete")
        self.assertIsNotNone(row["deleted_at_utc"])
        self.assertEqual(row["deletion_reason"], "remote_missing")
        self.assertEqual(len(self.revisions(21)), 1)

    async def test_reappearing_message_clears_tombstone(self):
        now = dt.datetime.now(tz=UTC)
        message = Message(22, "temporary gap", when=now)
        await archiver.reconcile(
            FakeClient([message]), object(), self.peer_id, self.conn, self.media_root, 108000
        )
        await archiver.reconcile(
            FakeClient([]), object(), self.peer_id, self.conn, self.media_root, 108000
        )
        self.assertIsNotNone(self.row(22)["deleted_at_utc"])
        await archiver.reconcile(
            FakeClient([message]), object(), self.peer_id, self.conn, self.media_root, 108000
        )
        self.assertIsNone(self.row(22)["deleted_at_utc"])

    async def test_media_is_downloaded_once_and_retained_after_delete(self):
        now = dt.datetime.now(tz=UTC)
        message = Message(31, "attachment", when=now, document=Document(900))
        client = FakeClient([message])
        await archiver.reconcile(
            client, object(), self.peer_id, self.conn, self.media_root, 108000
        )
        row = self.row(31)
        media_path = Path(row["media_path"])
        self.assertTrue(media_path.is_file())
        self.assertEqual(client.download_count, 1)
        first_hash = row["media_sha256"]

        await archiver.reconcile(
            client, object(), self.peer_id, self.conn, self.media_root, 108000
        )
        self.assertEqual(client.download_count, 1)
        self.assertEqual(self.row(31)["media_sha256"], first_hash)

        await archiver.reconcile(
            FakeClient([]), object(), self.peer_id, self.conn, self.media_root, 108000
        )
        self.assertTrue(media_path.is_file())
        self.assertIsNotNone(self.row(31)["deleted_at_utc"])

    async def test_old_messages_outside_reconcile_window_are_not_false_deleted(self):
        now = dt.datetime.now(tz=UTC)
        old = Message(41, "legacy", when=now - dt.timedelta(days=3))
        snapshot = archiver.snapshot_from_message(old)
        archiver.store_snapshot(
            self.conn,
            self.peer_id,
            snapshot,
            archiver.iso_utc(now - dt.timedelta(days=3)),
            None,
            None,
        )
        self.conn.commit()

        result = await archiver.reconcile(
            FakeClient([]), object(), self.peer_id, self.conn, self.media_root, 108000
        )
        self.assertEqual(result["deleted"], 0)
        self.assertIsNone(self.row(41)["deleted_at_utc"])

    async def test_first_sync_backfills_visible_history_beyond_window(self):
        now = dt.datetime.now(tz=UTC)
        old = Message(51, "pre-auto-delete legacy", when=now - dt.timedelta(days=10))
        recent = Message(52, "recent", when=now)
        result = await archiver.reconcile(
            FakeClient([recent, old]),
            object(),
            self.peer_id,
            self.conn,
            self.media_root,
            108000,
        )
        self.assertEqual(result["inserted"], 2)
        self.assertEqual(self.row(51)["text"], "pre-auto-delete legacy")
        self.assertEqual(self.row(52)["text"], "recent")

    async def test_phone_call_and_sender_are_human_readable(self):
        now = dt.datetime.now(tz=UTC)
        call = Message(
            61,
            "",
            when=now,
            sender_id=58037506,
            sender_name="Daniele",
            action=MessageActionPhoneCall(),
            out=True,
        )
        result = await archiver.reconcile(
            FakeClient([call]), object(), self.peer_id, self.conn, self.media_root, 108000
        )
        self.assertEqual(result["inserted"], 1)
        raw = self.row(61)
        self.assertEqual(raw["sender_name"], "Daniele")
        self.assertEqual(raw["action_type"], "MessageActionPhoneCall")
        self.assertEqual(raw["action_text"], "Chiamata annullata")
        self.assertIn("PhoneCallDiscardReasonMissed", raw["action_json"])

        cursor = self.conn.execute(
            "SELECT * FROM messages_human WHERE mittente='Daniele'"
        )
        columns = [item[0] for item in cursor.description]
        self.assertEqual(columns, ["quando", "mittente", "messaggio", "media", "stato"])
        human = cursor.fetchone()
        self.assertTrue(human["quando"].startswith("oggi "))
        self.assertEqual(human["mittente"], "Daniele")
        self.assertEqual(human["messaggio"], "Chiamata annullata")

        legacy = Message(62, "legacy sender fallback", when=now, sender_id=58037506)
        snapshot = archiver.snapshot_from_message(legacy, sender_name=None)
        archiver.store_snapshot(
            self.conn,
            self.peer_id,
            snapshot,
            archiver.iso_utc(now),
            None,
            None,
        )
        self.conn.commit()
        legacy_human = self.conn.execute(
            "SELECT * FROM messages_human WHERE messaggio='legacy sender fallback'"
        ).fetchone()
        self.assertEqual(legacy_human["mittente"], "Daniele")

    def test_relationship_events_are_deduped_and_interleaved(self):
        recent = {
            "type": "UserStatusRecently",
            "label": "recently",
            "long_time_ago": False,
            "was_online_utc": None,
            "raw": {"_": "UserStatusRecently"},
        }
        long_ago = {
            "type": "UserStatusEmpty",
            "label": "long_time_ago",
            "long_time_ago": True,
            "was_online_utc": None,
            "raw": {"_": "UserStatusEmpty"},
        }
        self.assertEqual(
            archiver.record_relationship_observation(
                self.conn,
                peer_id=self.peer_id,
                peer_name="Carlo",
                own_blocked=False,
                own_block_date_utc=None,
                peer_status=recent,
                observed_at_utc="2026-09-24T14:00:00Z",
            ),
            0,
        )
        self.assertEqual(
            archiver.record_relationship_observation(
                self.conn,
                peer_id=self.peer_id,
                peer_name="Carlo",
                own_blocked=False,
                own_block_date_utc=None,
                peer_status=long_ago,
                observed_at_utc="2026-09-24T14:05:00Z",
            ),
            1,
        )
        row = self.conn.execute(
            "SELECT * FROM relationship_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(row["event_type"], "peer_block_inferred")
        self.assertEqual(row["confidence"], "inferred")
        self.assertIn("Probabile blocco da Carlo", row["summary"])

        self.assertEqual(
            archiver.record_relationship_observation(
                self.conn,
                peer_id=self.peer_id,
                peer_name="Carlo",
                own_blocked=False,
                own_block_date_utc=None,
                peer_status=recent,
                observed_at_utc="2026-09-24T14:10:00Z",
            ),
            1,
        )
        row = self.conn.execute(
            "SELECT * FROM relationship_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(row["event_type"], "peer_unblock_inferred")

        self.assertEqual(
            archiver.record_relationship_observation(
                self.conn,
                peer_id=self.peer_id,
                peer_name="Carlo",
                own_blocked=True,
                own_block_date_utc="2026-09-24T14:12:34Z",
                peer_status=recent,
                observed_at_utc="2026-09-24T14:15:00Z",
            ),
            1,
        )
        row = self.conn.execute(
            "SELECT * FROM relationship_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(row["event_type"], "my_block")
        self.assertEqual(row["confidence"], "certain")
        self.assertEqual(row["event_time_utc"], "2026-09-24T14:12:34Z")

        self.assertEqual(
            archiver.record_relationship_observation(
                self.conn,
                peer_id=self.peer_id,
                peer_name="Carlo",
                own_blocked=False,
                own_block_date_utc=None,
                peer_status=recent,
                observed_at_utc="2026-09-24T14:20:00Z",
            ),
            1,
        )
        human = self.conn.execute(
            "SELECT * FROM chat_human WHERE messaggio LIKE 'Hai sbloccato%'"
        ).fetchone()
        self.assertIsNotNone(human)
        self.assertEqual(human["mittente"], "Sistema")
        self.assertEqual(human["stato"], "certo")

    def test_initial_current_block_uses_server_date_without_false_peer_history(self):
        long_ago = {
            "type": "UserStatusEmpty",
            "label": "long_time_ago",
            "long_time_ago": True,
            "was_online_utc": None,
            "raw": {"_": "UserStatusEmpty"},
        }
        events = archiver.record_relationship_observation(
            self.conn,
            peer_id=self.peer_id,
            peer_name="Carlo",
            own_blocked=True,
            own_block_date_utc="2026-09-24T12:34:56Z",
            peer_status=long_ago,
            observed_at_utc="2026-09-24T14:00:00Z",
        )
        self.assertEqual(events, 1)
        rows = self.conn.execute(
            "SELECT event_type,event_time_utc,confidence FROM relationship_events"
        ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_type"], "my_block")
        self.assertEqual(rows[0]["event_time_utc"], "2026-09-24T12:34:56Z")
        self.assertEqual(rows[0]["confidence"], "certain")


if __name__ == "__main__":
    unittest.main()
