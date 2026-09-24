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


class Message:
    def __init__(
        self,
        message_id,
        text,
        *,
        when=None,
        edit_date=None,
        sender_id=10,
        document=None,
        reply_to_id=None,
    ):
        self.id = message_id
        self.date = when or dt.datetime.now(tz=UTC)
        self.message = text
        self.edit_date = edit_date
        self.sender_id = sender_id
        self.document = document
        self.photo = None
        self.media = document
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


if __name__ == "__main__":
    unittest.main()
