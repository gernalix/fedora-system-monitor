import asyncio
import datetime as dt
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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
        file.write(self.media_bytes)
        return file


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
        self.assertEqual(row["deletion_reason"], "manual_before_ttl")
        self.assertEqual(row["deletion_confidence"], "timing_inference")
        self.assertEqual(row["deletion_actor"], "unknown")
        self.assertEqual(len(self.revisions(21)), 1)

    def test_missing_after_ttl_is_classified_as_timer(self):
        message_time = dt.datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
        deleted_time = message_time + dt.timedelta(hours=24, seconds=5)
        message = Message(23, "expires by ttl", when=message_time)
        snapshot = archiver.snapshot_from_message(message)
        archiver.store_snapshot(
            self.conn,
            self.peer_id,
            snapshot,
            archiver.iso_utc(message_time),
            None,
            None,
        )
        self.conn.commit()
        changed = archiver.mark_message_deleted(
            self.conn,
            self.peer_id,
            23,
            archiver.iso_utc(deleted_time),
            86400,
        )
        self.assertTrue(changed)
        row = self.row(23)
        self.assertEqual(row["deletion_reason"], "auto_delete_timer")
        self.assertEqual(row["deletion_actor"], "telegram_timer")
        self.assertGreaterEqual(row["deletion_age_seconds"], 86400)

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

    async def test_chunk_larger_than_cap_is_never_written_and_metadata_survives(self):
        message = Message(401, "keep text", document=Document(401))
        # Advertised size can lie; the sink is the authority.
        message.document.size = 1
        client = FakeClient([message], media_bytes=b"x" * 9)
        policy = archiver.MediaPolicy(8, 100, 1)
        await archiver.reconcile(client, object(), self.peer_id, self.conn, self.media_root, 108000, media_policy=policy)
        self.assertEqual(self.row(401)["text"], "keep text")
        self.assertIsNone(self.row(401)["media_path"])
        self.assertEqual(client.download_count, 1)
        self.assertEqual(list(self.media_root.rglob(".partial-*")), [])
        self.assertEqual(list(self.media_root.rglob("attachment*")), [])

    async def test_cumulative_archive_quota_counts_historical_files(self):
        self.media_root.mkdir()
        historical = self.media_root / "retained.bin"
        historical.write_bytes(b"old!")
        message = Message(402, "keep metadata", document=Document(402))
        client = FakeClient([message], media_bytes=b"1234567")
        await archiver.ingest_message(client, self.conn, self.media_root, self.peer_id, message, archiver.MediaPolicy(100, 10, 1))
        self.assertIsNone(self.row(402)["media_path"])
        self.assertEqual(historical.read_bytes(), b"old!")
        self.assertEqual(list(self.media_root.rglob(".partial-*")), [])

    async def test_reserve_is_rechecked_before_each_write(self):
        message = Message(403, "text", document=Document(403))
        class Client:
            async def download_media(self, message, file):
                file.write(b"abc")
                file.write(b"def")
                return file
        free = [100, 100, 11]  # initial check, first write, second write
        with patch.object(archiver.shutil, "disk_usage", side_effect=lambda root: SimpleNamespace(free=free.pop(0))):
            await archiver.ingest_message(Client(), self.conn, self.media_root, self.peer_id, message, archiver.MediaPolicy(100, 100, 10))
        self.assertIsNone(self.row(403)["media_path"])
        self.assertFalse(list(self.media_root.rglob(".partial-*")))

    async def test_error_and_cancellation_remove_partial_download(self):
        message = Message(404, "text", document=Document(404))
        for failure in (OSError("fixture"), asyncio.CancelledError()):
            class Client:
                async def download_media(self, message, file):
                    file.write(b"partial")
                    raise failure
            if isinstance(failure, asyncio.CancelledError):
                with self.assertRaises(asyncio.CancelledError):
                    await archiver.preserve_media(Client(), message, self.media_root, self.peer_id, None)
            else:
                self.assertEqual(await archiver.preserve_media(Client(), message, self.media_root, self.peer_id, None), (None, None))
            self.assertFalse(list(self.media_root.rglob(".partial-*")))
            self.assertFalse(list(self.media_root.rglob("attachment*")))
        # Cancellation releases the inter-process quota lock too.
        self.assertIsNotNone((await archiver.preserve_media(FakeClient([message]), message, self.media_root, self.peer_id, None))[0])

    async def test_advertised_size_precheck_avoids_download(self):
        message = Message(405, "text", document=Document(405))
        message.document.size = 101
        client = FakeClient([message])
        self.assertEqual(await archiver.preserve_media(client, message, self.media_root, self.peer_id, None, archiver.MediaPolicy(100, 1000, 1)), (None, None))
        self.assertEqual(client.download_count, 0)

    async def test_edit_rejection_preserves_new_text_and_prior_revision_media(self):
        original = Message(406, "before", document=Document(406))
        await archiver.ingest_message(FakeClient([original]), self.conn, self.media_root, self.peer_id, original)
        retained = Path(self.row(406)["media_path"])
        edit = Message(406, "after", document=Document(407))
        await archiver.ingest_message(FakeClient([edit], media_bytes=b"too large"), self.conn, self.media_root, self.peer_id, edit, archiver.MediaPolicy(1, 1000, 1))
        self.assertEqual(self.row(406)["text"], "after")
        self.assertIsNone(self.row(406)["media_path"])
        self.assertTrue(retained.is_file())
        self.assertEqual(self.conn.execute("SELECT media_path FROM revisions WHERE message_id=406 AND revision_no=1").fetchone()[0], str(retained))

    async def test_success_publishes_complete_private_file_and_hash_atomically(self):
        message = Message(408, "text", document=Document(408))
        payload = b"complete media"
        class Client:
            async def download_media(self, message, file):
                self_outer.assertFalse(list(self_outer.media_root.rglob("attachment*")))
                file.write(payload[:4])
                self_outer.assertFalse(list(self_outer.media_root.rglob("attachment*")))
                file.write(payload[4:])
                return file
        self_outer = self
        path, digest = await archiver.preserve_media(Client(), message, self.media_root, self.peer_id, None)
        self.assertEqual(Path(path).read_bytes(), payload)
        self.assertEqual(digest, archiver.hashlib.sha256(payload).hexdigest())
        self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.media_root.rglob(".partial-*")))

    async def test_many_small_attachments_exhaust_total_quota(self):
        messages = [Message(i, "text", document=Document(i)) for i in range(410, 414)]
        await archiver.reconcile(FakeClient(messages, media_bytes=b"abc"), object(), self.peer_id, self.conn, self.media_root, 108000, media_policy=archiver.MediaPolicy(4, 10, 1))
        self.assertEqual(sum(self.row(i)["media_path"] is not None for i in range(410, 414)), 3)
        self.assertEqual(sum(path.stat().st_size for path in self.media_root.rglob("*") if path.is_file()), 9)
        self.assertTrue(all(self.row(i)["text"] == "text" for i in range(410, 414)))

    async def test_tiny_media_reaches_entry_cap_without_growing_empty_directories(self):
        messages = [Message(i, "keep", document=Document(i)) for i in range(420, 430)]
        policy = archiver.MediaPolicy(100, 10000, 1, max_entries=9)
        await archiver.reconcile(FakeClient(messages, media_bytes=b"x"), object(), self.peer_id, self.conn, self.media_root, 108000, media_policy=policy)
        self.assertEqual(sum(self.row(i)["media_path"] is not None for i in range(420, 430)), 2)
        self.assertEqual(len(list(self.media_root.rglob("*"))), 8)
        self.assertEqual(len(list(self.media_root.rglob("attachment*"))), 2)
        self.assertFalse(any(path.is_dir() and not any(path.iterdir()) for path in self.media_root.rglob("*")))
        self.assertTrue(all(self.row(i)["text"] == "keep" for i in range(420, 430)))

    async def test_empty_failed_and_cancelled_downloads_only_remove_new_empty_directories(self):
        existing = self.media_root / str(self.peer_id) / "preexisting-empty"
        existing.mkdir(parents=True)
        retained = self.media_root / "historical.bin"
        retained.write_bytes(b"history")
        baseline = set(self.media_root.rglob("*"))
        baseline.add(self.media_root / ".media-quota.lock")
        for mode in ("empty", "error", "cancel", "oversized"):
            message = Message(440, "keep", document=Document(440))
            class Client:
                async def download_media(self, message, file):
                    if mode == "empty":
                        return file
                    file.write(b"part")
                    if mode == "cancel":
                        raise asyncio.CancelledError()
                    if mode == "error":
                        raise OSError("fixture")
                    file.write(b"oversized")
                    return file
            policy = archiver.MediaPolicy(5, 10000, 1)
            if mode == "cancel":
                with self.assertRaises(asyncio.CancelledError):
                    await archiver.preserve_media(Client(), message, self.media_root, self.peer_id, None, policy)
            else:
                self.assertEqual(await archiver.preserve_media(Client(), message, self.media_root, self.peer_id, None, policy), (None, None))
            self.assertEqual(set(self.media_root.rglob("*")), baseline)
            self.assertEqual(retained.read_bytes(), b"history")
            self.assertTrue(existing.is_dir())

    async def test_inode_reserve_is_enforced_before_directory_and_temporary_file_creation(self):
        self.media_root.mkdir()
        (self.media_root / ".media-quota.lock").touch()
        for available in (0, 1, 2, 3):
            # Each allocation consumes an inode. These cases fail at each of
            # peer/message/remote directory and temp creation respectively.
            def usage(root):
                allocated = len(list(self.media_root.rglob("*"))) - 1
                return SimpleNamespace(f_files=100, f_favail=10 + available - allocated, f_ffree=10 + available - allocated)
            message = Message(441, "keep", document=Document(441))
            client = FakeClient([message], media_bytes=b"x")
            with patch.object(archiver.os, "statvfs", side_effect=usage), patch.object(archiver.shutil, "disk_usage", return_value=SimpleNamespace(free=10**9)):
                self.assertEqual(await archiver.preserve_media(client, message, self.media_root, self.peer_id, None, archiver.MediaPolicy(100, 10000, 1, min_free_inodes=10)), (None, None))
            self.assertEqual(client.download_count, 0)
            self.assertEqual(list(self.media_root.rglob("*")), [self.media_root / ".media-quota.lock"])

    async def test_inode_reserve_is_rechecked_on_every_stream_write(self):
        available = 100
        def usage(root):
            return SimpleNamespace(f_files=1000, f_favail=available, f_ffree=available)
        class Client:
            async def download_media(self, message, file):
                nonlocal available
                file.write(b"first")
                available = 9
                file.write(b"second")
                return file
        message = Message(442, "keep", document=Document(442))
        with patch.object(archiver.os, "statvfs", side_effect=usage), patch.object(archiver.shutil, "disk_usage", return_value=SimpleNamespace(free=10**9)):
            await archiver.ingest_message(Client(), self.conn, self.media_root, self.peer_id, message, archiver.MediaPolicy(100, 10000, 1, min_free_inodes=10))
        self.assertIsNone(self.row(442)["media_path"])
        self.assertEqual(self.row(442)["text"], "keep")
        self.assertEqual(list(self.media_root.rglob("*")), [self.media_root / ".media-quota.lock"])

    async def test_filesystems_without_inode_totals_still_use_entry_budget(self):
        messages = [Message(i, "keep", document=Document(i)) for i in range(450, 453)]
        with patch.object(archiver.os, "statvfs", return_value=SimpleNamespace(f_files=0, f_favail=0, f_ffree=0)), patch.object(archiver.shutil, "disk_usage", return_value=SimpleNamespace(free=10**9)):
            await archiver.reconcile(FakeClient(messages, media_bytes=b"x"), object(), self.peer_id, self.conn, self.media_root, 108000, media_policy=archiver.MediaPolicy(100, 10000, 1, max_entries=5))
        self.assertEqual(sum(self.row(i)["media_path"] is not None for i in range(450, 453)), 1)
        self.assertEqual(len(list(self.media_root.rglob("*"))), 5)

    async def test_short_write_aborts_download_instead_of_publishing_truncation(self):
        class ShortStream:
            name = "fixture"
            def write(self, data):
                return len(data) - 1
        sink = archiver._BoundedMediaSink(ShortStream(), self.root, archiver.MediaPolicy(100, 100, 1), 0)
        with self.assertRaises(OSError):
            sink.write(b"abcdef")

    async def test_nonpositive_policy_is_rejected(self):
        for config in ({"MEDIA_MAX_FILE_BYTES": "0"}, {"MEDIA_MAX_ARCHIVE_BYTES": "-1"}, {"MEDIA_MIN_FREE_BYTES": "bad"}, {"MEDIA_MAX_ENTRIES": "0"}, {"MEDIA_MIN_FREE_INODES": "-1"}):
            with self.assertRaises(ValueError):
                archiver.MediaPolicy.from_config(config)

    async def test_real_telethon_filelike_download_methods_offline(self):
        try:
            from telethon.client.downloads import DownloadMethods
            from telethon.tl import types
        except ImportError:
            self.skipTest("Telethon optional: run with the installed archiver venv for integration coverage")
        class OfflineDownloads(DownloadMethods):
            def _iter_download(self, *args, **kwargs):
                async def chunks():
                    yield b"abc"
                    yield b"def"
                return chunks()
        target = self.root / "telethon.bin"
        policy = archiver.MediaPolicy(5, 100, 1)
        with target.open("wb", buffering=0) as stream:
            sink = archiver._BoundedMediaSink(stream, self.root, policy, 0)
            with self.assertRaises(archiver.MediaLimitExceeded):
                await OfflineDownloads()._download_file(object(), file=sink)
        self.assertEqual(target.read_bytes(), b"abc")
        with target.open("wb", buffering=0) as stream:
            sink = archiver._BoundedMediaSink(stream, self.root, archiver.MediaPolicy(100, 100, 1), 0)
            await OfflineDownloads()._download_file(object(), file=sink)
        self.assertEqual(target.read_bytes(), b"abcdef")
        with target.open("wb", buffering=0) as stream:
            sink = archiver._BoundedMediaSink(stream, self.root, policy, 0)
            with self.assertRaises(archiver.MediaLimitExceeded):
                OfflineDownloads()._download_cached_photo_size(types.PhotoCachedSize("x", 1, 1, b"oversize"), sink)
        self.assertEqual(target.read_bytes(), b"")

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
