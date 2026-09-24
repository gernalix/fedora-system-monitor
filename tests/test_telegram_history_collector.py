import datetime as dt
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import telegram_history_collector as collector


class Message:
    def __init__(self, message_id, text, *, media=None):
        self.id = message_id
        self.date = dt.datetime(2026, 9, 24, tzinfo=dt.timezone.utc)
        self.message = text
        self.document = None
        self.photo = None
        self.media = media
        self.reply_to = None


class FakeClient:
    def __init__(self, messages):
        self.messages = messages
        self.peer = None

    def get_entity(self, peer):
        self.peer = peer
        return peer

    def iter_messages(self, entity, *, min_id, reverse):
        assert entity == self.peer
        assert reverse is True
        return iter(message for message in self.messages if message.id > min_id)


def git(path, *args):
    return subprocess.run(["git", "-C", str(path), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()


class TelegramHistoryCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.remote = root / "remote.git"
        self.repo = root / "data"
        subprocess.run(["git", "init", "--bare", "--initial-branch=main", str(self.remote)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.repo.mkdir()
        git(self.repo, "init", "--initial-branch=main")
        git(self.repo, "config", "user.name", "fixture")
        git(self.repo, "config", "user.email", "fixture@example.invalid")
        (self.repo / "README.md").write_text("fixture\n")
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-m", "fixture")
        git(self.repo, "remote", "add", "origin", str(self.remote))
        git(self.repo, "push", "-u", "origin", "main")
        self.config = {
            "DATA_REPO": str(self.repo),
            "DATA_REMOTE": str(self.remote),
            "TELEGRAM_CHAT": "target-peer",
            "TELEGRAM_API_HASH": "fixture-secret-never-serialized",
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_incremental_delta_noop_target_scope_and_secret_exclusion(self):
        first = FakeClient([Message(3, "first notification"), Message(4, "second notification")])
        self.assertEqual(collector.sync(self.config, first), 2)
        self.assertEqual(first.peer, "target-peer")
        remote_head = subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"], check=True,
            stdout=subprocess.PIPE, text=True).stdout.strip()
        data_file = self.repo / "archive/messages-2026-09.jsonl"
        initial = data_file.read_text()
        self.assertEqual(len(initial.splitlines()), 2)
        self.assertNotIn("fixture-secret", initial)
        self.assertNotIn("fixture-secret", (self.repo / "archive/latest.md").read_text())

        repeated = FakeClient([Message(3, "first notification"), Message(4, "second notification")])
        self.assertEqual(collector.sync(self.config, repeated), 0)
        current_remote_head = subprocess.run(["git", "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"],
                                            check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
        self.assertEqual(current_remote_head, remote_head)
        self.assertEqual(len(data_file.read_text().splitlines()), 2)

        delta = FakeClient([Message(3, "duplicate"), Message(4, "duplicate"), Message(5, "new notification")])
        self.assertEqual(collector.sync(self.config, delta), 1)
        self.assertEqual(len(data_file.read_text().splitlines()), 3)
        self.assertEqual([3, 4, 5], [json.loads(line)["message_id"] for line in data_file.read_text().splitlines()])
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_network_failure_does_not_advance_cursor(self):
        class BrokenClient(FakeClient):
            def iter_messages(self, entity, *, min_id, reverse):
                raise OSError("network fixture")
        with self.assertRaises(OSError):
            collector.sync(self.config, BrokenClient([]))
        self.assertFalse((self.repo / "archive/state.json").exists())
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_numeric_peer_falls_back_to_dialog_cache(self):
        entity = type("Entity", (), {"id": 4426028673})()
        dialog = type("Dialog", (), {"id": 999, "entity": entity})()

        class DialogClient(FakeClient):
            def get_entity(self, peer):
                self.peer = peer
                raise ValueError("not cached")

            def iter_dialogs(self):
                return iter([dialog])

            def iter_messages(self, resolved, *, min_id, reverse):
                self.asserted_entity = resolved
                return iter(self.messages)

        client = DialogClient([Message(8, "resolved notification")])
        records = collector.collect(client, "-1004426028673", 0)
        self.assertIs(client.asserted_entity, entity)
        self.assertEqual([item["message_id"] for item in records], [8])

    def test_media_metadata_is_text_only(self):
        message = Message(7, "caption")
        message.document = type("Document", (), {"mime_type": "text/plain", "size": 123,
                                                   "attributes": [type("Attribute", (), {"file_name": "note.txt"})()]})()
        record = collector.message_record(message)
        self.assertEqual(record["text"], "caption")
        self.assertEqual(record["media"], {"kind": "document", "mime_type": "text/plain",
                                             "size": 123, "file_name": "note.txt"})
        self.assertNotIn("data", record)

    def test_push_failure_rolls_back_archive_and_cursor(self):
        real_git = collector.git
        def fail_push(repo, *args):
            if args and args[0] == "push":
                raise subprocess.CalledProcessError(1, ["git", "push"])
            return real_git(repo, *args)
        with patch.object(collector, "git", side_effect=fail_push):
            with self.assertRaises(subprocess.CalledProcessError):
                collector.sync(self.config, FakeClient([Message(9, "not published")]))
        self.assertFalse((self.repo / "archive/state.json").exists())
        self.assertFalse((self.repo / "archive/messages-2026-09.jsonl").exists())
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_interrupted_write_is_recovered_before_next_sync(self):
        base = git(self.repo, "rev-parse", "HEAD")
        branch = git(self.repo, "branch", "--show-current")
        marker = collector.write_transaction(self.repo, base, branch)
        archive = self.repo / "archive"
        archive.mkdir()
        (archive / "state.json").write_text('{"last_message_id":99}\n')
        (archive / "messages-2026-09.jsonl").write_text('{"message_id":99')
        collector.recover_transaction(self.repo)
        self.assertFalse(marker.exists())
        self.assertFalse(archive.exists())
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), base)
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")


if __name__ == "__main__":
    unittest.main()
