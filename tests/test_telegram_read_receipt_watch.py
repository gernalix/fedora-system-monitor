"""Offline tests for Telegram read receipt watcher (no live messages)."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import telegram_read_receipt_watch as watch

TARGET = {"peer_id": 77, "message_id": 101, "label": "Test contact",
          "sent_at_local": "14 novembre, 08:02"}
OWNER = {"TELEGRAM_INSERT_BOT_ALLOWED_USER_ID": "17"}


class ReadReceiptWatchTests(unittest.TestCase):
    def test_threshold(self):
        self.assertFalse(watch.was_read(99, 101))
        self.assertFalse(watch.was_read(100, 101))
        self.assertTrue(watch.was_read(101, 101))
        self.assertTrue(watch.was_read(102, 101))

    def test_state_round_trip_and_permissions(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "delivery.json"
            watch.atomic_json(path, {"peer_id": 77, "message_id": 101, "status": "sent"})
            self.assertEqual(watch.read_json(path)["status"], "sent")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_waiting_does_not_send(self):
        with (tempfile.TemporaryDirectory() as root,
              patch.object(watch, "STATE_DIR", Path(root)),
              patch.object(watch, "read_max_outbox", return_value=100),
              patch.object(watch, "notify_bot") as notify,
              patch.dict("os.environ", OWNER)):
            (Path(root) / "target.json").write_text(json.dumps(TARGET))
            self.assertEqual(watch.run(), 0)
            notify.assert_not_called()
            self.assertFalse((Path(root) / "delivery.json").exists())

    def test_preexisting_inflight_fails_closed(self):
        with (tempfile.TemporaryDirectory() as root,
              patch.object(watch, "STATE_DIR", Path(root)),
              patch.object(watch, "notify_bot") as notify,
              patch.dict("os.environ", OWNER)):
            (Path(root) / "target.json").write_text(json.dumps(TARGET))
            (Path(root) / "delivery.json").write_text(
                json.dumps({"peer_id": 77, "message_id": 101, "status": "in_flight"}))
            with self.assertRaisesRegex(RuntimeError, "uncertain"):
                watch.run()
            notify.assert_not_called()

    def test_read_notifies_once_and_disables(self):
        with (tempfile.TemporaryDirectory() as root,
              patch.object(watch, "STATE_DIR", Path(root)),
              patch.object(watch, "read_max_outbox", return_value=101),
              patch.object(watch, "notify_bot", return_value=42) as notify,
              patch.object(watch, "disable_timer") as disable,
              patch.dict("os.environ", OWNER)):
            (Path(root) / "target.json").write_text(json.dumps(TARGET))
            self.assertEqual(watch.run(), 0)
            self.assertEqual(watch.read_json(Path(root) / "delivery.json")["status"], "sent")
            self.assertEqual(watch.run(), 0)
            notify.assert_called_once()
            self.assertEqual(disable.call_count, 2)


if __name__ == "__main__":
    unittest.main()
