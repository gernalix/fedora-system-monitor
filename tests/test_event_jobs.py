from __future__ import annotations

import tempfile
import os
import time
import unittest
from pathlib import Path
from unittest import mock

from fedora_system_monitor.capsules import event_jobs


class EventJobTests(unittest.TestCase):
    def test_disconnected_t7_is_not_down(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(event_jobs, "_backup_unit", return_value={"Result": "success", "ExecMainStatus": "0", "ActiveState": "inactive"}):
                healthy, reason = event_jobs.t7_backup_health(Path(temporary) / "absent", Path(temporary) / "record")
        self.assertTrue(healthy)
        self.assertIn("disconnected", reason)

    def test_present_t7_requires_current_attachment_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = Path(temporary) / "device"
            record = Path(temporary) / "record"
            record.write_text("completed")
            old = time.time() - 30
            os.utime(record, (old, old))
            device.write_text("present")
            with mock.patch.object(event_jobs, "_backup_unit", return_value={"Result": "success", "ExecMainStatus": "0", "ActiveState": "inactive"}):
                self.assertFalse(event_jobs.t7_backup_health(device, record)[0])
                record.write_text("new completion")
                self.assertTrue(event_jobs.t7_backup_health(device, record)[0])

    def test_failure_stays_down_after_disconnect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(event_jobs, "_backup_unit", return_value={"Result": "exit-code", "ExecMainStatus": "1", "ActiveState": "failed"}):
                self.assertFalse(event_jobs.t7_backup_health(Path(temporary) / "absent", Path(temporary) / "record")[0])


if __name__ == "__main__":
    unittest.main()
