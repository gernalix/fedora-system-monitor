from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from fedora_system_monitor.capsules.command import exclusive_lock, run_command


class CommandTests(unittest.TestCase):
    def test_command_success(self) -> None:
        result = run_command([sys.executable, "-c", "print('ok')"], timeout=2)
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout.strip(), "ok")

    def test_command_timeout_is_isolated(self) -> None:
        result = run_command([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.05)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, 124)

    def test_output_is_bounded_while_pipe_is_drained(self) -> None:
        result = run_command([sys.executable, "-c", "print('x' * 1000000)"], timeout=2, max_output=1024)
        self.assertTrue(result.ok)
        self.assertEqual(len(result.stdout), 1024)

    def test_lock_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "monitor.lock"
            with exclusive_lock(path):
                self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
