from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from fedora_system_monitor.app import main
from fedora_system_monitor.capsules.database import Database


class AppTests(unittest.TestCase):
    config = Path(__file__).resolve().parents[1] / "config/fedora-system-monitor.toml"

    def test_db_check_and_read_only_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "monitor.sqlite3"
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--config", str(self.config), "--database", str(database), "db-check", "--json"])
            self.assertEqual(result, 0)
            self.assertTrue(json.loads(output.getvalue())["ok"])
            database.chmod(0o440)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--config", str(self.config), "--database", str(database), "status", "--json"])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue())["schema_version"], 2)

    def test_collect_worker_persists_real_minute_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "monitor.sqlite3"
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "--config",
                        str(self.config),
                        "--database",
                        str(database),
                        "collect-worker",
                        "minute",
                        "--json",
                    ]
                )
            self.assertEqual(result, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["scope"], "minute")
            self.assertGreater(payload["metrics"], 5)
            db = Database(database)
            try:
                names = {row["name"] for row in db.query("SELECT DISTINCT name FROM periodic_metrics")}
            finally:
                db.close()
            self.assertIn("memory.used_percent", names)


if __name__ == "__main__":
    unittest.main()
