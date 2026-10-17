from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fedora_system_monitor.capsules.runtime import coordinator


class ServiceRuntimeProjectionTests(unittest.TestCase):
    def test_hourly_projection_uses_existing_megavault_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot.json"
            db = SimpleNamespace(path=Path(directory) / "monitor.sqlite3")
            with patch.object(coordinator, "MEGAVAULT_SERVICE_SNAPSHOT", snapshot), patch.object(
                coordinator, "build_runtime_snapshot",
                side_effect=lambda *args, **kwargs: (snapshot.write_text("{}", encoding="utf-8") or {"ok": True}),
            ), patch.object(
                coordinator, "run_command",
                return_value=SimpleNamespace(ok=True, stdout=json.dumps({"status": "PASS", "matched": 4}), stderr="", returncode=0),
            ) as command:
                result = coordinator._reconcile_megavault_service_runtime({}, db)

        self.assertEqual("PASS", result["status"])
        argv = command.call_args.args[0]
        self.assertEqual(["runuser", "--user", "daniele", "--"], argv[:4])
        self.assertIn("service-runtime", argv)
        self.assertEqual(4, result["receipt"]["matched"])

    def test_projection_failure_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot.json"
            db = SimpleNamespace(path=Path(directory) / "monitor.sqlite3")
            with patch.object(coordinator, "MEGAVAULT_SERVICE_SNAPSHOT", snapshot), patch.object(
                coordinator, "build_runtime_snapshot",
                side_effect=lambda *args, **kwargs: (snapshot.write_text("{}", encoding="utf-8") or {"ok": True}),
            ), patch.object(
                coordinator, "run_command",
                return_value=SimpleNamespace(ok=False, stdout="", stderr="writer unavailable", returncode=2),
            ):
                result = coordinator._reconcile_megavault_service_runtime({}, db)
        self.assertEqual("ERROR", result["status"])
        self.assertIn("writer unavailable", result["error"])


if __name__ == "__main__":
    unittest.main()
