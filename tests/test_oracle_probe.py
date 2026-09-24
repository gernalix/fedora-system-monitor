from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


spec = importlib.util.spec_from_file_location("oracle_probe", Path(__file__).resolve().parents[1] / "tools/oracle_probe.py")
assert spec and spec.loader
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class OracleProbeTests(unittest.TestCase):
    def test_backup_job_requires_success_and_freshness(self) -> None:
        properties = {"Result": "success", "ExecMainStatus": "0", "ExecMainExitTimestampMonotonic": "900000000"}
        state = {}
        with mock.patch.object(probe, "systemd_properties", return_value=properties):
            self.assertTrue(probe.check_job("oracle-backup.service", 150, 1000, 2000, state)[0])
            self.assertFalse(probe.check_job("oracle-backup.service", 50, 1000, 2000, state)[0])
            properties["ExecMainExitTimestampMonotonic"] = "0"
            self.assertTrue(probe.check_job("oracle-backup.service", 150, 1050, 2050, state)[0])
            self.assertFalse(probe.check_job("oracle-backup.service", 150, 200, 2200, state)[0])
        properties["Result"] = "exit-code"
        with mock.patch.object(probe, "systemd_properties", return_value=properties):
            self.assertFalse(probe.check_job("oracle-backup.service", 150, 1000, 2050, state)[0])

    def test_daemon_restart_loop_is_independent_of_active_state(self) -> None:
        state = {"datasette.service": {"restart_count": 1, "restart_events": []}}
        properties = {"ActiveState": "active", "SubState": "running", "NRestarts": "4"}
        with mock.patch.object(probe, "systemd_properties", return_value=properties):
            self.assertFalse(probe.check_daemon("datasette.service", 1000, state)[0])

    def test_run_pushes_each_probe_with_correlation_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            config.write_text(json.dumps({"targets": [{"key": "api", "kind": "http", "url": "http://127.0.0.1:8002/-/versions.json"}]}))
            (root / "oracle_push.toml").write_text('[push]\napi = "http://127.0.0.1:3002/api/push/fake"\n')
            with (
                mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(root)}),
                mock.patch.object(probe, "check_http", return_value=(True, "HTTP API status=200")),
                mock.patch.object(probe, "push") as push,
            ):
                result = probe.run(config, root / "state.json")
            self.assertTrue(result["results"][0]["healthy"])
            self.assertIn("run_id=", push.call_args.args[2])

    def test_delivery_failure_does_not_log_or_expose_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            config.write_text(json.dumps({"targets": [{"key": "api", "kind": "http", "url": "http://127.0.0.1:8002/-/versions.json"}]}))
            (root / "oracle_push.toml").write_text('[push]\napi = "http://127.0.0.1:3002/api/push/private"\n')
            with (
                mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(root)}),
                mock.patch.object(probe, "check_http", return_value=(True, "HTTP API status=200")),
                mock.patch.object(probe, "push", side_effect=OSError("transport failed")),
            ):
                result = probe.run(config, root / "state.json")
            self.assertFalse(result["results"][0]["delivered"])
            self.assertNotIn("private", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
