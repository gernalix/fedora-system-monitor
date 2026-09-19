from __future__ import annotations

from datetime import datetime, timezone
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fedora_system_monitor.capsules.graphics_incident import (
    build_compositor_transition_event,
    classify_gnome_journal,
    classify_graphics_coredump,
    classify_graphics_kernel,
    enrich_graphics_incident,
)


class GraphicsIncidentTests(unittest.TestCase):
    def test_gnome_shell_coredump_gets_incident_id_without_raw_core_data(self) -> None:
        event = classify_graphics_coredump(
            {
                "_BOOT_ID": "boot-a",
                "__CURSOR": "cursor-a",
                "__REALTIME_TIMESTAMP": "1789849169000000",
                "COREDUMP_EXE": "/usr/bin/gnome-shell",
                "COREDUMP_SIGNAL_NAME": "SIGABRT",
                "COREDUMP_UID": "1000",
                "COREDUMP_CMDLINE": "gnome-shell --secret=never-store",
                "COREDUMP_FILENAME": "/var/lib/systemd/coredump/private",
            }
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["name"], "desktop_compositor_coredump")
        self.assertEqual(event["severity"], "critical")
        self.assertTrue(event["details"]["incident_id"].startswith("gfx-"))
        rendered = json.dumps(event)
        self.assertNotIn("never-store", rendered)
        self.assertNotIn("COREDUMP_FILENAME", rendered)

    def test_gnome_assertion_is_recorded_but_not_promoted_to_incident(self) -> None:
        event = classify_gnome_journal(
            {"SYSLOG_IDENTIFIER": "gnome-shell"},
            "meta_window_actor assertion 'surface != NULL' failed",
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["name"], "desktop_compositor_assertion")
        self.assertNotIn("incident_id", event["details"])

    def test_amdgpu_timeout_is_graphics_fault(self) -> None:
        event = classify_graphics_kernel(
            {"_TRANSPORT": "kernel"},
            "amdgpu 0000:c4:00.0: ring gfx timeout, signaled seq=10",
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["name"], "gpu_driver_fault")
        self.assertEqual(event["severity"], "critical")

    def test_pid_transition_is_high_confidence_incident(self) -> None:
        event = build_compositor_transition_event(
            {1234},
            set(),
            when=datetime(2026, 9, 19, 20, 59, 29, tzinfo=timezone.utc),
            boot_id="boot-a",
        )
        self.assertEqual(event["name"], "desktop_compositor_failure")
        self.assertEqual(event["details"]["trigger"], "pid_disappeared")
        self.assertEqual(event["details"]["confidence"], "high")
        self.assertTrue(event["details"]["incident_id"].startswith("gfx-"))

    def test_forensic_snapshot_embeds_activitywatch_and_uses_relative_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            event = {
                "category": "graphics",
                "name": "desktop_compositor_failure",
                "timestamp_utc": "2026-09-19T20:59:29.000000Z",
                "details": {
                    "incident_id": "gfx-test-123",
                    "trigger": "pid_disappeared",
                },
            }
            config = {
                "monitor": {
                    "operator_user": "daniele",
                    "database_path": str(Path(temp) / "monitor.sqlite3"),
                }
            }
            with (
                patch(
                    "fedora_system_monitor.capsules.graphics_incident.correlate_activitywatch",
                    return_value={"available": True, "activity_state": "active"},
                ),
                patch(
                    "fedora_system_monitor.capsules.graphics_incident._run",
                    return_value={"ok": True, "returncode": 0, "stdout": "", "stderr": ""},
                ),
                patch(
                    "fedora_system_monitor.capsules.graphics_incident._graphics_sysfs",
                    return_value=[],
                ),
                patch(
                    "fedora_system_monitor.capsules.graphics_incident._user_command",
                    return_value=None,
                ),
            ):
                enrich_graphics_incident(config, event)

            snapshot = Path(temp) / "incidents" / "gfx-test-123.json"
            self.assertTrue(snapshot.exists())
            payload = json.loads(snapshot.read_text(encoding="utf-8"))
            self.assertEqual(payload["activitywatch"]["activity_state"], "active")
            self.assertEqual(
                event["details"]["forensic_snapshot"]["file"],
                "incidents/gfx-test-123.json",
            )


if __name__ == "__main__":
    unittest.main()
