from __future__ import annotations

import argparse
import json
import unittest
from unittest.mock import patch

from fedora_system_monitor.capsules.eventing import classify_journal
from fedora_system_monitor.capsules.smart_action import (
    SmartAlert,
    _notify_worker,
    fixture_alert,
    maybe_notify_smart_alert,
    open_gnome_disks,
    parse_smartd_message,
    render_detail_text,
    run_cli,
)


class FakeDb:
    def __init__(self) -> None:
        self.state: dict[tuple[str, str], object] = {}

    def get_state(self, key: str, default: object = None, *, namespace: str = "application") -> object:
        return self.state.get((namespace, key), default)

    def set_state(self, key: str, value: object, *, namespace: str = "application") -> None:
        self.state[(namespace, key)] = value


class SmartActionTests(unittest.TestCase):
    def test_parse_smartd_nvme_read_failure(self) -> None:
        alert = parse_smartd_message("Device: /dev/sdd [USB NVMe ASMedia], failed to read NVMe SMART/Health Information")
        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert.device, "/dev/sdd")
        self.assertEqual(alert.bridge, "USB NVMe ASMedia")
        self.assertEqual(alert.severity, "warning")
        self.assertIn("espulsione sicura", alert.action)

    def test_classify_smartd_journal_event(self) -> None:
        event = classify_journal(
            {
                "_SYSTEMD_UNIT": "smartd.service",
                "MESSAGE": "Device: /dev/sdd [USB NVMe ASMedia], open() of NVMe device failed: No such device",
            }
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["name"], "smartd_smart_alert")
        self.assertEqual(event["severity"], "warning")
        self.assertTrue(event["device_id"].startswith("smartd:"))
        self.assertEqual(event["details"]["device_node"], "/dev/sdd")
        self.assertIn("smartd_message", event["details"])

    def test_detail_text_contains_required_fields(self) -> None:
        text = render_detail_text(fixture_alert("t7-usb-nvme-read-failed"))
        for expected in (
            "Samsung Portable SSD T7 Shield",
            "/dev/sdd",
            "serial:S6YGNS0Y903440H",
            "failed to read NVMe SMART/Health Information",
            "Severity: warning",
            "Recommended action:",
        ):
            self.assertIn(expected, text)

    def test_gnome_disks_command_targets_current_device(self) -> None:
        result = open_gnome_disks({}, fixture_alert("t7-usb-nvme-read-failed"), no_open=True)
        self.assertEqual(result["command"], ["gnome-disks", "--block-device=/dev/sdc"])

    def test_notification_deduplicates_same_condition(self) -> None:
        db = FakeDb()
        alert = fixture_alert("t7-usb-nvme-read-failed")
        same_later = SmartAlert(
            device=alert.device,
            bridge=alert.bridge,
            problem=alert.problem,
            model=alert.model,
            serial=alert.serial,
            current_device=alert.current_device,
            smart_status=alert.smart_status,
            severity=alert.severity,
            action=alert.action,
            detected_at="2026-09-15T23:38:10+02:00",
        )
        with patch("fedora_system_monitor.capsules.smart_action.threading.Thread") as thread:
            self.assertTrue(maybe_notify_smart_alert({}, db, alert))
            self.assertFalse(maybe_notify_smart_alert({}, db, same_later))
        self.assertEqual(thread.call_count, 1)

    def test_cli_fixture_details_no_open_is_safe(self) -> None:
        args = argparse.Namespace(
            fixture="t7-usb-nvme-read-failed",
            message="",
            action="details",
            no_open=True,
            force=False,
        )
        output = run_cli(args, {}, None)
        self.assertFalse(output["opened"])
        self.assertIn("SMART disk alert", output["text"])
        self.assertNotIn("raw-private", json.dumps(output))

    def test_cli_notification_probe_uses_notify_send(self) -> None:
        args = argparse.Namespace(
            fixture="t7-usb-nvme-read-failed",
            message="",
            action="notify",
            no_open=True,
            force=False,
        )
        with patch("fedora_system_monitor.capsules.smart_action.operator_external") as operator:
            operator.return_value.ok = True
            operator.return_value.returncode = 0
            output = run_cli(args, {}, None)
        self.assertTrue(output["sent"])
        command = operator.call_args.args[1]
        self.assertEqual(command[0], "notify-send")
        self.assertIn("SMART Disk Monitor", command)

    def test_notification_default_action_opens_details(self) -> None:
        result = type("Result", (), {"stdout": "default\n", "ok": True, "returncode": 0})()
        with (
            patch("fedora_system_monitor.capsules.smart_action.operator_external", return_value=result) as operator,
            patch("fedora_system_monitor.capsules.smart_action.show_details") as details,
        ):
            _notify_worker({}, fixture_alert("t7-usb-nvme-read-failed"))
        self.assertIn("--wait", operator.call_args.args[1])
        details.assert_called_once()


if __name__ == "__main__":
    unittest.main()
