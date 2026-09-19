from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fedora_system_monitor.capsules import eventing
from fedora_system_monitor.capsules.eventing import (
    build_device_event,
    build_lifecycle_event,
    build_network_event,
    classify_journal,
    stream_journal,
)


class JournalClassificationTests(unittest.TestCase):
    def test_real_oom_is_critical_and_minimal(self) -> None:
        event = classify_journal(
            {
                "_TRANSPORT": "kernel",
                "_BOOT_ID": "boot-a",
                "MESSAGE": "Out of memory: Killed process 4242 (python3) total-vm:1000kB, anon-rss:500kB",
            }
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["name"], "oom_kill")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(event["details"], {"pid": 4242, "executable": "python3"})
        self.assertNotIn("total-vm", json.dumps(event))

    def test_oom_words_from_application_are_not_classified(self) -> None:
        self.assertIsNone(
            classify_journal(
                {
                    "_TRANSPORT": "stdout",
                    "_SYSTEMD_UNIT": "example.service",
                    "MESSAGE": "Out of memory: Killed process 4242 (python3) total-vm:1000kB",
                }
            )
        )
        self.assertIsNone(
            classify_journal(
                {
                    "_TRANSPORT": "kernel",
                    "MESSAGE": "No Out of memory: Killed process events were found",
                }
            )
        )

    def test_read_only_requires_exact_kernel_record(self) -> None:
        event = classify_journal(
            {
                "_TRANSPORT": "kernel",
                "MESSAGE": "EXT4-fs (dm-0): Remounting filesystem read-only",
            }
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["name"], "filesystem_read_only")
        self.assertEqual(event["severity"], "critical")

        false_entries = (
            {
                "_TRANSPORT": "stdout",
                "MESSAGE": "EXT4-fs (dm-0): Remounting filesystem read-only",
            },
            {
                "_TRANSPORT": "kernel",
                "MESSAGE": "EXT4-fs (dm-0): Remounting filesystem read-only was avoided",
            },
            {
                "_TRANSPORT": "kernel",
                "MESSAGE": "documentation: filesystem remounted read-only",
            },
        )
        for entry in false_entries:
            with self.subTest(entry=entry):
                self.assertIsNone(classify_journal(entry))

    def test_real_udisks_unsafe_removal_format(self) -> None:
        event = classify_journal(
            {
                "_SYSTEMD_UNIT": "udisks2.service",
                "_COMM": "udisksd",
                "MESSAGE": (
                    "Cleaning up mount point /run/media/daniele/09FA16D309FA16D3 "
                    "(device 8:3 no longer exists)"
                ),
            }
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["name"], "unsafe_device_removal")
        self.assertEqual(event["severity"], "warning")
        self.assertEqual(event["details"]["major_minor"], "8:3")

    def test_coredump_drops_raw_sensitive_fields(self) -> None:
        event = classify_journal(
            {
                "MESSAGE_ID": "fc2e22bc6ee647b6b90729ab34a250b1",
                "SYSLOG_IDENTIFIER": "systemd-coredump",
                "COREDUMP_EXE": "/home/daniele/bin/example",
                "COREDUMP_SIGNAL_NAME": "SIGSEGV",
                "COREDUMP_UNIT": "example.service",
                "COREDUMP_UID": "1000",
                "COREDUMP_CMDLINE": "example --password=do-not-store",
                "COREDUMP_FILENAME": "/var/lib/systemd/coredump/private",
                "MESSAGE": "secret stack trace",
            }
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(
            event["details"],
            {
                "executable": "example",
                "signal": "SIGSEGV",
                "uid": 1000,
                "unit": "example.service",
            },
        )
        rendered = json.dumps(event)
        self.assertNotIn("password", rendered)
        self.assertNotIn("stack trace", rendered)
        self.assertNotIn("/home/daniele", rendered)
        self.assertIsNone(
            classify_journal(
                {
                    "MESSAGE_ID": "fc2e22bc6ee647b6b90729ab34a250b1",
                    "SYSLOG_IDENTIFIER": "untrusted-application",
                    "COREDUMP_EXE": "/tmp/fake",
                }
            )
        )

    def test_gnome_shell_coredump_is_promoted_to_graphics_incident(self) -> None:
        event = classify_journal(
            {
                "MESSAGE_ID": "fc2e22bc6ee647b6b90729ab34a250b1",
                "SYSLOG_IDENTIFIER": "systemd-coredump",
                "COREDUMP_EXE": "/usr/bin/gnome-shell",
                "COREDUMP_SIGNAL_NAME": "SIGSEGV",
                "_BOOT_ID": "boot-graphics",
                "__REALTIME_TIMESTAMP": "1789849169000000",
            }
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["category"], "graphics")
        self.assertEqual(event["name"], "desktop_compositor_coredump")
        self.assertTrue(event["details"]["incident_id"].startswith("gfx-"))

    def test_udisks_mount_failure_with_spaced_mount_path(self) -> None:
        event = classify_journal(
            {
                "_SYSTEMD_UNIT": "udisks2.service",
                "MESSAGE": (
                    "Error mounting /dev/sdb1 at /run/media/daniele/External Drive: "
                    "unknown filesystem type"
                ),
            }
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["name"], "device_mount_failed")
        self.assertEqual(event["details"]["mount_point"], "/run/media/daniele/External Drive")

    def test_networkmanager_offline_and_vpn_final_states(self) -> None:
        offline = classify_journal(
            {
                "_SYSTEMD_UNIT": "NetworkManager.service",
                "MESSAGE": "<info>  [123.4] manager: NetworkManager state is now DISCONNECTED",
            }
        )
        self.assertIsNotNone(offline)
        assert offline is not None
        self.assertEqual(offline["name"], "networkmanager_offline")

        vpn = classify_journal(
            {
                "_SYSTEMD_UNIT": "NetworkManager.service",
                "MESSAGE": (
                    '<info>  [123.5] vpn[0x123,deadbeef,"Private profile"]: '
                    "state changed: activated (5)"
                ),
            }
        )
        self.assertIsNotNone(vpn)
        assert vpn is not None
        self.assertEqual(vpn["name"], "vpn_connected")
        self.assertNotIn("Private profile", json.dumps(vpn))


class BuilderTests(unittest.TestCase):
    def test_device_id_is_stable_and_serial_is_hashed(self) -> None:
        properties = {
            "DEVNAME": "/dev/sdb",
            "SUBSYSTEM": "block",
            "ID_BUS": "usb",
            "ID_VENDOR": "Samsung",
            "ID_MODEL": "Portable_SSD_T7",
            "ID_SERIAL_SHORT": "raw-private-serial",
            "ID_FS_UUID": "A1B2-C3D4",
            "ID_FS_LABEL": "Ventoy",
        }
        added = build_device_event("add", "/dev/sdb", properties, {})
        self.assertTrue(added["device_id"].startswith("serial-sha256:"))
        self.assertNotEqual(added["device_id"], "node:/dev/sdb")
        rendered = json.dumps(added)
        self.assertNotIn("raw-private-serial", rendered)
        self.assertIn("serial_sha256", added["details"])

        removed = build_device_event("device-remove", "/dev/sdb", {}, {"/dev/sdb": added})
        self.assertEqual(removed["device_id"], added["device_id"])
        self.assertEqual(removed["name"], "device_disconnected")

    def test_device_without_identity_does_not_use_sdx_as_id(self) -> None:
        event = build_device_event("add", "/dev/sdz", {"DEVNAME": "/dev/sdz"}, {})
        self.assertEqual(event["device_id"], "")
        self.assertEqual(event["details"]["device_node"], "/dev/sdz")

    def test_network_dispatcher_environment_is_allowlisted(self) -> None:
        event = build_network_event(
            "wlp2s0",
            "up",
            {
                "CONNECTION_TYPE": "802-11-wireless",
                "CONNECTION_ID": "Current-WiFi",
                "IP4_ADDRESS_0": "192.0.2.25/24 192.0.2.1",
                "IP4_GATEWAY": "192.0.2.1",
                "DEVICE_MAC": "AA:BB:CC:DD:EE:FF",
                "BSSID": "11:22:33:44:55:66",
                "PASSWORD": "never-store-this",
                "TOKEN": "never-store-this-either",
                "CONNECTION_FILENAME": "/etc/NetworkManager/system-connections/private.nmconnection",
            },
        )
        self.assertEqual(event["name"], "wifi_connected")
        self.assertEqual(event["details"]["ssid"], "Current-WiFi")
        self.assertEqual(event["details"]["ip_address"], "192.0.2.25/24")
        rendered = json.dumps(event)
        for forbidden in (
            "AA:BB:CC:DD:EE:FF",
            "11:22:33:44:55:66",
            "never-store",
            "nmconnection",
            "PASSWORD",
            "TOKEN",
        ):
            self.assertNotIn(forbidden, rendered)

        disconnected = build_network_event(
            "wlp2s0",
            "down",
            {"CONNECTION_TYPE": "802-11-wireless", "CONNECTION_ID": "Old-WiFi"},
        )
        self.assertNotIn("ssid", disconnected["details"])

    def test_lifecycle_resume_is_recovery(self) -> None:
        event = build_lifecycle_event("post-suspend")
        self.assertEqual(event["name"], "system_resume")
        self.assertEqual(event["outcome"], "recovery")


class _FakeDatabase:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []
        self.state: dict[str, object] = {}

    def get_state(self, key: str, default: object = None, **kwargs: object) -> object:
        namespace = str(kwargs.get("namespace") or "application")
        if namespace == "application":
            return self.state.get(key, default)
        return self.state.get(f"{namespace}:{key}", default)

    def set_state(self, key: str, value: object, **kwargs: object) -> None:
        namespace = str(kwargs.get("namespace") or "application")
        if namespace == "application":
            self.state[key] = value
            return
        self.state[f"{namespace}:{key}"] = value

    def insert_events(self, events: list[dict[str, object]], **_: object) -> int:
        self.events.extend(events)
        return len(events)


class _FakeProcess:
    def __init__(self, output: str) -> None:
        self.stdout = io.StringIO(output)
        self.returncode = 0

    def poll(self) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 0

    def wait(self, timeout: int | None = None) -> int:
        del timeout
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


class StreamTests(unittest.TestCase):
    def test_power_profile_dbus_parser_records_requested_profile_and_caller(self) -> None:
        with patch("fedora_system_monitor.capsules.eventing.correlate_activitywatch", return_value={"available": True, "activity_state": "active"}):
            event = eventing._power_profile_event_from_dbus(
                [
                    "method call time=1785605268.123456 sender=:1.15 -> destination=org.freedesktop.UPower.PowerProfiles serial=42 path=/org/freedesktop/UPower/PowerProfiles; interface=org.freedesktop.DBus.Properties; member=Set\n",
                    '   string "org.freedesktop.UPower.PowerProfiles"\n',
                    '   string "ActiveProfile"\n',
                    '   variant       string "power-saver"\n',
                ],
                caller={"sender": ":1.15", "pid": 1234, "uid": 1000, "user": "daniele", "process": "gnome-control-c"},
            )

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["name"], "power_profile_set_requested")
        self.assertEqual(event["source"], "dbus-monitor")
        self.assertEqual(event["timestamp_utc"], "2026-08-01T17:27:48.123456Z")
        self.assertEqual(event["details"]["requested_profile"], "power-saver")
        self.assertEqual(event["details"]["property"], "ActiveProfile")
        self.assertEqual(event["details"]["path"], "/org/freedesktop/UPower/PowerProfiles")
        self.assertEqual(event["details"]["method"], "Set")
        self.assertEqual(event["details"]["caller"]["process"], "gnome-control-c")
        self.assertEqual(event["details"]["activitywatch"]["activity_state"], "active")
        self.assertEqual(event["dedup_window_seconds"], 0)

    def test_power_profile_dbus_parser_accepts_legacy_path(self) -> None:
        event = eventing._power_profile_event_from_dbus(
            [
                "method call time=1785605268.123456 sender=:1.15 -> destination=net.hadess.PowerProfiles serial=42 path=/net/hadess/PowerProfiles; interface=org.freedesktop.DBus.Properties; member=Set\n",
                '   string "net.hadess.PowerProfiles"\n',
                '   string "ActiveProfile"\n',
                '   variant       string "balanced"\n',
            ],
            caller={"sender": ":1.15"},
        )

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["details"]["path"], "/net/hadess/PowerProfiles")
        self.assertEqual(event["details"]["requested_profile"], "balanced")

    def test_power_profile_dbus_parser_records_hold_and_release(self) -> None:
        hold = eventing._power_profile_event_from_dbus(
            [
                "method call time=1785605269.000000 sender=:1.20 -> destination=org.freedesktop.UPower.PowerProfiles serial=44 path=/org/freedesktop/UPower/PowerProfiles; interface=org.freedesktop.UPower.PowerProfiles; member=HoldProfile\n",
                '   string "performance"\n',
                '   string "test reason"\n',
                '   string "test.app"\n',
            ],
            caller={"sender": ":1.20", "pid": 55},
        )
        release = eventing._power_profile_event_from_dbus(
            [
                "method call time=1785605270.000000 sender=:1.20 -> destination=org.freedesktop.UPower.PowerProfiles serial=45 path=/org/freedesktop/UPower/PowerProfiles; interface=org.freedesktop.UPower.PowerProfiles; member=ReleaseProfile\n",
                "   uint32 7\n",
            ],
            caller={"sender": ":1.20", "pid": 55},
        )

        self.assertIsNotNone(hold)
        self.assertIsNotNone(release)
        assert hold is not None
        assert release is not None
        self.assertEqual(hold["name"], "power_profile_hold_requested")
        self.assertEqual(hold["details"]["requested_profile"], "performance")
        self.assertEqual(hold["details"]["reason"], "test reason")
        self.assertEqual(hold["details"]["application_id"], "test.app")
        self.assertEqual(release["name"], "power_profile_release_requested")
        self.assertEqual(release["details"]["cookie"], 7)

    def test_power_profile_dbus_stream_persists_matching_request(self) -> None:
        process = _FakeProcess(
            "\n".join(
                (
                    "method call time=1785605268.500000 sender=:1.16 -> destination=org.freedesktop.UPower.PowerProfiles serial=43 path=/org/freedesktop/UPower/PowerProfiles; interface=org.freedesktop.DBus.Properties; member=Set",
                    '   string "org.freedesktop.UPower.PowerProfiles"',
                    '   string "ActiveProfile"',
                    '   variant       string "performance"',
                )
            )
            + "\n"
        )
        database = _FakeDatabase()
        callbacks: list[dict[str, object]] = []

        with (
            patch("fedora_system_monitor.capsules.eventing.subprocess.Popen", return_value=process) as popen,
            patch(
                "fedora_system_monitor.capsules.eventing._dbus_sender_identity",
                return_value={"sender": ":1.16", "pid": 4321, "user": "root", "process": "tuned-ppd"},
            ),
            patch("fedora_system_monitor.capsules.eventing.correlate_activitywatch", return_value={"available": True, "activity_state": "active"}),
        ):
            count = eventing.stream_power_profile_dbus({}, database, on_event=callbacks.append)

        self.assertEqual(count, 1)
        self.assertEqual(len(database.events), 1)
        self.assertEqual(callbacks, database.events)
        self.assertEqual(database.events[0]["details"]["requested_profile"], "performance")
        self.assertEqual(database.events[0]["details"]["caller"]["process"], "tuned-ppd")
        command = popen.call_args.args[0]
        self.assertEqual(command[:2], ["dbus-monitor", "--system"])
        self.assertTrue(any("/net/hadess/PowerProfiles" in item for item in command))
        self.assertTrue(any("HoldProfile" not in item for item in command))

    def test_platform_profile_snapshot_persists_only_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sys_root = Path(temp)
            profile = sys_root / "firmware" / "acpi" / "platform_profile"
            ac = sys_root / "class" / "power_supply" / "AC"
            battery = sys_root / "class" / "power_supply" / "BAT0"
            profile.parent.mkdir(parents=True)
            ac.mkdir(parents=True)
            battery.mkdir(parents=True)
            profile.write_text("balanced\n", encoding="utf-8")
            (ac / "type").write_text("Mains\n", encoding="utf-8")
            (ac / "online").write_text("1\n", encoding="utf-8")
            (battery / "type").write_text("Battery\n", encoding="utf-8")
            (battery / "status").write_text("Charging\n", encoding="utf-8")
            (battery / "capacity").write_text("81\n", encoding="utf-8")
            database = _FakeDatabase()

            first = eventing._record_platform_profile_snapshot(
                database,
                eventing._platform_profile_snapshot(sys_root),
            )
            duplicate = eventing._record_platform_profile_snapshot(
                database,
                eventing._platform_profile_snapshot(sys_root),
            )
            profile.write_text("performance\n", encoding="utf-8")
            changed = eventing._record_platform_profile_snapshot(
                database,
                eventing._platform_profile_snapshot(sys_root),
            )

        self.assertIsNone(first)
        self.assertIsNone(duplicate)
        self.assertIsNotNone(changed)
        assert changed is not None
        self.assertEqual(len(database.events), 1)
        self.assertEqual(changed["name"], "platform_profile_changed")
        self.assertEqual(changed["details"]["previous"], "balanced")
        self.assertEqual(changed["details"]["current"], "performance")
        self.assertTrue(changed["details"]["external_online"])
        self.assertEqual(changed["details"]["batteries"][0]["capacity_percent"], 81)

    def test_stream_persists_cursor_only_for_matched_events_and_calls_callback(self) -> None:
        ignored = {"MESSAGE": "ordinary application log", "__CURSOR": "ignored"}
        matched = {
            "_TRANSPORT": "kernel",
            "_BOOT_ID": "boot-a",
            "MESSAGE": "usb 2-2: USB disconnect, device number 2",
            "__CURSOR": "cursor-a",
            "__MONOTONIC_TIMESTAMP": "123",
            "__REALTIME_TIMESTAMP": "456",
        }
        process = _FakeProcess("\n".join((json.dumps(ignored), json.dumps(matched))) + "\n")
        database = _FakeDatabase()
        callbacks: list[dict[str, object]] = []
        with patch(
            "fedora_system_monitor.capsules.eventing.subprocess.Popen",
            return_value=process,
        ) as popen:
            count = stream_journal(
                {"events": {"journal_lookback_seconds": 900}},
                database,
                on_event=callbacks.append,
            )

        self.assertEqual(count, 1)
        self.assertEqual(len(database.events), 1)
        self.assertEqual(callbacks, database.events)
        self.assertEqual(database.events[0]["timestamp_utc"], "1970-01-01T00:00:00.000456Z")
        self.assertEqual(
            database.events[0]["details"]["journal_identity"],
            {"cursor": "cursor-a", "boot_id": "boot-a", "monotonic": 123, "realtime": 456},
        )
        self.assertEqual(
            database.state["journal_cursor"],
            {"cursor": "cursor-a", "boot_id": "boot-a", "monotonic": 123, "realtime": 456},
        )
        command = popen.call_args.args[0]
        self.assertIn("--since=-900s", command)
        self.assertTrue(any(value.startswith("--output-fields=") for value in command))
        self.assertIn("SYSLOG_IDENTIFIER=gnome-shell", command)
        self.assertIn("_SYSTEMD_USER_UNIT=org.gnome.Shell@wayland.service", command)

    def test_existing_valid_cursor_is_used(self) -> None:
        database = _FakeDatabase()
        database.state["journal_cursor"] = {"cursor": "stored-cursor"}
        process = _FakeProcess("")
        with (
            patch(
                "fedora_system_monitor.capsules.eventing._cursor_is_valid",
                return_value=True,
            ),
            patch(
                "fedora_system_monitor.capsules.eventing.subprocess.Popen",
                return_value=process,
            ) as popen,
        ):
            stream_journal({}, database)
        self.assertIn("--after-cursor=stored-cursor", popen.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
