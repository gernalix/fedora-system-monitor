from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from fedora_system_monitor.capsules.command import CommandResult
from fedora_system_monitor.capsules.database import Database
from fedora_system_monitor.capsules import collectors
from fedora_system_monitor.capsules.collectors import periodic, software
from fedora_system_monitor.capsules.collectors import common as collector_common
from fedora_system_monitor.capsules.collectors import system as system_collectors
from fedora_system_monitor.capsules.collectors.model import CollectionResult, record


class FakeDatabase:
    def __init__(self) -> None:
        self.state: dict[tuple[str, str], object] = {}

    def get_state(self, key: str, default: object = None, *, namespace: str = "application") -> object:
        return self.state.get((namespace, key), default)

    def set_state(self, key: str, value: object, *, namespace: str = "application", **_: object) -> None:
        self.state[(namespace, key)] = value


class IntegrityDatabase(FakeDatabase):
    def integrity_check(self, *, quick: bool = False) -> list[str]:
        return ["ok"]


def command_result(stdout: str = "", *, returncode: int = 0, timed_out: bool = False, missing: bool = False) -> CommandResult:
    return CommandResult(("mock",), returncode, stdout, "", 1, timed_out=timed_out, missing=missing)


class CollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = FakeDatabase()

    def test_proc_cpu_memory_swap_and_delta(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            (proc / "stat").write_text("cpu  100 0 100 800 0 0 0 0 0 0\n", encoding="utf-8")
            (proc / "loadavg").write_text("1.0 2.0 3.0 1/100 42\n", encoding="utf-8")
            (proc / "meminfo").write_text(
                "MemTotal: 1000 kB\nMemAvailable: 100 kB\nSwapTotal: 1000 kB\nSwapFree: 400 kB\n",
                encoding="utf-8",
            )
            with mock.patch.object(periodic, "PROC_ROOT", proc):
                first = periodic.collect_proc("minute", {}, self.db)
                (proc / "stat").write_text("cpu  200 0 200 1000 0 0 0 0 0 0\n", encoding="utf-8")
                second = periodic.collect_proc("minute", {}, self.db)
        by_name = {metric["name"]: metric for metric in second.metrics}
        self.assertAlmostEqual(by_name["cpu_total_used_percent"]["value"], 50.0)
        self.assertEqual(by_name["cpu_total_used_percent"]["details"]["basis"], "interval")
        self.assertEqual(by_name["memory.used_percent"]["value"], 90.0)
        self.assertEqual(by_name["swap.used_percent"]["severity"], "critical")
        self.assertTrue(any(metric["name"] == "load_15m" for metric in first.metrics))

    def test_filesystem_emergency_and_unsupported_inodes(self) -> None:
        fake_stat = SimpleNamespace(f_blocks=100, f_bavail=4, f_frsize=1024, f_files=0, f_favail=0)
        mounts = [{"mount_point": "/", "root": "/root", "major_minor": "253:0", "options": "rw,relatime", "fstype": "btrfs", "source": "/dev/dm-0"}]
        with mock.patch.object(periodic, "mount_table", return_value=mounts), mock.patch.object(periodic.os, "statvfs", return_value=fake_stat):
            result = periodic.collect_filesystems("minute", {}, self.db, all_relevant=False)
        percent = next(metric for metric in result.metrics if metric["name"] == "filesystem.free_percent")
        self.assertEqual(percent["severity"], "emergency")
        self.assertNotIn("fsdev:", percent["device_id"])
        self.assertEqual(percent["details"]["total_bytes"], 102400)
        self.assertEqual(percent["details"]["free_bytes"], 4096)
        self.assertFalse(any("inode" in metric["name"] for metric in result.metrics))

    def test_btrfs_views_have_distinct_stable_ids(self) -> None:
        fake_stat = SimpleNamespace(f_blocks=100, f_bavail=80, f_frsize=1024, f_files=100, f_favail=90)
        mounts = [
            {"mount_point": "/", "root": "/root", "major_minor": "253:0", "options": "rw", "fstype": "btrfs", "source": "/dev/mapper/root"},
            {"mount_point": "/home", "root": "/home", "major_minor": "253:0", "options": "rw", "fstype": "btrfs", "source": "/dev/mapper/root"},
        ]
        config = {"collection": {"critical_filesystems": ["/", "/home", "/var"]}}
        with mock.patch.object(periodic, "mount_table", return_value=mounts), mock.patch.object(periodic.os, "statvfs", return_value=fake_stat):
            result = periodic.collect_filesystems("minute", config, self.db, all_relevant=False)
        metrics = [metric for metric in result.metrics if metric["name"] == "filesystem.free_percent"]
        self.assertEqual(len(metrics), 3)
        self.assertEqual(len({metric["device_id"] for metric in metrics}), 3)
        self.assertEqual(len({metric["details"]["filesystem_id"] for metric in metrics}), 1)

    def test_discover_services_and_successful_inactive_oneshot(self) -> None:
        listing = "NetworkManager.service enabled enabled\namici-fb.service static -\nrandom.service disabled disabled\n"
        config = {"services": {"essential": ["NetworkManager.service"], "secondary": ["amici-fb.service"], "name_patterns": ["amici"]}}
        show = """Id=NetworkManager.service
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
Type=dbus
Result=success
NRestarts=0

Id=amici-fb.service
LoadState=loaded
ActiveState=inactive
SubState=dead
UnitFileState=static
Type=oneshot
Result=success
NRestarts=0

"""
        with mock.patch.object(periodic, "external", side_effect=[command_result(listing), command_result(listing), command_result(show)]), mock.patch.object(periodic, "_discover_user_services", return_value=[]):
            discovered = periodic.discover_services(config)
            result = periodic.collect_services("minute", config, self.db)
        self.assertEqual(discovered, ["NetworkManager.service", "amici-fb.service"])
        oneshot = next(metric for metric in result.metrics if metric.get("device_id") == "amici-fb.service")
        self.assertEqual(oneshot["severity"], "info")
        self.assertTrue(oneshot["details"]["successful_inactive_oneshot"])
        self.assertEqual(oneshot["details"]["importance"], "secondary")

    def test_service_restart_loop_is_stateful_and_isolated(self) -> None:
        first_show = """Id=demo.service
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
Type=simple
Result=success
NRestarts=1

"""
        second_show = first_show.replace("NRestarts=1", "NRestarts=4")
        config = {"services": {"secondary": ["demo.service"]}, "thresholds": {"services": {"restart_loop_count": 3, "restart_loop_window_minutes": 15}}}
        with mock.patch.object(periodic, "discover_services", return_value=["demo.service"]), mock.patch.object(periodic, "_discover_user_services", return_value=[]), mock.patch.object(periodic, "external", side_effect=[command_result(first_show), command_result(second_show)]):
            first = periodic.collect_services("minute", config, self.db)
            second = periodic.collect_services("minute", config, self.db)
        self.assertFalse(any(event["name"] == "service_restarted" for event in first.events))
        loop = next(metric for metric in second.metrics if metric["name"] == "service.restart_count_window")
        self.assertEqual(loop["severity"], "critical")
        self.assertTrue(any(event["name"] == "service_restarted" for event in second.events))

    def test_scope_failure_isolation(self) -> None:
        def broken(scope: str, config: object, db: object) -> CollectionResult:
            raise RuntimeError("token=do-not-store")

        def healthy(scope: str, config: object, db: object) -> CollectionResult:
            value = CollectionResult(scope)
            value.metrics.append(record(60, "test", "healthy", 1, "boolean", source="test"))
            return value

        with mock.patch.dict(collectors._COLLECTORS, {"minute": (("broken", broken), ("healthy", healthy))}, clear=False):
            result = collectors.collect_scope("minute", {}, self.db)
        self.assertTrue(any(metric["name"] == "healthy" for metric in result.metrics))
        failure = next(event for event in result.events if event["name"] == "collector_failure")
        self.assertNotIn("do-not-store", failure["error_message"])
        self.assertEqual(failure["details"]["exception_type"], "RuntimeError")

    def test_network_counter_rate_uses_database_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            (proc / "net").mkdir()
            header = "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
            (proc / "net" / "dev").write_text(header + "wlan0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n", encoding="utf-8")
            with mock.patch.object(periodic, "PROC_ROOT", proc), mock.patch.object(periodic, "_network_manager_snapshot", return_value=({}, "unavailable")), mock.patch.object(periodic, "_internet_probe", return_value=(True, None, "disabled")), mock.patch.object(periodic.time, "time", side_effect=[100.0, 110.0]):
                periodic.collect_network_detail("five_minute", {}, self.db)
                (proc / "net" / "dev").write_text(header + "wlan0: 2000 0 0 0 0 0 0 0 3000 0 0 0 0 0 0 0\n", encoding="utf-8")
                second = periodic.collect_network_detail("five_minute", {}, self.db)
        download = next(metric for metric in second.metrics if metric["name"] == "interface_download_bytes_per_second")
        self.assertEqual(download["value"], 100.0)

    def test_journal_filter_deduplicates_exact_io_event(self) -> None:
        entries = [
            {"MESSAGE": "MCE: In-kernel MCE decoding enabled.", "__CURSOR": "a"},
            {"MESSAGE": "Buffer I/O error on dev sda3", "__CURSOR": "b", "_BOOT_ID": "boot", "__MONOTONIC_TIMESTAMP": "123"},
        ]
        output = "\n".join(json.dumps(entry) for entry in entries)
        with mock.patch.object(periodic, "external", return_value=command_result(output)):
            first = periodic.collect_journal_io("fifteen_minute", {}, self.db)
            second = periodic.collect_journal_io("fifteen_minute", {}, self.db)
        self.assertEqual([event["name"] for event in first.events], ["kernel_io_error"])
        self.assertEqual(second.events, [])

    def test_external_timeout_is_reported_without_aborting_scope(self) -> None:
        with mock.patch.object(periodic, "external", return_value=command_result(returncode=124, timed_out=True)):
            result = periodic.collect_journal_io("fifteen_minute", {}, self.db)
        self.assertEqual(result.events, [])
        self.assertEqual(result.errors, ["journal: command timed out"])

    def test_dnf_history_is_deduplicated_and_drops_command_line(self) -> None:
        listing = json.dumps([{"id": 1, "command_line": "dnf install token=secret"}])
        info = json.dumps(
            {
                "id": 1,
                "user_id": 1000,
                "status": "Ok",
                "description": "dnf install password=secret",
                "packages": [{"nevra": "example-0:1.2-3.fc44.x86_64", "action": "Install", "repository": "fedora"}],
            }
        )

        def fake_external(config: object, args: list[str], **kwargs: object) -> CommandResult:
            if args[:3] == ["dnf", "history", "list"]:
                return command_result(listing)
            if args[:3] == ["dnf", "history", "info"]:
                return command_result(info)
            if args[:2] == ["flatpak", "history"]:
                return command_result("[]")
            return command_result(missing=True, returncode=127)

        with mock.patch.object(software, "external", side_effect=fake_external):
            first = software.collect_software_history("software_event", {}, self.db)
            second = software.collect_software_history("software_event", {}, self.db)
        package_events = [event for event in first.events if event["name"] == "package_install"]
        self.assertEqual(len(package_events), 1)
        serialized = json.dumps(package_events[0])
        self.assertNotIn("command_line", serialized)
        self.assertNotIn("password", serialized)
        self.assertFalse(any(event["name"] == "package_install" for event in second.events))

    def test_dnf_started_transaction_is_retried_until_terminal(self) -> None:
        listing = json.dumps([{"id": 7, "status": "Started"}])
        statuses = iter(("Started", "Ok"))

        def fake_external(config: object, args: list[str], **kwargs: object) -> CommandResult:
            if args[:3] == ["dnf", "history", "list"]:
                return command_result(listing)
            if args[:3] == ["dnf", "history", "info"]:
                status = next(statuses)
                return command_result(json.dumps({"id": 7, "status": status, "packages": [{"nevra": "demo-0:1-1.x86_64", "action": "Install"}]}))
            return command_result("[]")

        with tempfile.TemporaryDirectory() as temp:
            database = Database(Path(temp) / "monitor.sqlite3")
            try:
                with mock.patch.object(software, "external", side_effect=fake_external):
                    started = software._dnf_history("software_event", {}, database)
                    complete = software._dnf_history("software_event", {}, database)
            finally:
                database.close()
        self.assertFalse(any(event["name"] == "dnf_transaction_failed" for event in started.events))
        self.assertEqual([event["name"] for event in complete.events], ["package_install"])

    def test_manual_snapshot_baseline_then_modify(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            launcher = Path(temp) / "example.desktop"
            launcher.write_text("[Desktop Entry]\nName=One\n", encoding="utf-8")
            config = {"inventory": {"manual_paths": [], "launcher_paths": [temp], "appimage_paths": [], "icon_paths": [], "max_scan_depth": 2, "metadata_hash_max_bytes": 1024}}
            first = software.collect_manual_changes("software_event", config, self.db)
            launcher.write_text("[Desktop Entry]\nName=Two\n", encoding="utf-8")
            second = software.collect_manual_changes("software_event", config, self.db)
        self.assertFalse(any(event["name"].startswith("launcher_") for event in first.events))
        changed = next(event for event in second.events if event["name"] == "launcher_modify")
        self.assertEqual(changed["details"]["operation"], "modify")
        self.assertIn("content_hash", changed["details"])

    def test_android_and_npm_inventory_use_metadata_without_runtimes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            sdk = Path(temp) / "Sdk"
            sdk.mkdir()
            (sdk / "packages.xml").write_text(
                '<sdk:sdk-repository xmlns:sdk="urn:test"><localPackage path="platforms;android-44"><revision><major>1</major><minor>2</minor><micro>3</micro></revision></localPackage></sdk:sdk-repository>',
                encoding="utf-8",
            )
            package = home / ".local" / "lib" / "node_modules" / "demo"
            package.mkdir(parents=True)
            (package / "package.json").write_text('{"name":"demo","version":"2.0.0"}', encoding="utf-8")
            android = software._android_sdk_items(sdk, "daniele")
            npm = software._npm_metadata_items(home, "daniele")
        self.assertEqual(android[0]["version"], "1.2.3")
        self.assertEqual(npm[0]["name"], "demo")
        self.assertEqual(npm[0]["owner_user"], "daniele")

    def test_operator_command_uses_clean_dropped_privilege_environment(self) -> None:
        account = SimpleNamespace(pw_name="daniele", pw_dir="/home/daniele", pw_uid=1000)
        captured: list[str] = []

        def fake_external(config: object, args: list[str], **kwargs: object) -> CommandResult:
            captured.extend(args)
            return command_result("[]")

        with mock.patch.object(collector_common.pwd, "getpwnam", return_value=account), mock.patch.object(collector_common.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="root")), mock.patch.object(collector_common, "external", side_effect=fake_external):
            collector_common.operator_external({}, ["flatpak", "list", "--user"])
        self.assertEqual(captured[:5], ["runuser", "-u", "daniele", "--", "env"])
        self.assertIn("-i", captured)
        self.assertIn("HOME=/home/daniele", captured)
        self.assertIn("XDG_DATA_HOME=/home/daniele/.local/share", captured)
        self.assertNotIn("token", " ".join(captured).lower())

    def test_coredump_records_basename_without_arguments(self) -> None:
        payload = json.dumps(
            [
                {
                    "time": 123,
                    "pid": 22,
                    "uid": 1000,
                    "sig": 11,
                    "exe": "/home/user/private/qemu-system-x86_64-headless",
                    "cmdline": "--password secret",
                    "corefile": "present",
                    "size": 99,
                }
            ]
        )
        with mock.patch.object(system_collectors, "external", return_value=command_result(payload)):
            result = system_collectors.collect_coredumps("hourly", {}, self.db)
        event = result.events[0]
        self.assertEqual(event["details"]["executable"], "qemu-system-x86_64-headless")
        self.assertNotIn("cmdline", json.dumps(event))
        self.assertNotIn("/home/", json.dumps(event))

    def test_sqlite_ok_row_is_not_reported_as_integrity_failure(self) -> None:
        result = system_collectors.collect_db_check("daily", {}, IntegrityDatabase(), quick=True)
        metric = next(item for item in result.metrics if item["name"] == "database_integrity_ok")
        self.assertEqual(metric["value"], 1)
        self.assertEqual(result.events, [])

    def test_smart_details_are_bounded_and_use_canonical_health_name(self) -> None:
        nodes = [{"type": "disk", "path": "/dev/test", "name": "test", "serial": "local-serial", "model": "Demo", "tran": "usb"}]
        payload = json.dumps(
            {
                "smart_status": {"passed": True},
                "ata_smart_attributes": {
                    "table": [
                        {"name": "Reallocated_Sector_Ct", "raw": {"value": 2}},
                        {"name": "Vendor_Private_Secret", "raw": {"value": 999}},
                    ]
                },
            }
        )
        with mock.patch.object(system_collectors, "_block_listing", return_value=(nodes, None)), mock.patch.object(system_collectors, "external", return_value=command_result(payload)):
            result = system_collectors.collect_smart("daily", {}, self.db, detailed=True)
        names = {metric["name"] for metric in result.metrics}
        self.assertIn("smart.health", names)
        self.assertIn("smart.reallocated_sectors", names)
        self.assertNotIn("Vendor_Private_Secret", json.dumps(result.metrics))

    def test_record_convention_is_complete(self) -> None:
        expected = {"cadence", "category", "name", "value", "unit", "severity", "source", "device_id", "details", "outcome", "error_message"}
        self.assertEqual(set(record(60, "x", "y", source="test")), expected)

    def test_software_event_metrics_use_persistable_cadence(self) -> None:
        self.assertGreater(collectors.CADENCE_SECONDS["software_event"], 0)

    def test_malformed_service_entries_do_not_break_discovery(self) -> None:
        config = {"services": {"auto_detect": False, "essential": [{"bad": "entry"}], "secondary": [42, {"name": "demo.service"}]}}
        with mock.patch.object(periodic, "external", return_value=command_result("demo.service enabled enabled\n")):
            self.assertEqual(periodic.discover_services(config), ["demo.service"])

    def test_records_and_inventories_integrate_with_database_capsule(self) -> None:
        with Database(":memory:") as database:
            metric = record(60, "memory", "memory.used_percent", 42.0, "%", source="test")
            event = record(60, "software", "package_install", 1, "package", source="test", device_id="rpm:demo")
            database.insert_metrics(metric)
            database.insert_events(event)
            database.insert_software_snapshot(
                {"category": "software", "name": "demo", "item_key": "rpm:demo", "version": "1", "source": "test"}
            )
            counts = database.table_counts()
            self.assertEqual(counts["periodic_metrics"], 1)
            self.assertEqual(counts["events"], 1)
            self.assertEqual(counts["software_inventory"], 1)


if __name__ == "__main__":
    unittest.main()
