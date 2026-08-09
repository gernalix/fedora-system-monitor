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
from fedora_system_monitor.capsules.collectors import dnf, periodic, software
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


def command_result(stdout: str = "", *, stderr: str = "", returncode: int = 0, timed_out: bool = False, missing: bool = False) -> CommandResult:
    return CommandResult(("mock",), returncode, stdout, stderr, 1, timed_out=timed_out, missing=missing)


class CollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = FakeDatabase()

    def test_proc_cpu_memory_swap_and_delta(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            proc = root / "proc"
            sys = root / "sys"
            (proc / "pressure").mkdir(parents=True)
            (sys / "block" / "zram0").mkdir(parents=True)
            (proc / "stat").write_text("cpu  100 0 100 800 0 0 0 0 0 0\n", encoding="utf-8")
            (proc / "loadavg").write_text("1.0 2.0 3.0 1/100 42\n", encoding="utf-8")
            (proc / "meminfo").write_text(
                "MemTotal: 1000 kB\nMemAvailable: 100 kB\nSwapTotal: 1000 kB\nSwapFree: 400 kB\n",
                encoding="utf-8",
            )
            (proc / "pressure" / "memory").write_text("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n", encoding="utf-8")
            (proc / "vmstat").write_text("pswpin 0\npswpout 0\npgscan_kswapd 0\npgsteal_kswapd 0\noom_kill 0\n", encoding="utf-8")
            (sys / "block" / "zram0" / "mm_stat").write_text("600000 300000 320000 0 0 0 0 0 0\n", encoding="utf-8")
            (sys / "block" / "zram0" / "disksize").write_text("1000000\n", encoding="utf-8")
            with mock.patch.object(periodic, "PROC_ROOT", proc), mock.patch.object(periodic, "SYS_ROOT", sys):
                first = periodic.collect_proc("minute", {}, self.db)
                (proc / "stat").write_text("cpu  200 0 200 1000 0 0 0 0 0 0\n", encoding="utf-8")
                second = periodic.collect_proc("minute", {}, self.db)
        by_name = {metric["name"]: metric for metric in second.metrics}
        self.assertAlmostEqual(by_name["cpu_total_used_percent"]["value"], 50.0)
        self.assertEqual(by_name["cpu_total_used_percent"]["details"]["basis"], "interval")
        self.assertEqual(by_name["memory.used_percent"]["value"], 90.0)
        self.assertEqual(by_name["swap.used_percent"]["severity"], "info")
        self.assertEqual(by_name["memory.pressure_level"]["value"], 0)
        self.assertEqual(by_name["zram.compression_ratio"]["value"], 2.0)
        self.assertTrue(any(metric["name"] == "load_15m" for metric in first.metrics))

    def test_memory_pressure_combines_available_psi_swap_reclaim_and_oom(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            (proc / "pressure").mkdir()
            (proc / "stat").write_text("cpu  100 0 100 800 0 0 0 0 0 0\n", encoding="utf-8")
            (proc / "loadavg").write_text("0 0 0 1/1 1\n", encoding="utf-8")
            (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 40 kB\nSwapTotal: 1000 kB\nSwapFree: 100 kB\n", encoding="utf-8")
            (proc / "pressure" / "memory").write_text("some avg10=12.00 avg60=1.00 avg300=0.00 total=1\nfull avg10=6.00 avg60=1.00 avg300=0.00 total=1\n", encoding="utf-8")
            (proc / "vmstat").write_text("pswpin 0\npswpout 0\npgscan_kswapd 0\npgsteal_kswapd 0\noom_kill 0\n", encoding="utf-8")
            with mock.patch.object(periodic, "PROC_ROOT", proc), mock.patch.object(periodic, "SYS_ROOT", proc / "missing"), mock.patch.object(periodic.time, "time", return_value=100.0):
                periodic.collect_proc("minute", {}, self.db)
            (proc / "vmstat").write_text("pswpin 10\npswpout 5000\npgscan_kswapd 5000\npgsteal_kswapd 4000\noom_kill 1\n", encoding="utf-8")
            with mock.patch.object(periodic, "PROC_ROOT", proc), mock.patch.object(periodic, "SYS_ROOT", proc / "missing"), mock.patch.object(periodic.time, "time", return_value=160.0):
                result = periodic.collect_proc("minute", {}, self.db)
        by_name = {metric["name"]: metric for metric in result.metrics}
        self.assertEqual(by_name["memory.pressure_level"]["value"], 2)
        self.assertEqual(by_name["memory.oom_kills_delta"]["value"], 1)
        self.assertGreater(by_name["memory.swap_out_bytes_per_second"]["value"], 0)
        self.assertEqual(by_name["memory.pressure_level"]["details"]["reclaim_efficiency_percent"], 80.0)

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

    def test_virtual_and_temporary_filesystems_are_excluded(self) -> None:
        fake_stat = SimpleNamespace(
            f_blocks=100,
            f_bavail=80,
            f_frsize=1024,
            f_files=100,
            f_favail=90,
        )
        mounts = [
            {"mount_point": "/", "root": "/", "major_minor": "253:0", "options": "rw", "fstype": "btrfs", "source": "/dev/mapper/root"},
            {"mount_point": "/tmp", "root": "/", "major_minor": "0:42", "options": "rw", "fstype": "tmpfs", "source": "tmpfs"},
            {"mount_point": "/var/lib/containers/overlay", "root": "/", "major_minor": "0:43", "options": "rw", "fstype": "overlay", "source": "overlay"},
            {"mount_point": "/var/lib/snap", "root": "/", "major_minor": "7:0", "options": "ro", "fstype": "squashfs", "source": "/dev/loop0"},
        ]
        with mock.patch.object(periodic, "mount_table", return_value=mounts), mock.patch.object(periodic.os, "statvfs", return_value=fake_stat):
            result = periodic.collect_filesystems("five_minute", {}, self.db, all_relevant=True)
        mount_points = {
            metric["details"]["mount_point"]
            for metric in result.metrics
            if metric["name"] == "filesystem_free_bytes"
        }
        self.assertIn("/", mount_points)
        self.assertNotIn("/tmp", mount_points)
        self.assertNotIn("/var/lib/containers/overlay", mount_points)
        self.assertNotIn("/var/lib/snap", mount_points)

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

        with mock.patch.object(dnf, "external", side_effect=fake_external), mock.patch.object(software, "external", side_effect=fake_external):
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
                with mock.patch.object(dnf, "external", side_effect=fake_external):
                    started = dnf.collect_history("software_event", {}, database)
                    complete = dnf.collect_history("software_event", {}, database)
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
                "ata_smart_error_log": {"summary": {"count": 0}},
                "ata_smart_self_test_log": {"standard": {"table": [{"status": {"string": "Completed without error"}}]}},
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
        self.assertIn("smart.error_log_entries", names)
        self.assertIn("smart.self_test_failures", names)
        self.assertNotIn("Vendor_Private_Secret", json.dumps(result.metrics))

    def test_smart_permission_failure_keeps_bounded_diagnostics(self) -> None:
        nodes = [{"type": "disk", "path": "/dev/test", "name": "test", "serial": "local-serial", "model": "Demo NVMe", "tran": "nvme"}]
        payload = json.dumps(
            {
                "smartctl": {
                    "argv": ["smartctl", "-j", "-n", "standby", "-H", "/dev/test"],
                    "exit_status": 4,
                    "messages": [{"string": "NVME_IOCTL_ADMIN_CMD: Permission denied", "severity": "error"}],
                },
                "device": {"type": "nvme", "protocol": "NVMe"},
            }
        )
        with mock.patch.object(system_collectors, "_block_listing", return_value=(nodes, None)), mock.patch.object(system_collectors.Path, "exists", return_value=True), mock.patch.object(system_collectors, "external", return_value=command_result(payload, returncode=4)):
            result = system_collectors.collect_smart("hourly", {}, self.db, detailed=False)
        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event["name"], "smart_check_failed")
        self.assertEqual(event["details"]["failure_class"], "permission")
        self.assertEqual(event["details"]["exit_status"], 4)
        self.assertEqual(event["details"]["device_type"], "nvme")
        self.assertEqual(event["details"]["identity"], event["device_id"])
        self.assertIn("Permission denied", event["error_message"])

    def test_smart_absent_and_unsupported_devices_are_skipped(self) -> None:
        nodes = [{"type": "disk", "path": "/dev/test", "name": "test", "serial": "local-serial", "model": "USB Disk", "tran": "usb"}]
        absent_payload = json.dumps({"smartctl": {"exit_status": 2}})
        with mock.patch.object(system_collectors, "_block_listing", return_value=(nodes, None)), mock.patch.object(system_collectors.Path, "exists", return_value=False), mock.patch.object(system_collectors, "external", return_value=command_result(absent_payload, returncode=2)):
            absent = system_collectors.collect_smart("hourly", {}, self.db, detailed=False)
        self.assertEqual(absent.events, [])
        self.assertEqual(absent.metrics[0]["name"], "smart_check_skipped_absent")
        self.assertEqual(absent.metrics[0]["details"]["failure_class"], "device_absent")

        unsupported_payload = json.dumps(
            {
                "smartctl": {
                    "exit_status": 1,
                    "messages": [{"string": "Unknown USB bridge", "severity": "error"}],
                }
            }
        )
        with mock.patch.object(system_collectors, "_block_listing", return_value=(nodes, None)), mock.patch.object(system_collectors, "external", return_value=command_result(unsupported_payload, returncode=1)):
            unsupported = system_collectors.collect_smart("hourly", {}, self.db, detailed=False)
        self.assertEqual(unsupported.events, [])
        self.assertEqual(unsupported.metrics[0]["name"], "smart.supported")
        self.assertEqual(unsupported.metrics[0]["outcome"], "skipped")

    def test_smart_usb_nvme_detailed_mode_avoids_error_log(self) -> None:
        nodes = [{"type": "disk", "path": "/dev/test", "name": "test", "serial": "local-serial", "model": "USB NVMe", "tran": "usb"}]
        health = json.dumps(
            {
                "smartctl": {"exit_status": 0},
                "device": {"type": "sntasmedia", "protocol": "NVMe"},
                "smart_status": {"passed": True},
            }
        )
        detail = json.dumps(
            {
                "smartctl": {"exit_status": 0},
                "device": {"type": "sntasmedia", "protocol": "NVMe"},
                "nvme_self_test_log": {"current_self_test_operation": {"value": 0}},
            }
        )
        with mock.patch.object(system_collectors, "_block_listing", return_value=(nodes, None)), mock.patch.object(system_collectors, "external", side_effect=[command_result(health), command_result(detail)]) as mocked:
            result = system_collectors.collect_smart("daily", {}, self.db, detailed=True)
        detail_command = mocked.call_args_list[1].args[1]
        self.assertIn("-A", detail_command)
        self.assertIn("selftest", detail_command)
        self.assertNotIn("error", detail_command)
        by_name = {metric["name"]: metric for metric in result.metrics}
        self.assertEqual(by_name["smart.error_log_supported"]["outcome"], "skipped")
        self.assertEqual(result.events, [])

    def test_btrfs_health_collects_device_and_scrub_errors(self) -> None:
        outputs = [
            command_result("/\n/home\n"),
            command_result("[/dev/mapper/root].write_io_errs 0\n[/dev/mapper/root].read_io_errs 2\n[/dev/mapper/root].flush_io_errs 0\n[/dev/mapper/root].corruption_errs 0\n[/dev/mapper/root].generation_errs 0\n"),
            command_result("Error summary: no errors found\n"),
        ]
        with mock.patch.object(system_collectors, "external", side_effect=outputs) as mocked:
            result = system_collectors.collect_btrfs_health("daily", {}, self.db)
        by_name = {metric["name"]: metric for metric in result.metrics}
        self.assertEqual(by_name["btrfs.read_io_errors"]["value"], 2)
        self.assertEqual(by_name["btrfs.read_io_errors"]["severity"], "critical")
        self.assertEqual(by_name["btrfs.scrub_errors"]["value"], 0)
        self.assertEqual(mocked.call_args_list[1].args[1], ["btrfs", "device", "stats", "/"])

    def test_battery_health_includes_capacity_wear_energy_and_power(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sys = Path(temp)
            battery = sys / "class" / "power_supply" / "BAT0"
            battery.mkdir(parents=True)
            values = {
                "type": "Battery", "energy_full_design": "50000000", "energy_full": "45000000",
                "energy_now": "25000000", "power_now": "7500000", "voltage_now": "16000000",
                "cycle_count": "100", "capacity": "50", "status": "Discharging",
            }
            for name, value in values.items():
                (battery / name).write_text(value, encoding="utf-8")
            with mock.patch.object(system_collectors, "SYS_ROOT", sys):
                health = system_collectors.collect_battery_health("daily", {}, self.db)
            with mock.patch.object(periodic, "SYS_ROOT", sys):
                current = periodic.collect_power("minute", {}, self.db)
        health_names = {metric["name"] for metric in health.metrics}
        current_names = {metric["name"] for metric in current.metrics}
        self.assertTrue({"battery_design_capacity_wh", "battery_full_capacity_wh", "battery_wear_percent"} <= health_names)
        self.assertTrue({"battery_energy_wh", "battery_power_w", "battery_voltage_v"} <= current_names)

    def test_power_profile_metric_and_change_event_are_stateful(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sys = Path(temp)
            mains = sys / "class" / "power_supply" / "AC"
            battery = sys / "class" / "power_supply" / "BAT0"
            profile_path = sys / "firmware" / "acpi" / "platform_profile"
            mains.mkdir(parents=True)
            battery.mkdir(parents=True)
            profile_path.parent.mkdir(parents=True)
            for path, value in (
                (mains / "type", "Mains"),
                (mains / "online", "1"),
                (battery / "type", "Battery"),
                (battery / "present", "1"),
                (battery / "capacity", "78"),
                (battery / "status", "Not charging"),
                (battery / "energy_now", "40780000"),
                (battery / "power_now", "0"),
                (battery / "voltage_now", "16178000"),
            ):
                path.write_text(value, encoding="utf-8")
            profile_path.write_text("low-power\n", encoding="utf-8")
            first_profile = {
                "platform_profile": "low-power",
                "tuned_profile": "powersave",
                "ppd_base_profile": "power-saver",
                "profile_mode": "manual",
            }
            second_profile = {
                "platform_profile": "performance",
                "tuned_profile": "throughput-performance",
                "ppd_base_profile": "performance",
                "profile_mode": "manual",
            }
            with (
                mock.patch.object(periodic, "SYS_ROOT", sys),
                mock.patch.object(periodic, "_power_profile_snapshot", side_effect=[first_profile, second_profile]),
                mock.patch.object(periodic, "correlate_activitywatch", return_value={"available": True, "activity_state": "active"}),
            ):
                first = periodic.collect_power("minute", {}, self.db)
                second = periodic.collect_power("minute", {}, self.db)
        metric = next(item for item in first.metrics if item["name"] == "power_profile.active")
        self.assertEqual(metric["details"]["tuned_profile"], "powersave")
        event = next(item for item in second.events if item["name"] == "power_profile_changed")
        self.assertEqual(event["details"]["previous"]["tuned_profile"], "powersave")
        self.assertEqual(event["details"]["current"]["tuned_profile"], "throughput-performance")
        self.assertTrue(event["details"]["power_context"]["external_online"])
        self.assertEqual(event["details"]["power_context"]["batteries"][0]["status"], "Not charging")
        self.assertEqual(event["details"]["activitywatch"]["activity_state"], "active")

    def test_record_convention_is_complete(self) -> None:
        expected = {"cadence", "category", "name", "value", "unit", "severity", "source", "device_id", "details", "outcome", "error_message"}
        self.assertEqual(set(record(60, "x", "y", source="test")), expected)

    def test_software_event_metrics_use_persistable_cadence(self) -> None:
        self.assertGreater(collectors.CADENCE_SECONDS["software_event"], 0)

    def test_missing_flatpak_cached_summary_is_skipped_not_failed(self) -> None:
        system_commands = [
            command_result("", returncode=0),
            command_result("[]", returncode=0),
            command_result("", stderr="No cached summary for remote 'flathub'", returncode=1),
        ]
        with mock.patch.object(software, "external", side_effect=system_commands), mock.patch.object(software, "_operator_external", return_value=command_result("[]")):
            result = software.collect_updates("daily", {}, self.db)
        cache = next(metric for metric in result.metrics if metric["name"] == "flatpak_system_update_cache_available")
        self.assertEqual(cache["value"], 0)
        self.assertEqual(cache["outcome"], "skipped")
        self.assertEqual(result.errors, [])

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
