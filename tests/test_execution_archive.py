"""Execution archive gates use temporary storage and public synthetic canaries."""
import hashlib
import json
import os
import pty
import select
import shlex
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fedora_system_monitor.capsules.execution_archive import Archive, Zstd, atomic_json
from fedora_system_monitor.capsules.execution_archive.capture import request
from fedora_system_monitor.capsules.execution_archive.process_adapter import _command_name
from fedora_system_monitor.capsules.execution_archive.local_sources import (
    collect_journal,
    collect_podman,
    inventory,
    parse_podman_events,
    run_wrapped,
)
from fedora_system_monitor.capsules.execution_archive.remote_sources import (
    _transport_argv,
    ingest_github_run,
    remote_inventory,
)

REPO = Path(__file__).resolve().parent.parent
MODULE = "fedora_system_monitor.capsules.execution_archive.cli"
PROCESS_MODULE = "fedora_system_monitor.capsules.execution_archive.process_adapter"


class ArchiveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "archive"
        self.a = Archive(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *args):
        return subprocess.run([sys.executable, "-m", MODULE, "--root", str(self.root), *args],
                              capture_output=True, timeout=15, env=os.environ | {"PYTHONPATH": str(REPO / "src")})

    def event(self, data=b"public frame\n"):
        m = self.a.begin(kind="command", source="diagnostic", label="demo", pid=os.getpid(), capture=True)
        self.a.append(m, data, .01)
        self.a.finish(m, 0)
        return m

    def test_manifest_zstd_fts_replay_and_rebuild(self):
        m = self.event(b"\x1b[2J\x1b[Hpublic frame\n")
        self.assertEqual(self.a.read(m, "output"), b"\x1b[2J\x1b[Hpublic frame\n")
        self.assertEqual(self.a.query('"public frame"')[0]["id"], m["id"])
        self.a.recover(rebuild=True)
        self.a.recover(rebuild=True)
        self.assertEqual(len(self.a.query("public")), 1)
        self.assertEqual(self.cli("replay", m["id"], "--speed", "1000").stdout,
                         b"\x1b[2J\x1b[Hpublic frame\n")
        for p in self.root.rglob("*"):
            self.assertEqual(p.stat().st_mode & 0o777, 0o700 if p.is_dir() else 0o600)
        # SQLite isn't the original: remove the derived index and restore it.
        (self.root / "index.sqlite3").unlink()
        self.a.recover(rebuild=True)
        self.assertEqual(self.a.query("public")[0]["id"], m["id"])

    def test_crash_recovery_unpaired_tail_and_live_owner(self):
        m = self.a.begin(kind="command", source="diagnostic", label="demo", pid=os.getpid(), capture=True)
        self.a.append(m, b"public\n", .01)
        path = self.a.events / m["id"]
        with (path / "output.raw").open("ab") as f:
            f.write(b"unpaired tail")
        self.assertEqual(self.a.recover(), 0)
        m["owner_fingerprint"] = "dead-test-owner"
        atomic_json(path / "manifest.json", m)
        self.assertEqual(self.a.recover(), 1)
        self.assertEqual(self.a.recover(), 0)
        restored = json.loads((path / "manifest.json").read_text())
        self.assertEqual(restored["state"], "interrupted")
        self.assertIsNone(restored["exit_code"])
        self.assertEqual(self.a.read(restored, "output"), b"public\n")

    def test_metadata_only_exclusions_no_canary_on_disk(self):
        canary = "PUBLIC_SYNTHETIC_DO_NOT_ARCHIVE_12345"
        result = self.cli("run", "/usr/bin/printf", "%s", canary)
        self.assertEqual(result.stdout.decode(), canary)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.a.query()[0]["coverage"], "metadata-only")
        for p in self.root.rglob("*"):
            if p.is_file():
                self.assertNotIn(canary.encode(), p.read_bytes())
        for p in self.root.glob("events/*/manifest.json"):
            m = json.loads(p.read_text())
            for name in m["files"]:
                self.assertNotIn(canary.encode(), self.a.read(m, name))
        self.assertEqual(self.cli("run", "false").returncode, 1)

    def test_capture_demo_stderr_screen_and_exit_status(self):
        result = self.cli("run", "demo")
        self.assertEqual(result.returncode, 0, result.stderr)
        m = json.loads((self.root / self.a.query("demo")[0]["manifest"]).read_text())
        raw = self.a.read(m, "output")
        self.assertIn(b"FSM stderr fixture", raw)
        self.assertIn(b"\x1b[Hframe 2", raw)
        self.assertNotIn(b"\x1b", self.a.query("frame")[0]["label"].encode())
        self.assertEqual(self.cli("replay", m["id"], "--speed", "1000").stdout, raw)

    def test_quota_retention_truncation_active_preserved(self):
        self.a.config["event_bytes"] = 4
        m = self.a.begin(kind="command", source="diagnostic", label="demo", pid=os.getpid(), capture=True)
        self.a.append(m, b"abcd", .01)
        self.a.append(m, b"excess", .01)
        self.a.append(m, b"x", .01)
        self.a.finish(m, 0)
        self.assertEqual(self.a.read(m, "output"), b"abcd")
        self.assertEqual(m["coverage"], "truncated")
        live = self.a.begin(kind="session", source="bash", label="shell", pid=os.getpid())
        m["ended"] = time.time() - 40 * 86400
        atomic_json(self.a.events / m["id"] / "manifest.json", m)
        self.a.recover()
        self.assertFalse((self.a.events / m["id"]).exists())
        self.assertTrue((self.a.events / live["id"]).exists())
        self.assertEqual(self.a.query(), [])
        sealed = self.event(b"safe")
        self.a.config["quota_bytes"] = 1
        with self.a.lock():
            self.a._maintain()
        self.assertFalse((self.a.events / sealed["id"]).exists())
        self.assertTrue((self.a.events / live["id"]).exists())

    def test_filters_and_tamper_fail_closed(self):
        m = self.event()
        self.assertEqual(len(self.a.query("public", source="diagnostic")), 1)
        self.assertEqual(self.a.query("public", source="bash"), [])
        self.assertEqual(self.a.query(since=time.time() + 10), [])
        (self.a.events / m["id"] / "output.zst").write_bytes(b"bad")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.a.read(m, "output")
        with self.assertRaises(ValueError):
            self.a.begin(kind="command", source="chatgpt", label="excluded", pid=1)

    def test_disable_no_new_record_and_restore(self):
        self.assertEqual(self.cli("disable").returncode, 0)
        result = self.cli("run", "date")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.a.query(), [])
        self.assertEqual(self.cli("enable").returncode, 0)
        self.assertEqual(self.cli("run", "date").returncode, 0)
        self.assertEqual(len(self.a.query()), 1)


class LocalSourcesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.root = self.home / "archive"
        self.a = Archive(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def completed(argv, stdout="", returncode=0, **_kwargs):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")

    def test_journal_cursor_duplicate_resume_output_and_classification(self):
        public = "PUBLIC_SYSTEMD_STREAM_P36"
        entries = [
            {"__CURSOR": "cursor-a", "__REALTIME_TIMESTAMP": "1000000", "_BOOT_ID": "boot",
             "_PID": "41", "_SYSTEMD_UNIT": "fsm-p36.service",
             "_SYSTEMD_INVOCATION_ID": "invocation-1", "_COMM": "printf", "MESSAGE": public},
            {"__CURSOR": "cursor-b", "__REALTIME_TIMESTAMP": "2000000", "_BOOT_ID": "boot",
             "_PID": "1", "UNIT": "fsm-p36.service", "INVOCATION_ID": "invocation-1",
             "_COMM": "systemd", "MESSAGE": "process exited code=0/SUCCESS", "EXIT_STATUS": "0"},
        ]
        calls = []

        def first(argv, **kwargs):
            calls.append(argv)
            return self.completed(argv, "\n".join(json.dumps(item) for item in entries), **kwargs)

        result = collect_journal(self.a, scope="system", unit="fsm-p36.service",
                                 include_output=True, runner=first)
        self.assertEqual((result["inserted"], result["content_events"]), (2, 1))
        self.assertIn("--since", calls[0])
        manifests = [json.loads(p.read_text()) for p in self.root.glob("events/*/manifest.json")]
        stream = next(m for m in manifests if m["coverage"] == "journal-stream")
        self.assertEqual(self.a.read(stream, "output"), (public + "\n").encode())
        self.assertEqual(stream["metadata"]["argv"], "filtered-to-executable-basename")
        self.assertTrue(stream["consent"]["explicit"])
        self.assertTrue(stream["residual_risk"])
        self.assertTrue(stream["content_gaps"])
        self.assertIsNone(stream["parent_pid"])
        exited = next(m for m in manifests if m["exit_code"] == 0)
        self.assertEqual(stream["correlation"], exited["correlation"])

        def resumed(argv, **kwargs):
            self.assertIn("--after-cursor", argv)
            self.assertEqual(argv[argv.index("--after-cursor") + 1], "cursor-b")
            return self.completed(argv, "", **kwargs)

        resumed_result = collect_journal(self.a, scope="system", unit="fsm-p36.service",
                                         include_output=True, runner=resumed)
        self.assertEqual(resumed_result["inserted"], 0)
        state_path = self.root / "local-source-cursors.json"
        state = json.loads(state_path.read_text())
        state["journals"].clear()
        state_path.write_text(json.dumps(state))
        duplicate = collect_journal(self.a, scope="system", unit="fsm-p36.service",
                                    include_output=True, runner=first)
        self.assertEqual((duplicate["inserted"], duplicate["duplicates"]), (0, 2))
        self.assertEqual(len(list(self.root.glob("events/*/manifest.json"))), 2)

    def test_user_unit_field_precedes_system_user_manager_scope(self):
        entry = {"__CURSOR": "user-a", "__REALTIME_TIMESTAMP": "4000000", "_PID": "62",
                 "_SYSTEMD_UNIT": "user@1000.service", "_SYSTEMD_USER_UNIT": "fixture.service",
                 "_SYSTEMD_INVOCATION_ID": "user-invocation", "_COMM": "printf",
                 "MESSAGE": "PUBLIC_USER_STREAM_P36"}
        runner = lambda argv, **kwargs: self.completed(argv, json.dumps(entry), **kwargs)
        result = collect_journal(self.a, scope="user", unit="fixture.service",
                                 include_output=True, runner=runner)
        self.assertEqual(result["content_events"], 1)
        manifest = json.loads(next(self.root.glob("events/*/manifest.json")).read_text())
        self.assertEqual(manifest["coverage"], "journal-stream")

    def test_journal_sensitive_output_and_cron_are_metadata_only(self):
        entry = {"__CURSOR": "cron-a", "__REALTIME_TIMESTAMP": "3000000", "_PID": "52",
                 "_SYSTEMD_UNIT": "crond.service", "_COMM": "crond",
                 "MESSAGE": "token=PUBLIC_SYNTHETIC_REDACTED_P36"}
        runner = lambda argv, **kwargs: self.completed(argv, json.dumps(entry), **kwargs)
        result = collect_journal(self.a, scope="system", unit="crond.service",
                                 include_output=True, runner=runner)
        self.assertEqual(result["source"], "cron")
        manifest = json.loads(next(self.root.glob("events/*/manifest.json")).read_text())
        self.assertEqual(manifest["coverage"], "metadata-only")
        self.assertEqual(manifest["content_gap"], "recognizable-sensitive-output")
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"PUBLIC_SYNTHETIC_REDACTED_P36", path.read_bytes())

    def test_podman_native_metadata_parser_and_dedup(self):
        line = json.dumps({"Type": "container", "Status": "start", "ID": "public-container-id",
                           "TimeNano": 4_000_000_000, "Actor": {"Attributes": {
                               "name": "fixture", "image": "localhost/public-fixture:latest",
                               "private-label": "never-persist"}}})
        parsed = parse_podman_events(line)
        self.assertEqual(parsed[0]["metadata"]["name"], "fixture")
        self.assertNotIn("private-label", parsed[0]["metadata"])
        runner = lambda argv, **kwargs: self.completed(argv, line, **kwargs)
        first = collect_podman(self.a, runner=runner)
        second = collect_podman(self.a, runner=runner)
        self.assertEqual((first["inserted"], second["duplicates"]), (1, 1))
        manifest = json.loads(next(self.root.glob("events/*/manifest.json")).read_text())
        self.assertEqual(manifest["coverage"], "metadata-only")
        self.assertNotIn("private-label", json.dumps(manifest))

    def test_inventory_classifies_every_required_source_without_opening_content(self):
        (self.home / ".config/Google/AndroidStudioFixture").mkdir(parents=True)
        repo = self.home / "repo"
        (repo / ".git/hooks").mkdir(parents=True)
        (repo / ".git/hooks/pre-commit").write_text("PRIVATE_FIXTURE_CONTENT_NEVER_READ")
        with mock.patch("fedora_system_monitor.capsules.execution_archive.local_sources._present",
                        side_effect=lambda command: command in {"systemctl", "journalctl", "podman", "auditctl"}):
            result = inventory(self.home, repo)
        sources = {item["source"]: item for item in result["sources"]}
        expected = {"systemd-system", "systemd-user", "timers", "cron-anacron", "udev",
                    "autostart", "git-hooks", "podman", "docker", "ide-gradle",
                    "chrome-native-messaging", "launchers", "auditd-ebpf"}
        self.assertEqual(set(sources), expected)
        self.assertIn("NOT COVERED", sources["chrome-native-messaging"]["coverage"])
        self.assertIn("NOT ENABLED", sources["auditd-ebpf"]["coverage"])
        self.assertNotIn("PRIVATE_FIXTURE_CONTENT_NEVER_READ", json.dumps(result))

    def test_inventory_resolves_linked_worktree_common_git_hooks(self):
        repo = self.home / "linked"
        common = self.home / "common"
        repo.mkdir()
        (repo / ".git").write_text("gitdir: elsewhere")
        (common / "hooks").mkdir(parents=True)
        (common / "hooks/pre-push").write_text("PRIVATE_HOOK_BODY")

        def runner(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout=str(common) + "\n", stderr="")

        with mock.patch("fedora_system_monitor.capsules.execution_archive.local_sources._run", runner), \
             mock.patch("fedora_system_monitor.capsules.execution_archive.local_sources._present", return_value=True):
            result = inventory(self.home, repo)
        hooks = next(item for item in result["sources"] if item["source"] == "git-hooks")
        self.assertTrue(hooks["present"])
        self.assertEqual(hooks["count"], 1)
        self.assertNotIn("PRIVATE_HOOK_BODY", json.dumps(result))

    def test_wrapper_records_pid_parent_exit_and_archiver_failure_is_fail_open(self):
        for source, name in (("git-hook", "pre-commit"), ("ide", "gradle-fixture"),
                             ("launcher", "launcher-fixture")):
            self.assertEqual(run_wrapped(self.root, source, name, ["/usr/bin/true"]), 0)
        manifests = [json.loads(p.read_text()) for p in self.root.glob("events/*/manifest.json")]
        self.assertEqual({m["source"] for m in manifests}, {"git-hook", "ide", "launcher"})
        for manifest in manifests:
            self.assertGreater(manifest["pid"], 0)
            self.assertEqual(manifest["parent_pid"], os.getpid())
            self.assertEqual(manifest["exit_code"], 0)
            self.assertEqual(manifest["coverage"], "metadata-only")
        broken = self.home / "not-a-directory"
        broken.write_text("fixture")
        self.assertEqual(run_wrapped(broken, "launcher", "fixture", ["/usr/bin/true"]), 0)
        with mock.patch.object(Archive, "record_external", side_effect=sqlite3.OperationalError("fixture")):
            self.assertEqual(run_wrapped(self.home / "sqlite-failure", "ide", "fixture",
                                         ["/usr/bin/true"]), 0)


class RemoteSourcesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.root = self.home / "archive"
        self.bin = self.home / "bin"
        self.bin.mkdir()
        self.env = os.environ | {"PYTHONPATH": str(REPO / "src"),
                                 "PATH": str(self.bin) + os.pathsep + os.environ["PATH"]}

    def tearDown(self):
        self.tmp.cleanup()

    def executable(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o700)
        return path

    def cli(self, *args, root=None):
        return subprocess.run([sys.executable, "-m", MODULE, "--root", str(root or self.root),
                               "--json", *args], env=self.env, cwd=self.home,
                              capture_output=True, timeout=20)

    def manifests(self):
        return [json.loads(path.read_text()) for path in self.root.glob("events/*/manifest.json")]

    def test_ssh_and_adb_authentic_streams_metadata_fts_replay_and_exit(self):
        self.executable("ssh", "printf 'PUBLIC_P37_SSH_STDOUT\\n'; printf 'PUBLIC_P37_SSH_STDERR\\n' >&2; exit 7\n")
        self.executable("adb", """
if [ "$1" = devices ]; then
  printf 'List of devices attached\\nPUBLIC-DEVICE-37\\tdevice\\n'
  exit 0
fi
printf 'PUBLIC_P37_ADB_STDOUT\\n'; printf 'PUBLIC_P37_ADB_STDERR\\n' >&2
""")
        ssh = self.cli("remote", "ssh", "--target", "oracle-fixture", "--include-output",
                       "--", "/usr/bin/printf", "public")
        self.assertEqual(ssh.returncode, 7, ssh.stderr)
        self.assertIn(b"PUBLIC_P37_SSH_STDOUT", ssh.stdout)
        self.assertIn(b"PUBLIC_P37_SSH_STDERR", ssh.stderr)
        adb = self.cli("remote", "adb", "--include-output", "--", "/system/bin/printf", "public")
        self.assertEqual(adb.returncode, 0, adb.stderr)
        manifests = self.manifests()
        self.assertEqual({m["source"] for m in manifests}, {"ssh", "adb"})
        archive = Archive(self.root)
        for manifest in manifests:
            self.assertEqual(manifest["coverage"], "remote-streams")
            self.assertIn("stdout", manifest["files"])
            self.assertIn("stderr", manifest["files"])
            self.assertIn("timing", manifest["files"])
            self.assertEqual(manifest["input"], "closed-not-recorded")
            self.assertEqual(manifest["metadata"]["argv"], "filtered-to-executable-basename")
            replay = self.cli("replay", manifest["id"], "--speed", "1000")
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertEqual(replay.stdout, archive.read(manifest, "output"))
        ssh_manifest = next(m for m in manifests if m["source"] == "ssh")
        adb_manifest = next(m for m in manifests if m["source"] == "adb")
        self.assertEqual(ssh_manifest["exit_code"], 7)
        self.assertEqual(ssh_manifest["metadata"]["remote_host"], "oracle-fixture")
        self.assertEqual(adb_manifest["exit_code"], 0)
        self.assertEqual(adb_manifest["metadata"]["device_serial_sha256"],
                         hashlib.sha256(b"PUBLIC-DEVICE-37").hexdigest())
        self.assertNotIn("PUBLIC-DEVICE-37", json.dumps(adb_manifest))
        self.assertTrue(archive.query("PUBLIC_P37", source="ssh"))
        self.assertTrue(archive.query("PUBLIC_P37", source="adb"))
        self.assertTrue(archive.query('"oracle-fixture"', source="ssh"))

    def test_ssh_remote_command_preserves_argv_boundaries(self):
        command = ["/usr/bin/python3", "-c", "print('public value')"]
        argv, _metadata = _transport_argv("ssh", command, target="oracle-fixture",
                                          device_sha256=None)
        self.assertEqual(argv[-1], shlex.join(command))
        self.assertEqual(argv[-2], "oracle-fixture")
        runner = lambda args, **_kwargs: subprocess.CompletedProcess(
            args, 0, stdout="List of devices attached\nPUBLIC-DEVICE-37\tdevice\n", stderr="")
        adb_argv, _metadata = _transport_argv("adb", command, target=None,
                                              device_sha256=None, runner=runner)
        self.assertEqual(adb_argv[-1], shlex.join(command))

    def test_sensitive_stream_disabled_and_storage_failure_do_not_block_commands(self):
        marker = "PUBLIC_P37_REDACTED_STREAM"
        self.executable("ssh", f"printf 'token={marker}\\n'; exit 0\n")
        result = self.cli("remote", "ssh", "--target", "safe-alias", "--include-output",
                          "--", "/usr/bin/printf", "public")
        self.assertEqual(result.returncode, 0)
        manifest = self.manifests()[0]
        self.assertEqual(manifest["coverage"], "metadata-only")
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(marker.encode(), path.read_bytes())
        broken = self.home / "not-a-directory"
        broken.write_text("fixture")
        fail_open = self.cli("remote", "ssh", "--target", "safe-alias", "--",
                             "/usr/bin/true", root=broken)
        self.assertEqual(fail_open.returncode, 0)

    def test_disable_runs_transport_without_new_event_then_enable_restores(self):
        self.executable("ssh", "printf 'PUBLIC_DISABLED_REMOTE\\n'; exit 0\n")
        self.assertEqual(self.cli("disable").returncode, 0)
        result = self.cli("remote", "ssh", "--target", "safe-alias", "--include-output",
                          "--", "/usr/bin/printf", "public")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.manifests(), [])
        self.assertEqual(self.cli("enable").returncode, 0)
        self.assertEqual(self.cli("remote", "ssh", "--target", "safe-alias", "--",
                                  "/usr/bin/true").returncode, 0)
        self.assertEqual(len(self.manifests()), 1)

    def test_github_run_log_metadata_digest_dedup_and_no_fake_replay(self):
        metadata = {"id": 37001, "run_attempt": 1, "name": "CI", "event": "push",
                    "status": "completed", "conclusion": "success", "head_sha": "a" * 40,
                    "created_at": "2026-10-12T00:00:00Z", "updated_at": "2026-10-12T00:01:00Z",
                    "run_started_at": "2026-10-12T00:00:01Z"}
        log = b"build\tverify\t2026-10-12T00:00:02Z PUBLIC_P37_GITHUB_LOG\n"

        def runner(argv, **_kwargs):
            if argv[1] == "api":
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(metadata), stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout=log, stderr=b"")

        archive = Archive(self.root)
        first = ingest_github_run(archive, repo="owner/repo", run_id=37001,
                                  include_logs=True, runner=runner)
        second = ingest_github_run(archive, repo="owner/repo", run_id=37001,
                                   include_logs=True, runner=runner)
        self.assertEqual((first["inserted"], second["duplicates"]), (1, 1))
        self.assertEqual(first["log_sha256"], hashlib.sha256(log).hexdigest())
        manifest = self.manifests()[0]
        self.assertEqual(manifest["coverage"], "runner-log")
        self.assertIn("output", manifest["files"])
        self.assertNotIn("timing", manifest["files"])
        self.assertTrue(archive.query("PUBLIC_P37_GITHUB_LOG", source="github-actions"))
        self.assertTrue(archive.query("37001", source="github-actions"))
        replay = self.cli("replay", manifest["id"])
        self.assertNotEqual(replay.returncode, 0)

    def test_github_masked_or_sensitive_log_is_metadata_only(self):
        metadata = {"id": 37002, "run_attempt": 1, "name": "CI", "event": "push",
                    "status": "completed", "conclusion": "success", "head_sha": "b" * 40,
                    "created_at": "2026-10-12T00:00:00Z", "updated_at": "2026-10-12T00:02:00Z"}
        marker = b"PUBLIC_P37_MASKED_MATERIAL"

        def runner(argv, **_kwargs):
            if argv[1] == "api":
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(metadata), stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout=b"value=*** " + marker, stderr=b"")

        result = ingest_github_run(Archive(self.root), repo="owner/repo", run_id=37002,
                                   include_logs=True, runner=runner)
        self.assertEqual(result["coverage"], "metadata-only")
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(marker, path.read_bytes())

    def test_remote_crash_recovers_durable_stream_once(self):
        self.executable("ssh", "printf 'PUBLIC_P37_CRASH_FRAME\\n'; head -c 9000 /dev/zero | tr '\\000' x; exec sleep 10\n")
        argv = [sys.executable, "-m", MODULE, "--root", str(self.root), "--json",
                "remote", "ssh", "--target", "safe-alias", "--include-output",
                "--", "/usr/bin/printf", "public"]
        proc = subprocess.Popen(argv, env=self.env, cwd=self.home,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        manifest = None
        try:
            while time.monotonic() < deadline:
                paths = list(self.root.glob("events/*/manifest.json"))
                if paths and list(self.root.glob("events/*/output.raw")):
                    manifest = json.loads(paths[0].read_text())
                    break
                time.sleep(.02)
            self.assertIsNotNone(manifest)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            if manifest:
                try:
                    os.kill(manifest["transport_pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
        archive = Archive(self.root)
        self.assertEqual(archive.recover(), 1)
        self.assertEqual(archive.recover(), 0)
        recovered = json.loads(next(self.root.glob("events/*/manifest.json")).read_text())
        self.assertEqual(recovered["state"], "interrupted")
        self.assertIsNone(recovered["exit_code"])
        self.assertIn(b"PUBLIC_P37_CRASH_FRAME", archive.read(recovered, "output"))

    def test_remote_inventory_is_complete_and_explicit(self):
        sources = {item["source"]: item for item in remote_inventory()["sources"]}
        self.assertEqual(set(sources), {"ssh", "github-actions", "adb"})
        self.assertIn("remote PID NOT COVERED", sources["ssh"]["coverage"])
        self.assertIn("replay NOT COVERED", sources["github-actions"]["coverage"])


class ProcessAdapterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.root = self.home / "archive"
        self.a = Archive(self.root)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("FSM_EA_")} | {
            "PYTHONPATH": str(REPO / "src"), "HOME": str(self.home)}

    def tearDown(self):
        self.tmp.cleanup()

    def command(self, source, command, **kwargs):
        argv = [sys.executable, "-m", PROCESS_MODULE, "--source", source,
                "--root", str(self.root), "--", "-l", "-c", command]
        return subprocess.run(argv, cwd=self.home, env=self.env, timeout=20, **kwargs)

    def manifests(self):
        return [json.loads(p.read_text()) for p in self.root.glob("events/*/manifest.json")]

    def test_command_name_skips_assignments_and_prefixes(self):
        self.assertEqual(_command_name("TOKEN=synthetic-canary printf safe"), "printf")
        self.assertEqual(_command_name("env TOKEN=synthetic-canary printf safe"), "printf")
        self.assertEqual(_command_name("command nohup COLOR=blue /usr/bin/printf safe"), "printf")

    def test_rdc_separated_streams_over_4k_child_fts_and_replay(self):
        program = ("import os,subprocess;"
                   "os.write(1,b'PUBLIC_STDOUT_START\\n'+b'o'*5000+b'\\n');"
                   "os.write(2,b'PUBLIC_STDERR_START\\n'+b'e'*5000+b'\\n');"
                   "subprocess.run(['/usr/bin/printf','PUBLIC_CHILD_FRAME\\n'])")
        result = self.command("rdc", f"{shlex.quote(sys.executable)} -c {shlex.quote(program)}",
                              capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreater(len(result.stdout) + len(result.stderr), 10_000)
        manifests = self.manifests()
        self.assertEqual(len(manifests), 1)
        m = manifests[0]
        self.assertEqual(m["source"], "rdc")
        self.assertEqual(m["parent_pid"], os.getpid())
        self.assertNotEqual(m["child_pid"], m["pid"])
        self.assertEqual(self.a.read(m, "stdout"), result.stdout)
        self.assertEqual(self.a.read(m, "stderr"), result.stderr)
        combined = self.a.read(m, "output")
        self.assertIn(b"PUBLIC_CHILD_FRAME", combined)
        self.assertTrue(self.a.query('"PUBLIC_CHILD_FRAME"', source="rdc"))
        filtered = subprocess.run([sys.executable, "-m", MODULE, "--root", str(self.root),
                                   "search", '"PUBLIC_CHILD_FRAME"', "--source", "rdc"],
                                  env=self.env, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(filtered.stdout)[0]["id"], m["id"])
        replay = subprocess.check_output([sys.executable, "-m", MODULE, "--root", str(self.root),
                                          "replay", m["id"], "--speed", "1000"], env=self.env)
        self.assertEqual(replay, combined)

    def test_long_running_input_is_forwarded_but_never_archived(self):
        program = "import sys; print('PUBLIC_READY',flush=True); print('PUBLIC_ACK:'+sys.stdin.readline().strip())"
        argv = [sys.executable, "-m", PROCESS_MODULE, "--source", "rdc",
                "--root", str(self.root), "--", "-l", "-c",
                f"{shlex.quote(sys.executable)} -c {shlex.quote(program)}"]
        proc = subprocess.Popen(argv, cwd=self.home, env=self.env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert proc.stdin is not None and proc.stdout is not None
        self.assertEqual(proc.stdout.readline(), b"PUBLIC_READY\n")
        proc.stdin.write(b"PUBLIC_INNOCUOUS_INPUT\n"); proc.stdin.flush()
        out, err = proc.communicate(timeout=10)
        self.assertEqual(proc.returncode, 0, err)
        self.assertIn(b"PUBLIC_ACK:PUBLIC_INNOCUOUS_INPUT", out)
        m = self.manifests()[0]
        self.assertEqual(m["input"], "forwarded-not-recorded")
        self.assertNotIn("input", m["files"])

    def test_nested_codex_adapter_is_one_correlated_event(self):
        inner = self.home / "fsm-ea-codex-bash"
        inner.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} -m {PROCESS_MODULE} --source codex --root {shlex.quote(str(self.root))} -- \"$@\"\n")
        inner.chmod(0o700)
        result = self.command("rdc", f"{shlex.quote(str(inner))} -lc 'printf PUBLIC_NESTED_ONCE'",
                              capture_output=True)
        self.assertEqual(result.stdout, b"PUBLIC_NESTED_ONCE")
        manifests = self.manifests()
        self.assertEqual(len(manifests), 1)
        self.assertEqual(manifests[0]["source"], "codex")
        self.assertEqual(manifests[0]["origins"], ["codex", "rdc"])
        self.assertEqual(manifests[0]["correlation"], manifests[0]["id"])

    def test_sensitive_command_and_output_fail_closed_to_metadata(self):
        command_canary = "PUBLIC_SYNTHETIC_METADATA_CANARY_64"
        output_canary = "PUBLIC_SYNTHETIC_STREAM_CANARY_64"
        secret_command = self.command(
            "rdc", f"TOKEN={command_canary} printf PUBLIC_EXCLUDED_COMMAND",
            capture_output=True)
        self.assertEqual(secret_command.stdout, b"PUBLIC_EXCLUDED_COMMAND")
        program = ("import os;"
                   "label=bytes((116,111,107,101,110,61));"
                   f"value={output_canary!r}.encode();"
                   "os.write(1,label+value+b'\\n');"
                   "os.write(2,label+value+b'\\n')")
        secret_output = self.command(
            "rdc", f"{shlex.quote(sys.executable)} -c {shlex.quote(program)}",
                                      capture_output=True)
        expected = b"token=" + output_canary.encode() + b"\n"
        self.assertEqual(secret_output.stdout, expected)
        self.assertEqual(secret_output.stderr, expected)
        manifests = self.manifests()
        self.assertEqual(len(manifests), 2)
        self.assertTrue(all(m["coverage"] == "metadata-only" for m in manifests))
        self.assertEqual({m["command_name"] for m in manifests}, {"excluded", "python3"})
        for m in manifests:
            self.assertEqual(m["files"], {})
        self.assertEqual(self.a.query(command_canary), [])
        self.assertEqual(self.a.query(output_canary), [])
        for path in self.root.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                self.assertNotIn(command_canary.encode(), data)
                self.assertNotIn(output_canary.encode(), data)

    def test_codex_hook_rewrites_only_bash_without_transcript_access(self):
        hook = REPO / "hooks/execution-archive-codex.py"
        event = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                 "tool_input": {"command": "printf PUBLIC_HOOK"},
                 "transcript_path": "/private/never-read.jsonl"}
        result = subprocess.run([sys.executable, "-I", str(hook)], input=json.dumps(event),
                                text=True, capture_output=True, cwd=self.home, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        updated = json.loads(result.stdout)["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertIn("fsm-ea-codex-bash", updated)
        self.assertNotIn("transcript", updated)


class InstallerTest(unittest.TestCase):
    def test_process_integrations_upgrade_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".bashrc").write_text("# user customization\n")
            rdc_dir = home / ".claude-server-commander"
            rdc_dir.mkdir()
            rdc_config = rdc_dir / "config.json"
            rdc_config.write_text(json.dumps({"defaultShell": "/bin/bash", "preserved": True}))
            env = os.environ | {"HOME": str(home)}
            command = [sys.executable, str(REPO / "scripts/install-execution-archive.py")]
            for _ in range(2):
                result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
            rdc = json.loads(rdc_config.read_text())
            self.assertEqual(rdc["defaultShell"], str(home / ".local/bin/fsm-ea-rdc-bash"))
            self.assertTrue(rdc["preserved"])
            hooks = json.loads((home / ".codex/hooks.json").read_text())
            handlers = [h for g in hooks["hooks"]["PreToolUse"] for h in g["hooks"]]
            self.assertEqual(sum("codex-hook.py" in h["command"] for h in handlers), 1)
            self.assertTrue((home / ".local/bin/fsm-ea-codex-bash").is_file())
            receipt = json.loads((home / ".local/state/fedora-system-monitor/executions/install-receipt.json").read_text())
            self.assertEqual(receipt["rdc_default_shell_original"], "/bin/bash")
            result = subprocess.run(command + ["--rollback"], env=env, capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(rdc_config.read_text())["defaultShell"], "/bin/bash")
            rolled = json.loads((home / ".codex/hooks.json").read_text())
            self.assertFalse(rolled.get("hooks", {}).get("PreToolUse"))
            self.assertEqual((home / ".bashrc").read_text(), "# user customization\n")
            self.assertTrue((home / ".local/state/fedora-system-monitor/executions/disabled").exists())


class BashPTYTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.root = self.home / ".local/state/fedora-system-monitor/executions"
        self.a = Archive(self.root)
        bin_dir = self.home / ".local/bin"
        bin_dir.mkdir(parents=True)
        launcher = bin_dir / "ea"
        launcher.write_text(f'#!/bin/bash\nexec {sys.executable} -m {MODULE} "$@"\n')
        launcher.chmod(0o700)
        (self.home / ".bashrc").write_text(
            f'source {REPO}/hooks/execution-archive-entry.bash\n'
            'PS1="FSM_TEST_READY> "\n'
            f'source {REPO}/hooks/execution-archive-metadata.bash "$(trap -p DEBUG)"\n')
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("FSM_EA_")} | {
            "HOME": str(self.home), "PYTHONPATH": str(REPO / "src")}
        self.children = []

    def tearDown(self):
        for proc, fd in self.children:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            os.close(fd)
        self.tmp.cleanup()

    def tab(self):
        master, slave = pty.openpty()
        proc = subprocess.Popen(["/bin/bash", "--noprofile", "-i"], env=self.env,
                                stdin=slave, stdout=slave, stderr=slave, start_new_session=True, cwd=self.home)
        os.close(slave)
        self.children.append((proc, master))
        self.until(master, b"FSM_TEST_READY> ")
        return proc, master

    def until(self, fd, marker):
        data = b""
        deadline = time.monotonic() + 10
        while marker not in data and time.monotonic() < deadline:
            if select.select([fd], [], [], .2)[0]:
                try:
                    data += os.read(fd, 65536)
                except OSError:
                    break
        self.assertIn(marker, data)
        return data

    def session(self, proc):
        for p in self.root.glob("events/*/manifest.json"):
            m = json.loads(p.read_text())
            if m["kind"] == "session" and m["parent"] is None and m["owner_pid"] == proc.pid:
                return m["id"]
        self.fail("missing shell session")

    def control(self, proc, action, **kwargs):
        result = request(self.a, self.session(proc), {"action": action} | kwargs)
        self.assertTrue(result["ok"], result)
        return result

    def originals(self):
        result = []
        for p in self.root.glob("events/*/manifest.json"):
            m = json.loads(p.read_text())
            for name in m["files"]:
                result.append((m, name, self.a.read(m, name)))
        return result

    def command(self, fd, text):
        os.write(fd, text.encode() + b"\n")
        return self.until(fd, b"FSM_TEST_READY> ")

    def test_full_generic_output_input_multiline_ansi_replay_and_runtime_levels(self):
        proc, fd = self.tab()
        self.command(fd, "printf 'SAFE_OMITTED_ORDINARY\\n'")
        state = self.control(proc, "on", input=True)
        self.assertEqual(state["level"], "full")
        shown = self.command(fd, "echo PUBLIC_ECHO_FULL; printf 'PUBLIC_PRINTF_FULL\\n'")
        self.assertIn(b"PUBLIC_PRINTF_FULL", shown)
        shown = self.command(fd, "python3 -c 'import sys; print(\"\\033[2J\\033[Hframe-public\"); [print(\"public-line-%04d\"%i) for i in range(400)]; print(\"public-stderr-line\",file=sys.stderr)'")
        self.assertGreater(len(shown), 4096)
        self.assertIn(b"public-stderr-line", shown)
        os.write(fd, b"python3 -c 'v=input(\"APP_\"+\"READY\"); print(\"PUBLIC_ACK:\"+v)'\n")
        self.until(fd, b"APP_READY")
        os.write(fd, b"PUBLIC_ORDINARY_INPUT\n")
        self.until(fd, b"FSM_TEST_READY> ")
        self.control(proc, "pause")
        self.command(fd, "printf 'PAUSED_NOT_SAVED\\n'")
        self.control(proc, "resume")
        self.command(fd, "printf 'RESUMED_SAVED\\n'")
        self.control(proc, "off")
        self.command(fd, "printf 'SAFE_AGAIN_NOT_SAVED\\n'")
        self.command(fd, "false; printf 'STATUS:%s PIPE:%s\\n' $? 0")
        os.write(fd, b"exit 0\n")
        self.assertEqual(proc.wait(timeout=10), 0)
        originals = self.originals()
        output = b"".join(raw for _m, name, raw in originals if name == "output")
        self.assertIn(b"PUBLIC_ECHO_FULL", output)
        self.assertIn(b"PUBLIC_PRINTF_FULL", output)
        self.assertIn(b"\x1b[2J\x1b[Hframe-public", output)
        self.assertIn(b"public-line-0399", output)
        self.assertIn(b"public-stderr-line", output)
        self.assertIn(b"RESUMED_SAVED", output)
        for canary in (b"SAFE_OMITTED_ORDINARY", b"PAUSED_NOT_SAVED", b"SAFE_AGAIN_NOT_SAVED"):
            self.assertNotIn(canary, output)
        self.assertTrue(self.a.query("PUBLIC_PRINTF_FULL"))
        self.assertTrue(self.a.query('"public-line-0399"'))
        inputs = b"".join(raw for _m, name, raw in originals if name == "input")
        self.assertIn(b"PUBLIC_ORDINARY_INPUT\n", inputs)
        for m, name, raw in originals:
            if name != "output":
                continue
            replay = subprocess.check_output([sys.executable, "-m", MODULE, "--root", str(self.root),
                                              "replay", m["id"], "--speed", "1000"], env=self.env)
            self.assertEqual(replay, raw)
            self.assertEqual(m["streams"], "pty-output-and-echo-inseparable")
            self.assertTrue(m["consent"]["explicit"])

    def test_full_hidden_sensitive_paths_and_output_canaries_excluded(self):
        proc, fd = self.tab()
        self.control(proc, "on", input=True)
        self.command(fd, "echo public_before_guard")
        os.write(fd, b"read -s -p 'HIDDEN_READY' value; printf '\\n'; unset value\n")
        self.until(fd, b"HIDDEN_READY")
        os.write(fd, b"PUBLIC_SYNTHETIC_HIDDEN_48\n")
        self.until(fd, b"FSM_TEST_READY> ")
        self.command(fd, "printf 'token=PUBLIC_SYNTHETIC_TOKEN_48\\n'")
        # A generic executable toggles ECHO, without a recognizable command name.
        reader = self.home / "public-reader.py"
        reader.write_text('import sys,termios\nt=termios.tcgetattr(0); t[3]&=~termios.ECHO; termios.tcsetattr(0,termios.TCSANOW,t)\nprint("DYNAMIC_HIDDEN_READY",flush=True)\nv=sys.stdin.readline();t[3]|=termios.ECHO;termios.tcsetattr(0,termios.TCSANOW,t)\nprint(v,flush=True)\n')
        os.write(fd, f"python3 {reader}\n".encode())
        self.until(fd, b"DYNAMIC_HIDDEN_READY")
        os.write(fd, b"PUBLIC_SYNTHETIC_DYNAMIC_48\n")
        self.until(fd, b"FSM_TEST_READY> ")
        sensitive = self.home / "private-path"
        sensitive.mkdir()
        atomic_json(self.root / "capture-policy.json", {"sensitive_paths": [str(sensitive)]})
        self.command(fd, f"cd {sensitive}")
        self.command(fd, "printf 'PUBLIC_PATH_EXCLUDED_48\\n'")
        self.command(fd, f"cd {self.home}")
        self.command(fd, "echo public_after_guard")
        self.control(proc, "off")
        os.write(fd, b"exit 0\n")
        proc.wait(timeout=10)
        canaries = (b"PUBLIC_SYNTHETIC_HIDDEN_48", b"PUBLIC_SYNTHETIC_TOKEN_48",
                    b"PUBLIC_SYNTHETIC_DYNAMIC_48", b"PUBLIC_PATH_EXCLUDED_48")
        for _m, _name, raw in self.originals():
            for marker in canaries:
                self.assertNotIn(marker, raw)
        for marker in canaries:
            self.assertEqual(self.a.query(marker.decode()), [])
            for path in self.root.rglob("*"):
                if path.is_file():
                    self.assertNotIn(marker, path.read_bytes())
        self.assertTrue(self.a.query("public_after_guard"))

    def test_new_session_defaults_persistent_consent_scope_and_crash(self):
        proc, fd = self.tab()
        self.assertEqual(self.control(proc, "status")["level"], "safe")
        # Persistent consent is tested ONLY inside this disposable HOME/root.
        command = [sys.executable, "-m", MODULE, "--root", str(self.root), "capture", "on", "--new-sessions"]
        self.assertNotEqual(subprocess.run(command, env=self.env, capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(command + ["--consent"], env=self.env, capture_output=True).returncode, 0)
        self.assertEqual(self.control(proc, "status")["level"], "safe")
        full, ffd = self.tab()
        self.assertEqual(self.control(full, "status")["level"], "full")
        self.command(ffd, "echo PUBLIC_NEW_SESSION_FULL")
        # Crash while a content segment is open. Recover both session and stream.
        os.write(ffd, b"python3 -c 'import time; print(\"CRASH_\"+\"PUBLIC_FRAME\",flush=True); time.sleep(10)'\n")
        self.until(ffd, b"CRASH_PUBLIC_FRAME")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if any(b"CRASH_PUBLIC_FRAME" in p.read_bytes() for p in self.root.glob("events/*/output.raw")):
                break
            time.sleep(.005)
        else:
            self.fail("crash fixture did not reach durable spool")
        full.kill(); full.wait(timeout=5)
        for path in self.root.glob("events/*/manifest.json"):
            m = json.loads(path.read_text())
            if m["parent"] is None and m["owner_pid"] == full.pid:
                try:
                    os.killpg(m["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.assertGreaterEqual(self.a.recover(), 1)
        self.assertEqual(self.a.recover(), 0)
        self.assertTrue(self.a.query("PUBLIC_NEW_SESSION_FULL"))
        self.assertTrue(self.a.query("CRASH_PUBLIC_FRAME"))
        revoke = command[:-2] + ["off", "--new-sessions"]
        self.assertEqual(subprocess.run(revoke, env=self.env, capture_output=True).returncode, 0)
        safe, sfd = self.tab()
        self.assertEqual(self.control(safe, "status")["level"], "safe")
        for p, tab in ((proc, fd), (safe, sfd)):
            os.write(tab, b"exit\n"); p.wait(timeout=10)

    def test_full_storage_failure_preserves_terminal(self):
        proc, fd = self.tab()
        self.control(proc, "on")
        self.command(fd, "echo BEFORE_STORAGE_FAILURE_PUBLIC")
        (self.root / "capture-policy.json").write_text("invalid-json")
        shown = self.command(fd, "printf 'AFTER_STORAGE_FAILURE_PUBLIC\\n'")
        self.assertIn(b"AFTER_STORAGE_FAILURE_PUBLIC", shown)
        os.write(fd, b"exit 0\n")
        self.assertEqual(proc.wait(timeout=10), 0)
        self.assertTrue(self.a.query("BEFORE_STORAGE_FAILURE_PUBLIC"))
        self.assertFalse(self.a.query("AFTER_STORAGE_FAILURE_PUBLIC"))

    def test_profile_consent_and_guard_refusal(self):
        cmd = [sys.executable, "-m", MODULE, "--root", str(self.root),
               "capture", "on", "--new-sessions", "--consent", "--profile", "qa"]
        self.assertEqual(subprocess.run(cmd, env=self.env, capture_output=True).returncode, 0)
        safe, fd = self.tab()
        self.assertEqual(self.control(safe, "status")["level"], "safe")
        self.env["FSM_EA_PROFILE"] = "qa"
        full, ffd = self.tab()
        self.assertEqual(self.control(full, "status")["level"], "full")
        self.command(ffd, "echo PROFILE_PUBLIC_FULL")
        for p, f in ((safe, fd), (full, ffd)):
            os.write(f, b"exit\n"); p.wait(timeout=10)
        rc = self.home / ".bashrc"
        rc.write_text(rc.read_text().replace('PS1="FSM_TEST_READY> "',
                                            'PS1="FSM_TEST_READY> "\ntrap ":" DEBUG'))
        unavailable, ufd = self.tab()
        result = request(self.a, self.session(unavailable), {"action": "on"})
        self.assertFalse(result["ok"])
        self.assertIn(b"GUARD_PUBLIC_CONTINUES", self.command(ufd, "echo GUARD_PUBLIC_CONTINUES"))
        os.write(ufd, b"exit\n"); unavailable.wait(timeout=10)

    def test_two_concurrent_tabs_normal_input_hidden_input_and_safe_capture(self):
        p1, t1 = self.tab()
        p2, t2 = self.tab()
        self.assertEqual(self.a.status()["active"], 2)
        os.write(t1, b"printf 'ordinary input\\n'; printf 'stderr output\\n' >&2\n")
        shown = self.until(t1, b"FSM_TEST_READY> ")
        self.assertIn(b"ordinary input", shown)
        self.assertIn(b"stderr output", shown)
        os.write(t2, b"date\n")
        self.until(t2, b"FSM_TEST_READY> ")
        os.write(t1, b"read -s -p 'HIDDEN_READY' value; unset value; printf '\\n'\n")
        self.until(t1, b"HIDDEN_READY")
        os.write(t1, b"PUBLIC_SYNTHETIC_HIDDEN_CANARY\n")
        self.until(t1, b"FSM_TEST_READY> ")
        # Verify command status, pipeline status, tty and recursion in a nested shell.
        os.write(t1, b"false; printf 'RESULT:%s\\n' $?; test -t 0; printf 'TTY:%s\\n' $?\n")
        shown = self.until(t1, b"FSM_TEST_READY> ")
        self.assertIn(b"RESULT:1", shown)
        self.assertIn(b"TTY:0", shown)
        os.write(t2, b"bash --noprofile -i\n")
        self.until(t2, b"FSM_TEST_READY> ")
        self.assertEqual(sum(json.loads(p.read_text())["kind"] == "session"
                             for p in self.root.glob("events/*/manifest.json")), 2)
        os.write(t2, b"exit\n")
        self.until(t2, b"FSM_TEST_READY> ")
        os.write(t1, b"exit 7\n")
        os.write(t2, b"exit 0\n")
        self.assertEqual(p1.wait(timeout=10), 7)
        self.assertEqual(p2.wait(timeout=10), 0)
        rows = self.a.query(limit=200)
        self.assertTrue(any(r["label"] == "date" and r["coverage"] == "output-only" for r in rows))
        self.assertTrue(any(r["label"] == "excluded" for r in rows))
        self.assertEqual(self.a.status()["active"], 0)
        for p in self.root.rglob("*"):
            if p.is_file():
                self.assertNotIn(b"PUBLIC_SYNTHETIC_HIDDEN_CANARY", p.read_bytes())
                self.assertNotIn(b"ordinary input", p.read_bytes())
        for p in self.root.glob("events/*/manifest.json"):
            m = json.loads(p.read_text())
            for name in m["files"]:
                raw = self.a.read(m, name)
                self.assertNotIn(b"PUBLIC_SYNTHETIC_HIDDEN_CANARY", raw)
                self.assertNotIn(b"ordinary input", raw)

    def test_noninteractive_shell_and_crash_recovery(self):
        proc = subprocess.run(["bash", "-c", "printf noninteractive"], env=self.env,
                              capture_output=True, timeout=5)
        self.assertEqual(proc.stdout, b"noninteractive")
        self.assertEqual(list(self.a.events.iterdir()), [])
        p, fd = self.tab()
        p.kill()
        p.wait(timeout=5)
        # The wrapper owns the inner shell process group: clean up this test only.
        manifests = [json.loads(x.read_text()) for x in self.root.glob("events/*/manifest.json")]
        for m in manifests:
            if m["kind"] == "session":
                try:
                    os.killpg(m["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.assertGreaterEqual(self.a.recover(), 1)
        self.assertEqual(self.a.recover(), 0)

    def test_existing_prompt_debug_alias_and_custom_command_preserved(self):
        rc = self.home / ".bashrc"
        text = rc.read_text()
        text = text.replace('PS1="FSM_TEST_READY> "',
                            'PS1="FSM_TEST_READY> "\n'
                            'PROMPT_COMMAND="printf CUSTOM_PROMPT"\n'
                            'alias date="printf CUSTOM_DATE"\n'
                            "trap ':' DEBUG")
        rc.write_text(text)
        p, fd = self.tab()
        os.write(fd, b"date; false; printf 'STATUS:%s\\n' $?\n")
        shown = self.until(fd, b"FSM_TEST_READY> ")
        self.assertIn(b"CUSTOM_DATE", shown)
        self.assertIn(b"CUSTOM_PROMPT", shown)
        self.assertIn(b"STATUS:1", shown)
        os.write(fd, b"exit\n")
        p.wait(timeout=10)
        master, slave = pty.openpty()
        cmd = subprocess.Popen(["bash", "--noprofile", "-ic", "printf CUSTOM_COMMAND; exit 9"],
                               env=self.env, stdin=slave, stdout=slave, stderr=slave,
                               start_new_session=True)
        os.close(slave)
        self.children.append((cmd, master))
        self.assertIn(b"CUSTOM_COMMAND", self.until(master, b"CUSTOM_COMMAND"))
        self.assertEqual(cmd.wait(timeout=10), 9)


if __name__ == "__main__":
    unittest.main()
