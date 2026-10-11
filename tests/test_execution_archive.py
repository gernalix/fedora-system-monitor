"""Execution archive gates use temporary storage and public synthetic canaries."""
import json
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from fedora_system_monitor.capsules.execution_archive import Archive, Zstd, atomic_json

REPO = Path(__file__).resolve().parent.parent
MODULE = "fedora_system_monitor.capsules.execution_archive.cli"


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
            f'source {REPO}/hooks/execution-archive-metadata.bash\n')
        self.env = os.environ | {"HOME": str(self.home), "PYTHONPATH": str(REPO / "src")}
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
                                stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
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
