from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "systemd-journal-collector.sh"
FIXTURES = ROOT / "tests" / "fixtures" / "systemd_journal_collector"


class SystemdJournalCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.system = self.root / "system"
        self.user = self.root / "user"
        self.system.mkdir()
        self.user.mkdir()
        self.calls = self.root / "journalctl-calls.jsonl"
        self.journalctl = self.root / "journalctl"
        self.journalctl.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "with open(os.environ['CALLS'], 'a', encoding='utf-8') as out: json.dump(sys.argv[1:], out); out.write('\\n')\n"
            "unit = sys.argv[sys.argv.index('-u') + 1]\n"
            "print(json.dumps({'__REALTIME_TIMESTAMP':'1700000000000000','_HOSTNAME':'fixture-host','_SYSTEMD_UNIT':unit,'_PID':'321','PRIORITY':'3','MESSAGE':'fixture message','_SYSTEMD_INVOCATION_ID':'run-123','RESULT':'success','EXIT_STATUS':'0'}))\n",
            encoding="utf-8",
        )
        self.journalctl.chmod(0o755)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def invoke(self, *args: str, registry: Path | None = None) -> subprocess.CompletedProcess[str]:
        env = os.environ | {
            "SYSTEM_UNIT_DIR": str(self.system),
            "USER_UNIT_DIR": str(self.user),
            "MEGAVAULT_REGISTRY_PATH": str(registry or self.root / "missing.sqlite"),
            "JOURNALCTL_BIN": str(self.journalctl),
            "CALLS": str(self.calls),
        }
        return subprocess.run([str(SCRIPT), *args], text=True, capture_output=True, check=True, env=env)

    def install(self, *names: str, user: bool = False) -> None:
        destination = self.user if user else self.system
        for name in names:
            shutil.copy(FIXTURES / name, destination / name)

    def calls_for_run(self) -> list[list[str]]:
        return [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines()]

    def test_discovers_custom_directories_and_builds_system_and_user_commands(self) -> None:
        self.install("backup.timer", "fixture-backup.service", "implicit.timer")
        self.install("user-sync.service", user=True)

        result = self.invoke("--recent", "6h", "--until", "2026-09-27 12:00:00", "--limit", "7")

        calls = self.calls_for_run()
        self.assertTrue(any(call[:3] == ["-u", "fixture-backup.service", "--no-pager"] for call in calls))
        user_call = next(call for call in calls if "user-sync.service" in call)
        self.assertEqual(user_call[:3], ["--user", "-u", "user-sync.service"])
        for call in calls:
            self.assertIn("--output=json", call)
            self.assertIn("--lines", call)
            self.assertIn("7", call)
            self.assertIn("--since", call)
            self.assertIn("6h ago", call)
            self.assertIn("--until", call)
        self.assertEqual(len(result.stdout.splitlines()), 5)

    def test_timer_target_is_explicit_or_systemd_default(self) -> None:
        self.install("backup.timer", "implicit.timer")

        explicit = json.loads(self.invoke("--unit", "backup.timer").stdout)
        implicit = json.loads(self.invoke("--unit", "implicit.timer").stdout)

        self.assertEqual(explicit["timer_target"], "fixture-backup.service")
        self.assertEqual(implicit["timer_target"], "implicit.service")

    def test_normalizes_jsonl_with_invocation_group_and_status(self) -> None:
        self.install("fixture-backup.service")

        entry = json.loads(self.invoke("--unit", "fixture-backup.service").stdout)

        self.assertEqual(entry, {
            "timestamp": "1700000000000000",
            "hostname": "fixture-host",
            "unit": "fixture-backup.service",
            "pid": "321",
            "priority": "3",
            "message": "fixture message",
            "_SYSTEMD_INVOCATION_ID": "run-123",
            "result": "success",
            "exit_status": "0",
            "journal_scope": "system",
            "timer_target": None,
            "invocation_group": "fixture-backup.service:run-123",
        })

    def test_registry_units_and_timer_mapping_are_used_without_vendor_scan(self) -> None:
        registry = self.root / "registry.sqlite"
        registry.touch()
        sqlite = self.root / "sqlite3"
        sqlite.write_text(
            "#!/usr/bin/env bash\n"
            "case \"$*\" in *periodic_service_evidence*) printf 'registry-job.timer\\tregistry-job.service\\n' ;; *) printf 'systemd\\tregistry-job.service+registry-job.timer\\n' ;; esac\n",
            encoding="utf-8",
        )
        sqlite.chmod(0o755)
        previous = os.environ.get("SQLITE3_BIN")
        os.environ["SQLITE3_BIN"] = str(sqlite)
        try:
            entry = json.loads(self.invoke("--unit", "registry-job.timer", registry=registry).stdout)
        finally:
            if previous is None:
                os.environ.pop("SQLITE3_BIN", None)
            else:
                os.environ["SQLITE3_BIN"] = previous
        self.assertEqual(entry["timer_target"], "registry-job.service")
        self.assertEqual(self.calls_for_run()[0][1], "registry-job.timer")

    def test_empty_or_missing_sources_emit_no_entries(self) -> None:
        result = self.invoke()
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
