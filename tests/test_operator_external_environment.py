from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from fedora_system_monitor.capsules.command import CommandResult
from fedora_system_monitor.capsules.collectors import common


REPO_ROOT = Path(__file__).resolve().parents[1]


class OperatorExternalEnvironmentTests(unittest.TestCase):
    def test_operator_command_exports_runtime_and_dbus_session_bus(self) -> None:
        account = SimpleNamespace(pw_name="daniele", pw_dir="/home/daniele", pw_uid=1000)
        captured: list[str] = []

        def fake_external(config: object, args: list[str], **kwargs: object) -> CommandResult:
            captured.extend(args)
            return CommandResult(tuple(args), 0, "", "", 1)

        with (
            mock.patch.object(common.pwd, "getpwnam", return_value=account),
            mock.patch.object(common.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="root")),
            mock.patch.object(common, "external", side_effect=fake_external),
        ):
            common.operator_external({}, ["systemctl", "--user", "show", "demo.service"])

        self.assertEqual(captured[:5], ["runuser", "-u", "daniele", "--", "env"])
        self.assertIn("XDG_RUNTIME_DIR=/run/user/1000", captured)
        self.assertIn("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", captured)

    def test_collector_unit_allows_operator_uid_transition(self) -> None:
        unit = (REPO_ROOT / "systemd/fedora-system-monitor-collect@.service").read_text(encoding="utf-8")

        self.assertIn("User=root", unit)
        self.assertIn("CAP_SETGID", unit)
        self.assertIn("CAP_SETUID", unit)
        self.assertNotIn("NoNewPrivileges=yes", unit)


if __name__ == "__main__":
    unittest.main()
