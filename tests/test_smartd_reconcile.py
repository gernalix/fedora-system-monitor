from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "reconcile_smartd", ROOT / "tools" / "reconcile_smartd.py"
)
assert SPEC and SPEC.loader
reconcile_smartd = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reconcile_smartd)


class SmartdReconcileTests(unittest.TestCase):
    def test_t7_by_id_is_ignored_before_devicescan_and_reconcile_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "smartd.conf"
            backup_dir = root / "backups"
            by_id = root / "by-id"
            by_id.mkdir()
            disk = root / "sdc"
            disk.touch()
            link = by_id / "usb-Samsung_PSSD_T7_Shield_SERIAL-0:0"
            link.symlink_to(disk)
            config.write_text(
                "# local smartd config\n"
                "DEVICESCAN -H -m root -M exec /usr/libexec/smartmontools/smartdnotify\n",
                encoding="utf-8",
            )

            first = reconcile_smartd.apply(
                config,
                backup_dir,
                by_id,
                reconcile_smartd.DEFAULT_GLOBS,
            )
            text = config.read_text(encoding="utf-8")
            self.assertTrue(first["changed"])
            self.assertIn(f"{link} -d ignore", text)
            self.assertLess(text.index(str(link)), text.index("DEVICESCAN"))
            self.assertTrue(Path(first["backup"]).exists())

            second = reconcile_smartd.apply(
                config,
                backup_dir,
                by_id,
                reconcile_smartd.DEFAULT_GLOBS,
            )
            self.assertFalse(second["changed"])
            self.assertEqual(text, config.read_text(encoding="utf-8"))

    def test_managed_ignore_is_retained_when_drive_is_temporarily_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "smartd.conf"
            backup_dir = root / "backups"
            by_id = root / "by-id"
            by_id.mkdir()
            stored = by_id / "usb-Samsung_PSSD_T7_Shield_SERIAL-0:0"
            config.write_text(
                f"{reconcile_smartd.BEGIN}\n"
                f"{stored} -d ignore\n"
                f"{reconcile_smartd.END}\n"
                "DEVICESCAN -H\n",
                encoding="utf-8",
            )

            result = reconcile_smartd.apply(
                config,
                backup_dir,
                by_id,
                reconcile_smartd.DEFAULT_GLOBS,
            )
            self.assertFalse(result["changed"])
            self.assertIn(f"{stored} -d ignore", config.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
