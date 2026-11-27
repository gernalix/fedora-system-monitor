import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fedora_system_monitor.capsules.reporting import resource_journal


class ResourceJournalTests(unittest.TestCase):
    unit = "dbus-:1.1-org.gnome.Nautilus@8.service"

    def test_one_read_groups_each_producer_and_hides_messages(self):
        args = SimpleNamespace(minutes=8, lines=9, limit=5, cursor="earlier", unit="user:1000:" + self.unit)
        rows = [
            {"_SYSTEMD_USER_UNIT": self.unit, "_UID": "1000", "_TRANSPORT": "stdout",
             "PRIORITY": "4", "MESSAGE": "private test payload", "__CURSOR": "older"},
            {"_SYSTEMD_USER_UNIT": self.unit, "_UID": "1000", "_TRANSPORT": "stdout",
             "PRIORITY": "4", "MESSAGE": "private test payload", "__CURSOR": "next"},
        ]
        reply = SimpleNamespace(ok=True, stdout="\n".join(map(json.dumps, rows)))
        with patch.object(resource_journal, "external", return_value=reply) as reader:
            result, code = resource_journal.report(args, now=1000)
        reader.assert_called_once()
        command = reader.call_args.args[1]
        self.assertEqual(command[-3:], ["--after-cursor=earlier", "_SYSTEMD_USER_UNIT=" + self.unit, "_UID=1000"])
        self.assertIn("--lines=10", command)
        self.assertEqual(code, 0)
        self.assertEqual((result["entries"], result["cursor"]), (2, "next"))
        self.assertFalse(result["truncated"])
        source, = result["producers"]
        self.assertEqual(source["unit"], args.unit)
        self.assertEqual(source["entries"], 2)
        self.assertEqual(source["most_repeated"], 2)
        self.assertEqual(source["by_priority"], {"4": 2})
        self.assertNotIn("private test payload", json.dumps(result))

    def test_capped_read_keeps_cursor_and_accounts_for_omitted_message(self):
        args = SimpleNamespace(minutes=8, lines=1, limit=5, cursor="previous", unit=None)
        rows = [{"_SYSTEMD_UNIT": "a.service", "MESSAGE": "available", "__CURSOR": "old"},
                {"_SYSTEMD_UNIT": "a.service", "MESSAGE": None, "__CURSOR": "new"}]
        reply = SimpleNamespace(ok=True, stdout="\n".join(map(json.dumps, rows)))
        with patch.object(resource_journal, "external", return_value=reply):
            result, _ = resource_journal.report(args, now=1000)
        self.assertEqual((result["entries"], result["cursor"]), (1, "previous"))
        self.assertTrue(result["truncated"])
        self.assertEqual(result["producers"][0]["unavailable_messages"], 1)
