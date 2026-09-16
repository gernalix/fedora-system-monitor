from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fedora_system_monitor.capsules.kuma_admin import (
    KumaMonitorSpec,
    _monitor_payload,
    _monitor_upside_down,
    recover_chrome_session_token,
)


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


class KumaAdminTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = KumaMonitorSpec(
            "storage",
            "Fedora Storage",
            "Storage health",
            480,
            180,
            2,
        )

    def test_payload_can_preserve_upside_down(self) -> None:
        payload = _monitor_payload(
            self.spec,
            "token",
            {},
            upside_down=True,
        )
        self.assertTrue(payload["upsideDown"])

    def test_existing_upside_down_aliases_are_preserved(self) -> None:
        self.assertTrue(_monitor_upside_down({"upsideDown": True}))
        self.assertTrue(_monitor_upside_down({"upside_down": 1}))
        self.assertFalse(_monitor_upside_down({"upsideDown": False}))
        self.assertFalse(_monitor_upside_down(None))

    def test_recovers_fresh_token_from_leveldb_wal(self) -> None:
        origin = "https://kuma.example.test"
        token = "t" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "Default"
            leveldb = profile / "Local Storage/leveldb"
            leveldb.mkdir(parents=True)
            key = b"_" + origin.encode("utf-8") + b"\x00\x01token"
            value = b"\x01" + token.encode("utf-8")
            batch = (
                (100).to_bytes(8, "little")
                + (1).to_bytes(4, "little")
                + b"\x01"
                + _varint(len(key))
                + key
                + _varint(len(value))
                + value
            )
            wal_record = b"\x00" * 4 + len(batch).to_bytes(2, "little") + b"\x01" + batch
            (leveldb / "000001.log").write_bytes(wal_record)

            self.assertEqual(recover_chrome_session_token(root, origin), token)
            self.assertEqual(recover_chrome_session_token(profile, origin), token)


if __name__ == "__main__":
    unittest.main()
