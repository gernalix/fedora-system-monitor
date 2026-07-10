from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from fedora_system_monitor.capsules.command import LockUnavailable, exclusive_lock
from fedora_system_monitor.capsules.database import Database
from fedora_system_monitor.capsules.notifications import send_category_heartbeat


def _hold_lock(path: str, ready: multiprocessing.Queue[bool], seconds: float) -> None:
    with exclusive_lock(path, timeout=1):
        ready.put(True)
        time.sleep(seconds)


def _hold_transaction(path: str, ready: multiprocessing.Queue[bool], seconds: float) -> None:
    database = Database(path)
    try:
        with database._transaction() as connection:
            connection.execute(
                "INSERT INTO dedup_state(namespace,state_key,state_json,updated_at_utc) "
                "VALUES ('audit','uncommitted','true','2026-07-10T00:00:00Z')"
            )
            ready.put(True)
            time.sleep(seconds)
    finally:
        database.close()


class _SlowHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        time.sleep(0.2)
        try:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, _: str, *__: object) -> None:
        return


class ConcurrencyTests(unittest.TestCase):
    def test_simultaneous_identical_events_coalesce_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "monitor.sqlite3"
            Database(path).close()
            instant = datetime(2026, 7, 10, 10, 0, tzinfo=timezone.utc)

            def insert(_: int) -> int:
                database = Database(path)
                try:
                    return database.insert_events(
                        {
                            "category": "hardware",
                            "name": "device_connected",
                            "device_id": "serial-sha256:test",
                            "dedup_key": "concurrent-device",
                        },
                        occurred_at=instant,
                    )
                finally:
                    database.close()

            with ThreadPoolExecutor(max_workers=12) as executor:
                inserted = list(executor.map(insert, range(48)))

            database = Database(path)
            try:
                rows = database.query("SELECT occurrence_count FROM events")
                self.assertEqual(sum(inserted), 1)
                self.assertEqual(rows, [{"occurrence_count": 48}])
                self.assertTrue(database.db_check()["ok"])
            finally:
                database.close()

    def test_killed_lock_holder_leaves_no_orphan_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            lock = str(Path(temp) / "collector.lock")
            ready: multiprocessing.Queue[bool] = multiprocessing.Queue()
            process = multiprocessing.Process(target=_hold_lock, args=(lock, ready, 30))
            process.start()
            self.assertTrue(ready.get(timeout=3))
            with self.assertRaises(LockUnavailable):
                with exclusive_lock(lock, timeout=0.1):
                    pass
            process.kill()
            process.join(timeout=3)
            with exclusive_lock(lock, timeout=1):
                self.assertTrue(Path(lock).exists())

    def test_killed_transaction_rolls_back_and_database_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "monitor.sqlite3"
            Database(path).close()
            ready: multiprocessing.Queue[bool] = multiprocessing.Queue()
            process = multiprocessing.Process(
                target=_hold_transaction, args=(str(path), ready, 30)
            )
            process.start()
            self.assertTrue(ready.get(timeout=3))
            process.kill()
            process.join(timeout=3)

            database = Database(path)
            try:
                self.assertIsNone(
                    database.get_state("uncommitted", namespace="audit")
                )
                self.assertTrue(database.db_check()["ok"])
            finally:
                database.close()

    def test_busy_timeout_is_bounded_and_retry_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "monitor.sqlite3"
            Database(path).close()
            ready: multiprocessing.Queue[bool] = multiprocessing.Queue()
            process = multiprocessing.Process(
                target=_hold_transaction, args=(str(path), ready, 0.5)
            )
            process.start()
            self.assertTrue(ready.get(timeout=3))
            contender = Database(path, timeout_seconds=0.1, initialize=False)
            started = time.monotonic()
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    contender.set_state("contended", True, namespace="audit")
                self.assertLess(time.monotonic() - started, 0.4)
            finally:
                contender.close()
            process.join(timeout=3)

            retry = Database(path, timeout_seconds=1)
            try:
                retry.set_state("contended", True, namespace="audit")
                self.assertTrue(retry.get_state("contended", namespace="audit"))
                self.assertTrue(retry.db_check()["ok"])
            finally:
                retry.close()

    def test_slow_kuma_endpoint_times_out_without_blocking_indefinitely(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _SlowHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            config = {
                "notifications": {
                    "timeout_seconds": 0.05,
                    "uptime_kuma_credentials": "",
                }
            }
            with tempfile.TemporaryDirectory() as temp:
                credentials = Path(temp) / "kuma.toml"
                credentials.write_text(
                    "[push]\nsystem = \"http://127.0.0.1:"
                    + str(port)
                    + "/api/push/fake\"\n[transport]\nallow_insecure_http = true\n",
                    encoding="utf-8",
                )
                credentials.chmod(0o600)
                config["notifications"]["uptime_kuma_credentials"] = str(credentials)
                started = time.monotonic()
                result = send_category_heartbeat(
                    config, "system", healthy=True, message="audit heartbeat"
                )
                elapsed = time.monotonic() - started
            self.assertTrue(result.attempted)
            self.assertFalse(result.delivered)
            self.assertLess(elapsed, 0.5)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
