from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from fedora_system_monitor.capsules.activitywatch import correlate_activitywatch


class _Response:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class ActivityWatchCorrelationTests(unittest.TestCase):
    def test_correlation_is_bounded_and_omits_full_urls(self) -> None:
        def fake_urlopen(url: str, timeout: float) -> _Response:
            del timeout
            if url.endswith("/api/0/buckets/"):
                return _Response(
                    {
                        "aw-watcher-afk_fedora": {"type": "afkstatus"},
                        "aw-watcher-window_fedora": {"type": "currentwindow"},
                        "aw-watcher-web-chrome_fedora": {"type": "web.tab.current"},
                    }
                )
            if "aw-watcher-afk_fedora" in url:
                return _Response(
                    [
                        {
                            "timestamp": "2026-08-01T17:22:48+00:00",
                            "duration": 600,
                            "data": {"status": "not-afk"},
                        }
                    ]
                )
            if "aw-watcher-window_fedora" in url:
                return _Response(
                    [
                        {
                            "timestamp": "2026-08-01T17:27:48.000000+00:00",
                            "duration": 2.046,
                            "data": {"app": "org.gnome.Ptyxis", "title": "home - codex"},
                        },
                        {
                            "timestamp": "2026-08-01T17:27:51.334000+00:00",
                            "duration": 2.035,
                            "data": {"app": "google-chrome", "title": "ChatGPT token=private-value"},
                        },
                    ]
                )
            if "aw-watcher-web-chrome_fedora" in url:
                return _Response(
                    [
                        {
                            "timestamp": "2026-08-01T17:27:32.535000+00:00",
                            "duration": 0,
                            "data": {
                                "url": "https://example.invalid/private/path",
                                "title": "ChatGPT - Fedora",
                                "incognito": False,
                            },
                        }
                    ]
                )
            return _Response([])

        with patch("fedora_system_monitor.capsules.activitywatch.client.urlopen", side_effect=fake_urlopen):
            summary = correlate_activitywatch("2026-08-01T17:27:48.123456Z")

        rendered = json.dumps(summary)
        self.assertTrue(summary["available"])
        self.assertEqual(summary["activity_state"], "active")
        self.assertEqual(summary["afk"]["at_event"]["status"], "not-afk")
        self.assertEqual(summary["active_window"]["at_event"]["app"], "org.gnome.Ptyxis")
        self.assertEqual(summary["web_tab"]["previous_event"]["title"], "ChatGPT - Fedora")
        self.assertNotIn("private-value", rendered)
        self.assertNotIn("example.invalid/private", rendered)

    def test_unavailable_server_is_reported_in_band(self) -> None:
        with patch("fedora_system_monitor.capsules.activitywatch.client.urlopen", side_effect=TimeoutError):
            summary = correlate_activitywatch("2026-08-01T17:27:48Z", timeout=0.01)
        self.assertEqual(summary["available"], False)
        self.assertEqual(summary["reason"], "TimeoutError")


if __name__ == "__main__":
    unittest.main()
