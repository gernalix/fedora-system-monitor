"""Dependency-free, optional Prometheus exposition over the existing database."""

from __future__ import annotations

import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fedora_system_monitor.capsules.reporting import prometheus_snapshot


_SAFE = re.compile(r"[^a-zA-Z0-9_:]")


def exposition(path: str | Path) -> str:
    lines = ["# HELP fedora_system_monitor_up Local monitor database is readable.", "# TYPE fedora_system_monitor_up gauge", "fedora_system_monitor_up 1"]
    snapshot = prometheus_snapshot(path)
    lines.extend(("# TYPE fedora_system_monitor_active_alerts gauge", f"fedora_system_monitor_active_alerts {snapshot['active_alerts']}"))
    for row in snapshot["metrics"]:
        if row["value"] is None:
            continue
        metric = "fedora_system_monitor_" + _SAFE.sub("_", str(row["name"]))
        device = str(row["device_id"] or "host").replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{metric}{{device="{device}"}} {float(row["value"])}')
    return "\n".join(lines) + "\n"


def serve(path: str | Path, *, listen: str = "127.0.0.1", port: int = 9109) -> None:
    database = Path(path)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            if self.path != "/metrics":
                self.send_error(404)
                return
            payload = exposition(database).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    ThreadingHTTPServer((listen, port), Handler).serve_forever()


__all__ = ["exposition", "serve"]
