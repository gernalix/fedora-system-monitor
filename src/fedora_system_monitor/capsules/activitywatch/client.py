"""Optional ActivityWatch correlation helpers.

The monitor stores only bounded summaries around a host event.  ActivityWatch
remains an external evidence source and is never required for normal runtime.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.request import urlopen

from fedora_system_monitor.capsules.config import redact_text


DEFAULT_BASE_URL = "http://127.0.0.1:5600"
DEFAULT_WINDOW_SECONDS = 300
_MAX_EVENTS_PER_BUCKET = 80
_MAX_TEXT = 160


def _clean_text(value: object, limit: int = _MAX_TEXT) -> str:
    return redact_text(str(value or "").replace("\x00", " ").strip())[:limit]


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _read_json(url: str, timeout: float) -> Any:
    with urlopen(url, timeout=timeout) as response:  # noqa: S310 - localhost-only optional telemetry.
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _endpoint(base_url: str, path: str, query: dict[str, str] | None = None) -> str:
    base = base_url.rstrip("/")
    suffix = path if path.startswith("/") else f"/{path}"
    if query:
        return f"{base}{suffix}?{urlencode(query)}"
    return f"{base}{suffix}"


def _safe_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        return DEFAULT_BASE_URL
    return base_url


def _bounded_event(event: dict[str, Any]) -> dict[str, Any]:
    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    result = {
        "timestamp_utc": _format_time(_parse_time(str(event.get("timestamp")))),
        "duration_seconds": round(float(event.get("duration") or 0), 3),
    }
    app = _clean_text(data.get("app"))
    title = _clean_text(data.get("title"))
    status = _clean_text(data.get("status"), 32)
    if app:
        result["app"] = app
    if title:
        result["title"] = title
    if status:
        result["status"] = status
    if "incognito" in data:
        result["incognito"] = bool(data.get("incognito"))
    if "audible" in data:
        result["audible"] = bool(data.get("audible"))
    tab_count = data.get("tabCount")
    if isinstance(tab_count, int) and not isinstance(tab_count, bool) and 0 <= tab_count <= 10000:
        result["tab_count"] = tab_count
    raw_url = str(data.get("url") or "")
    if raw_url:
        parsed = urlparse(raw_url)
        if parsed.scheme == "chrome":
            result["browser_internal_page"] = _clean_text(
                f"chrome://{parsed.netloc}{parsed.path}",
                120,
            )
            if parsed.netloc == "extensions":
                error_id = (parse_qs(parsed.query).get("errors") or [""])[0]
                if len(error_id) == 32 and all("a" <= char <= "p" for char in error_id):
                    result["extension_error_id"] = error_id
    return result


def _event_interval(event: dict[str, Any]) -> tuple[datetime, datetime]:
    start = _parse_time(str(event.get("timestamp")))
    duration = max(0.0, float(event.get("duration") or 0))
    return start, start + timedelta(seconds=duration)


def _events_near(events: list[dict[str, Any]], timestamp: datetime) -> dict[str, Any]:
    bounded = sorted(events, key=lambda item: _event_interval(item)[0])
    overlapping: list[dict[str, Any]] = []
    previous_event: dict[str, Any] | None = None
    next_event: dict[str, Any] | None = None
    for event in bounded:
        start, end = _event_interval(event)
        if start <= timestamp <= end:
            overlapping.append(event)
        if end <= timestamp:
            previous_event = event
        if start > timestamp and next_event is None:
            next_event = event
    result: dict[str, Any] = {"event_count": len(events)}
    if overlapping:
        result["at_event"] = _bounded_event(overlapping[-1])
    if previous_event is not None:
        result["previous_event"] = _bounded_event(previous_event)
    if next_event is not None:
        result["next_event"] = _bounded_event(next_event)
    nearest = sorted(
        bounded,
        key=lambda item: abs((_event_interval(item)[0] - timestamp).total_seconds()),
    )[:16]
    result["recent_events"] = [
        _bounded_event(item)
        for item in sorted(nearest, key=lambda item: _event_interval(item)[0])
    ]
    return result


def _max_gap_seconds(events: list[dict[str, Any]], start: datetime, end: datetime) -> float | None:
    if not events:
        return (end - start).total_seconds()
    intervals = sorted(_event_interval(event) for event in events)
    max_gap = max(0.0, (intervals[0][0] - start).total_seconds())
    cursor = max(start, intervals[0][1])
    for interval_start, interval_end in intervals[1:]:
        max_gap = max(max_gap, (interval_start - cursor).total_seconds())
        if interval_end > cursor:
            cursor = interval_end
    max_gap = max(max_gap, (end - cursor).total_seconds())
    return round(max_gap, 3)


def _classify_activity(afk_summary: dict[str, Any]) -> str:
    candidate = afk_summary.get("at_event") or afk_summary.get("previous_event") or {}
    status = str(candidate.get("status") or "")
    if status == "not-afk":
        return "active"
    if status == "afk":
        return "idle"
    return "unknown"


def correlate_activitywatch(
    timestamp_utc: str,
    *,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = 0.8,
) -> dict[str, Any]:
    """Return a bounded ActivityWatch summary around *timestamp_utc*.

    The result is intentionally compact enough to embed in one monitor event.
    Failures are represented in-band so ActivityWatch stays optional.
    """

    base_url = _safe_base_url(base_url)
    try:
        timestamp = _parse_time(timestamp_utc)
    except (TypeError, ValueError):
        return {"available": False, "reason": "invalid_timestamp"}
    start = timestamp - timedelta(seconds=max(1, int(window_seconds)))
    end = timestamp + timedelta(seconds=max(1, int(window_seconds)))
    try:
        buckets_raw = _read_json(_endpoint(base_url, "/api/0/buckets/"), timeout)
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {"available": False, "reason": type(exc).__name__, "endpoint": base_url}
    if not isinstance(buckets_raw, dict):
        return {"available": False, "reason": "invalid_bucket_response", "endpoint": base_url}

    buckets: dict[str, str] = {}
    for bucket_id, metadata in buckets_raw.items():
        if not isinstance(metadata, dict):
            continue
        bucket_type = str(metadata.get("type") or "")
        if bucket_type in {"afkstatus", "currentwindow", "web.tab.current"} or "lock" in bucket_id.lower():
            buckets[str(bucket_id)] = bucket_type

    summaries: dict[str, Any] = {}
    events_by_type: dict[str, list[dict[str, Any]]] = {}
    for bucket_id, bucket_type in buckets.items():
        try:
            raw_events = _read_json(
                _endpoint(
                    base_url,
                    f"/api/0/buckets/{quote(bucket_id, safe='')}/events",
                    {"start": _format_time(start), "end": _format_time(end)},
                ),
                timeout,
            )
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
            continue
        if not isinstance(raw_events, list):
            continue
        events = [event for event in raw_events if isinstance(event, dict)][-_MAX_EVENTS_PER_BUCKET:]
        bucket_key = bucket_type or bucket_id
        events_by_type[bucket_key] = events
        summaries[bucket_key] = _events_near(events, timestamp)

    afk_summary = summaries.get("afkstatus", {})
    window_summary = summaries.get("currentwindow", {})
    all_events = [event for events in events_by_type.values() for event in events]
    lock_events = [
        event
        for event in all_events
        if "lock" in json.dumps(event.get("data") or {}, sort_keys=True).lower()
        or "unlock" in json.dumps(event.get("data") or {}, sort_keys=True).lower()
    ]
    core_gaps = {
        key: _max_gap_seconds(events_by_type.get(key, []), start, end)
        for key in ("currentwindow", "web.tab.current", "afkstatus")
    }
    window_events = events_by_type.get("currentwindow", [])
    app_seconds: dict[str, float] = {}
    for item in window_events:
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        app = _clean_text(data.get("app"))
        if app:
            app_seconds[app] = app_seconds.get(app, 0.0) + max(0.0, float(item.get("duration") or 0))
    app_mix = [
        {"app": app, "duration_seconds": round(seconds, 3)}
        for app, seconds in sorted(app_seconds.items(), key=lambda pair: (-pair[1], pair[0]))[:10]
    ]
    foreground_gap = core_gaps.get("currentwindow")
    afk_gap = core_gaps.get("afkstatus")
    return {
        "available": True,
        "source": "activitywatch",
        "endpoint": base_url,
        "event_timestamp_utc": _format_time(timestamp),
        "window_seconds": int(window_seconds),
        "buckets": sorted(buckets),
        "activity_state": _classify_activity(afk_summary),
        "afk": afk_summary,
        "active_window": window_summary,
        "web_tab": summaries.get("web.tab.current", {}),
        "app_mix": {
            "apps": app_mix,
            "window_event_count": len(window_events),
            "window_switch_count": max(0, len(window_events) - 1),
        },
        "lock_unlock": {
            "event_count": len(lock_events),
            "events": [_bounded_event(event) for event in sorted(lock_events, key=lambda item: _event_interval(item)[0])[:8]],
        },
        "data_gap": {
            "currentwindow_max_gap_seconds": foreground_gap,
            "web_tab_max_gap_seconds": core_gaps.get("web.tab.current"),
            "afk_max_gap_seconds": afk_gap,
            "suspend_resume_compatible": bool(
                foreground_gap is not None
                and afk_gap is not None
                and foreground_gap >= 120
                and afk_gap >= 120
            ),
        },
    }
