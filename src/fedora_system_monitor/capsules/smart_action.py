"""Clickable local SMART notifications and detail dialogs."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, Mapping, Sequence

from fedora_system_monitor.capsules.collectors.common import external, operator_external, stable_hash
from fedora_system_monitor.capsules.config import redact_text


_SMARTD_DEVICE_RE = re.compile(r"^Device: (?P<device>/dev/\S+) \[(?P<bridge>[^\]]+)\], (?P<problem>.+)$")
_SMARTD_IDENTITY_RE = re.compile(
    r"^Device: (?P<device>/dev/\S+) \[(?P<bridge>[^\]]+)\], "
    r"(?P<model>[^,\r\n]+), S/N:(?P<serial>[^,\r\n]+)"
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_SAFE_DEVICE_RE = re.compile(r"^/dev/[A-Za-z0-9_.:/+-]{1,240}$")


@dataclass(frozen=True)
class SmartAlert:
    device: str
    bridge: str
    problem: str
    model: str = ""
    serial: str = ""
    current_device: str = ""
    smart_status: str = "unknown"
    severity: str = "warning"
    action: str = "Verifica collegamento/cavo e ricollega il disco solo dopo espulsione sicura."
    detected_at: str = ""

    @property
    def stable_id(self) -> str:
        if self.serial:
            return f"serial:{self.serial}"
        if self.model:
            return stable_hash(f"{self.model}:{self.bridge}", "disk")
        return stable_hash(f"{self.device}:{self.bridge}", "disk")

    @property
    def notification_key(self) -> str:
        return stable_hash(f"{self.stable_id}:{self.problem}", "smart-alert")


def _clean(value: object, limit: int = 500) -> str:
    return _CONTROL_RE.sub(" ", redact_text(value)).strip()[:limit]


def parse_smartd_message(message: str, *, detected_at: str = "") -> SmartAlert | None:
    match = _SMARTD_DEVICE_RE.match(_clean(message))
    if not match:
        return None
    device = match.group("device")
    if not _SAFE_DEVICE_RE.fullmatch(device):
        return None
    problem = _clean(match.group("problem"), 300)
    severity = "critical" if re.search(r"failed|error|prefail|unreadable", problem, re.I) else "warning"
    action = "Esegui backup e pianifica sostituzione disco." if severity == "critical" else (
        "Monitora il disco e verifica collegamento/cavo."
    )
    if re.search(r"No such device|open\(\).*failed|failed to read NVMe SMART/Health Information", problem, re.I):
        severity = "warning"
        action = "Verifica che il disco USB sia collegato correttamente; se era stato rimosso, usa sempre espulsione sicura e riavvia smartd dopo la rimappatura."
    return SmartAlert(
        device=device,
        bridge=_clean(match.group("bridge"), 120),
        problem=problem,
        severity=severity,
        action=action,
        detected_at=detected_at,
    )


def _latest_identity_for_device(config: Mapping[str, Any], device: str) -> tuple[str, str]:
    result = external(
        config,
        ["journalctl", "-u", "smartd.service", "-b", "--no-pager", "-o", "cat"],
        timeout=8,
        max_output=1_000_000,
    )
    if not result.ok:
        return "", ""
    model = serial = ""
    for line in result.stdout.splitlines():
        match = _SMARTD_IDENTITY_RE.match(line.strip())
        if match and match.group("device") == device:
            model = _clean(match.group("model"), 160)
            serial = _clean(match.group("serial"), 160)
    return model, serial


def _current_device_by_serial(config: Mapping[str, Any], serial: str) -> str:
    if not serial:
        return ""
    result = external(
        config,
        ["lsblk", "-J", "-o", "PATH,MODEL,SERIAL,TYPE"],
        timeout=6,
        max_output=500_000,
    )
    if not result.ok:
        return ""
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return ""
    for node in payload.get("blockdevices", []):
        if not isinstance(node, Mapping) or node.get("type") != "disk":
            continue
        if str(node.get("serial") or "") == serial:
            path = str(node.get("path") or "")
            return path if _SAFE_DEVICE_RE.fullmatch(path) else ""
    return ""


def enrich_smart_alert(config: Mapping[str, Any], alert: SmartAlert) -> SmartAlert:
    model, serial = _latest_identity_for_device(config, alert.device)
    current_device = _current_device_by_serial(config, serial)
    smart_status = "device not currently present" if not current_device else "present; run detailed SMART from GNOME Disks or smartctl"
    return SmartAlert(
        device=alert.device,
        bridge=alert.bridge,
        problem=alert.problem,
        model=model,
        serial=serial,
        current_device=current_device,
        smart_status=smart_status,
        severity=alert.severity,
        action=alert.action,
        detected_at=alert.detected_at or datetime.now(timezone.utc).isoformat(),
    )


def smart_alert_from_event(config: Mapping[str, Any], event: Mapping[str, Any]) -> SmartAlert | None:
    details = event.get("details")
    if not isinstance(details, Mapping):
        return None
    message = str(details.get("smartd_message") or event.get("error_message") or "")
    alert = parse_smartd_message(message, detected_at=str(event.get("timestamp_utc") or ""))
    return enrich_smart_alert(config, alert) if alert else None


def alert_to_dict(alert: SmartAlert) -> dict[str, str]:
    return {
        "device": alert.device,
        "bridge": alert.bridge,
        "problem": alert.problem,
        "model": alert.model or "unknown",
        "serial": alert.serial or "unknown",
        "current_device": alert.current_device or "not present",
        "stable_id": alert.stable_id,
        "smart_status": alert.smart_status,
        "severity": alert.severity,
        "action": alert.action,
        "detected_at": alert.detected_at,
        "notification_key": alert.notification_key,
    }


def notification_signature(alert: SmartAlert) -> dict[str, str]:
    signature = alert_to_dict(alert)
    signature.pop("detected_at", None)
    return signature


def render_detail_text(alert: SmartAlert) -> str:
    fields = alert_to_dict(alert)
    return "\n".join(
        [
            "SMART disk alert",
            "",
            f"Disk: {fields['model']}",
            f"Device reported by smartd: {fields['device']}",
            f"Current device: {fields['current_device']}",
            f"Stable identifier: {fields['stable_id']}",
            f"Bridge/source: {fields['bridge']}",
            f"Overall SMART status: {fields['smart_status']}",
            f"Alarm reason: {fields['problem']}",
            "SMART attribute/error: NVMe SMART/Health read/open failure reported by smartd; no failing SMART attribute was identified.",
            f"Relevant values: model={fields['model']}; serial={fields['serial']}; bridge={fields['bridge']}",
            f"Detected at: {fields['detected_at']}",
            f"Severity: {fields['severity']}",
            f"Recommended action: {fields['action']}",
        ]
    )


def show_details(config: Mapping[str, Any], alert: SmartAlert, *, no_open: bool = False) -> dict[str, Any]:
    text = render_detail_text(alert)
    if no_open:
        return {"opened": False, "text": text}
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="fsm-smart-", suffix=".txt", delete=False) as handle:
        handle.write(text)
        path = handle.name
    try:
        result = operator_external(
            config,
            ["zenity", "--text-info", "--title=SMART Disk Details", f"--filename={path}", "--width=760", "--height=520"],
            timeout=3600,
            max_output=20_000,
        )
        return {"opened": result.ok, "status": result.returncode}
    finally:
        try:
            Path(path).unlink()
        except OSError:
            pass


def open_gnome_disks(config: Mapping[str, Any], alert: SmartAlert, *, no_open: bool = False) -> dict[str, Any]:
    device = alert.current_device or alert.device
    if not _SAFE_DEVICE_RE.fullmatch(device):
        return {"opened": False, "reason": "unsafe device"}
    if no_open:
        return {"opened": False, "command": ["gnome-disks", f"--block-device={device}"]}
    result = operator_external(config, ["gnome-disks", f"--block-device={device}"], timeout=10, max_output=20_000)
    return {"opened": result.ok, "status": result.returncode, "device": device}


def _notify_worker(config: Mapping[str, Any], alert: SmartAlert) -> None:
    body = f"{alert.problem}\nDisk: {alert.model or alert.device}\nClick to open details."
    result = operator_external(
        config,
        [
            "notify-send",
            "-u",
            "critical" if alert.severity == "critical" else "normal",
            "-i",
            "drive-harddisk",
            "-a",
            "Fedora System Monitor",
            "-A",
            "default=Details",
            "-A",
            "disks=Open Disks",
            "--wait",
            "SMART Disk Monitor",
            body,
        ],
        timeout=86400,
        max_output=20_000,
    )
    action = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if action in {"default", "0", "Details"}:
        show_details(config, alert)
    elif action in {"disks", "1", "Open Disks"}:
        open_gnome_disks(config, alert)


def send_notification_probe(config: Mapping[str, Any], alert: SmartAlert) -> dict[str, Any]:
    body = f"{alert.problem}\nDisk: {alert.model or alert.device}\nDetails action is enabled for real alerts."
    result = operator_external(
        config,
        [
            "notify-send",
            "-u",
            "critical" if alert.severity == "critical" else "normal",
            "-i",
            "drive-harddisk",
            "-a",
            "Fedora System Monitor",
            "-t",
            "3000",
            "SMART Disk Monitor",
            body,
        ],
        timeout=10,
        max_output=20_000,
    )
    return {"sent": result.ok, "status": result.returncode, "alert": alert_to_dict(alert)}


def maybe_notify_smart_alert(config: Mapping[str, Any], db: Any, alert: SmartAlert, *, force: bool = False) -> bool:
    state_key = f"smart-action:{alert.notification_key}"
    previous = db.get_state(state_key, {}, namespace="notification")
    signature = notification_signature(alert)
    if not force and previous == signature:
        return False
    db.set_state(state_key, signature, namespace="notification")
    thread = threading.Thread(target=_notify_worker, args=(config, alert), name="smart-action-notify", daemon=True)
    thread.start()
    return True


def fixture_alert(name: str) -> SmartAlert:
    if name != "t7-usb-nvme-read-failed":
        raise ValueError(f"unknown SMART fixture: {name}")
    return SmartAlert(
        device="/dev/sdd",
        bridge="USB NVMe ASMedia",
        problem="failed to read NVMe SMART/Health Information",
        model="Samsung Portable SSD T7 Shield",
        serial="S6YGNS0Y903440H",
        current_device="/dev/sdc",
        smart_status="PASSED in the last verified read; fixture does not re-read hardware",
        severity="warning",
        action="Verifica collegamento/cavo, usa espulsione sicura, poi monitora il prossimo controllo SMART.",
        detected_at="2026-09-12T03:49:22+02:00",
    )


def run_cli(args: argparse.Namespace, config: Mapping[str, Any], db: Any | None) -> dict[str, Any]:
    alert = fixture_alert(args.fixture) if args.fixture else None
    if alert is None and args.message:
        parsed = parse_smartd_message(args.message)
        alert = enrich_smart_alert(config, parsed) if parsed else None
    if alert is None:
        raise ValueError("SMART alert message or fixture did not match")
    if args.action == "details":
        return show_details(config, alert, no_open=args.no_open)
    if args.action == "disks":
        return open_gnome_disks(config, alert, no_open=args.no_open)
    if args.no_open:
        return send_notification_probe(config, alert)
    if db is None:
        raise ValueError("notification requires database access")
    notified = maybe_notify_smart_alert(config, db, alert, force=args.force)
    return {"notified": notified, "alert": alert_to_dict(alert)}


__all__ = [
    "SmartAlert",
    "alert_to_dict",
    "enrich_smart_alert",
    "fixture_alert",
    "maybe_notify_smart_alert",
    "notification_signature",
    "open_gnome_disks",
    "parse_smartd_message",
    "render_detail_text",
    "run_cli",
    "show_details",
    "smart_alert_from_event",
]
