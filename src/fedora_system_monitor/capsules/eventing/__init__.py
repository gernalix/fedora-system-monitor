"""Privacy-preserving, event-driven host event capture.

The capsule accepts plain mappings so the udev and NetworkManager dispatchers
do not need a Python binding.  Journal records are classified using trusted
metadata and anchored patterns; raw messages, command lines, core dumps, and
arbitrary dispatcher variables are never persisted.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import pwd
import re
import selectors
import subprocess
from typing import Any, Callable, Mapping

from fedora_system_monitor.capsules.activitywatch import correlate_activitywatch
from fedora_system_monitor.capsules.config import redact_text
from fedora_system_monitor.capsules.graphics_incident import (
    classify_gnome_journal,
    classify_graphics_coredump,
    classify_graphics_kernel,
    enrich_graphics_incident,
    is_graphics_incident,
)


Event = dict[str, Any]

_COREDUMP_MESSAGE_ID = "fc2e22bc6ee647b6b90729ab34a250b1"
_SYSTEMD_FAILED_MESSAGE_ID = "be02cf6855d2428ba40df7e9d022f03d"
_MAX_TEXT = 512
_MAX_JOURNAL_LINE = 1_048_576
_POWER_PROFILE_DBUS_PATHS = (
    "/org/freedesktop/UPower/PowerProfiles",
    "/net/hadess/PowerProfiles",
)
_POWER_PROFILE_DBUS_INTERFACES = (
    "org.freedesktop.UPower.PowerProfiles",
    "net.hadess.PowerProfiles",
)
_POWER_PROFILE_DBUS_MATCHES = tuple(
    f"type='method_call',path='{path}',interface='{interface}'"
    for path in _POWER_PROFILE_DBUS_PATHS
    for interface in ("org.freedesktop.DBus.Properties", *_POWER_PROFILE_DBUS_INTERFACES)
)

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_DBUS_METHOD_RE = re.compile(
    r"^method call time=(?P<time>[0-9.]+).* sender=(?P<sender>:[0-9.]+)\s"
    r".* path=(?P<path>[^;\s]+);\s+interface=(?P<interface>[^;\s]+);\s+member=(?P<member>[A-Za-z0-9_]+)"
)
_DBUS_STRING_RE = re.compile(r'^\s*string\s+"(?P<value>[^"]*)"\s*$')
_DBUS_VARIANT_STRING_RE = re.compile(r'^\s*variant\s+string\s+"(?P<value>[^"]*)"\s*$')
_DBUS_UINT_RE = re.compile(r"^\s*u(?:int32|int64)?\s+(?P<value>[0-9]+)\s*$")
_SAFE_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_UNIT_RE = re.compile(
    r"^[A-Za-z0-9_.:@\\-]+\.(?:service|mount|automount|socket|timer|target|scope|path|slice)$"
)
_DEVICE_NODE_RE = re.compile(r"^/dev/[A-Za-z0-9_./+:-]{1,240}$")
_USB_PORT_RE = re.compile(r"^[0-9]+-[0-9]+(?:\.[0-9]+)*$")

_OOM_RE = re.compile(
    r"^(?:Out of memory|Memory cgroup out of memory): "
    r"Killed process (?P<pid>[1-9][0-9]*) \((?P<process>[^)\r\n]{1,64})\)"
    r"(?:\s|$)"
)
_KERNEL_PANIC_RE = re.compile(r"^Kernel panic - not syncing:(?:\s*(?P<reason>.*))?$")
_KERNEL_OOPS_RE = re.compile(
    r"^(?P<kind>Oops:\s+[0-9A-Fa-f]+(?:\s+\[#\d+\])?|"
    r"BUG: kernel NULL pointer dereference(?:, address: [0-9A-Fa-fx]+)?|"
    r"general protection fault(?:, probably for non-canonical address [0-9A-Fa-fx]+)?)(?:\s|$)"
)
_IO_ERROR_RES = (
    re.compile(
        r"^(?:blk_update_request: |end_request: )?I/O error, dev "
        r"(?P<device>[A-Za-z0-9_.:+-]+)(?:,|\s|$)"
    ),
    re.compile(
        r"^Buffer I/O error on dev (?P<device>[A-Za-z0-9_.:+-]+)(?:,|\s|$)"
    ),
    re.compile(
        r"^(?P<device>[A-Za-z0-9_.:+-]+): critical (?:medium|target|nexus|hardware) error(?:,|\s|$)",
        re.IGNORECASE,
    ),
)
_USB_RESET_RE = re.compile(
    r"^usb (?P<port>[0-9]+-[0-9]+(?:\.[0-9]+)*): reset "
    r"(?:low-speed|full-speed|high-speed|SuperSpeed(?: Plus)?) USB device number "
    r"(?P<number>[0-9]+) using [A-Za-z0-9_.-]+$",
    re.IGNORECASE,
)
_USB_DISCONNECT_RE = re.compile(
    r"^usb (?P<port>[0-9]+-[0-9]+(?:\.[0-9]+)*): USB disconnect, device number "
    r"(?P<number>[0-9]+)$"
)
_EXT_RO_RE = re.compile(
    r"^(?P<filesystem>[A-Z0-9_-]+)-fs \((?P<device>[^)\s]+)\): "
    r"Remounting filesystem read-only$"
)
_BTRFS_RO_RE = re.compile(
    r"^BTRFS (?:info|warning|error|critical) \(device "
    r"(?P<device>[^ )]+)(?: state [^)]+)?\): forced readonly$",
    re.IGNORECASE,
)
_THERMAL_RE = re.compile(
    r"^(?P<subject>CPU\d+|Package|Core|thermal_zone\d+): "
    r"(?P<condition>(?:Core |Package )?temperature above threshold, cpu clock throttled|"
    r"critical temperature reached(?:, shutting down)?)$",
    re.IGNORECASE,
)
_HARDWARE_ERROR_RE = re.compile(
    r"^(?:mce: )?\[Hardware Error\]:|^EDAC\s+[^:]+:\s+(?:UE|Uncorrected Error)\b",
    re.IGNORECASE,
)
_SMARTD_ALERT_RE = re.compile(
    r"^Device: (?P<device>/dev/\S+) \[(?P<bridge>[^\]]+)\], "
    r"(?P<problem>(?:failed to read NVMe SMART/Health Information|open\(\) of NVMe device failed: No such device|.*SMART.*(?:failed|error).*))$",
    re.IGNORECASE,
)

_SYSTEMD_FAILED_RE = re.compile(
    r"^(?P<unit>[A-Za-z0-9_.:@\\-]+\.(?:service|mount|automount|socket|timer|path)): "
    r"Failed with result '(?P<result>[A-Za-z0-9_.-]+)'\.$"
)
_SYSTEMD_START_FAILED_RE = re.compile(r"^Failed to start (?P<description>[^\r\n]{1,300})\.$")
_UNCLEAN_JOURNAL_RE = re.compile(
    r"^(?:Journal f|F)ile .+ (?:corrupted or )?uncleanly shut down, renaming and replacing\.$"
)

_UDISKS_UNSAFE_RE = re.compile(
    r"^Cleaning up mount point (?P<mount>/[^\r\n]{1,400}?) "
    r"\(device (?P<major>[0-9]+):(?P<minor>[0-9]+) no longer exists\)$"
)
_UDISKS_MOUNTED_RE = re.compile(
    r'^Mounted (?P<device>/dev/\S{1,240}) \((?P<mode>Read-(?:Write|Only)), '
    r'label "(?P<label>[^"\r\n]{0,255})", (?P<filesystem>[^)\r\n]{1,80})\)$'
)
_UDISKS_MOUNTED_AT_RE = re.compile(
    r"^Mounted (?P<device>/dev/\S{1,240}) at (?P<mount>/[^\r\n]{1,400}?) "
    r"on behalf of uid (?P<uid>[0-9]+)$"
)
_UDISKS_UNMOUNT_RE = re.compile(
    r"^(?:Unmounting|Unmounted) (?P<device>/dev/\S{1,240})(?: \([^\r\n]*\)| "
    r"on behalf of uid (?P<uid>[0-9]+))$"
)
_UDISKS_FAILURE_RE = re.compile(
    r"^(?:Error (?P<gerund>mounting|unmounting)|Failed to (?P<verb>mount|unmount)) "
    r"(?P<device>/dev/\S{1,240})(?: at (?P<mount>/[^\r\n]{1,400}?))?:\s*"
    r"(?P<error>[^\r\n]{1,400})$",
    re.IGNORECASE,
)
_UDISKS_IO_RE = re.compile(
    r"^Failed to (?P<operation>sync device|close volume) "
    r"(?P<device>/dev/\S{1,240}): Input/output error$"
)

_NM_PREFIX = r"^(?:<[^>]+>\s+\[[^\]\r\n]+\]\s+)?"
_NM_STATE_RE = re.compile(
    _NM_PREFIX
    + r"device \((?P<interface>[A-Za-z0-9][A-Za-z0-9_.-]{0,31})\): "
    r"state change: (?P<old>[a-z-]+) -> (?P<new>[a-z-]+) "
    r"\(reason '[^'\r\n]{1,80}', managed-type: '[^'\r\n]{1,40}'\)$"
)
_NM_MANAGER_STATE_RE = re.compile(
    _NM_PREFIX
    + r"manager: NetworkManager state is now "
    r"(?P<state>CONNECTED_GLOBAL|CONNECTED_SITE|CONNECTED_LOCAL|CONNECTING|DISCONNECTED|DISABLED \(ASLEEP\))$"
)
_NM_DHCP_RE = re.compile(
    _NM_PREFIX
    + r"dhcp(?P<family>[46]) \((?P<interface>[A-Za-z0-9][A-Za-z0-9_.-]{0,31})\): "
    r"state changed new lease, address=(?P<address>[^,\s]+)(?:, acd pending)?$"
)
_NM_DEFAULT_RE = re.compile(
    _NM_PREFIX
    + r"policy: set '(?P<connection>[^'\r\n]{1,128})' "
    r"\((?P<interface>[A-Za-z0-9][A-Za-z0-9_.-]{0,31})\) as default for IPv[46] routing and DNS$"
)
_NM_VPN_STATE_RE = re.compile(
    _NM_PREFIX
    + r"vpn\[[^\]\r\n]{1,400}\]: state changed: "
    r"(?P<state>activated|disconnected|failed)(?: \([0-9]+\))?$"
)

_SLEEP_START_RE = re.compile(r"^Performing sleep operation '(?P<mode>suspend|hibernate|hybrid-sleep)'\.\.\.$")
_SLEEP_RETURN_RE = re.compile(r"^System returned from sleep operation '(?P<mode>suspend|hibernate|hybrid-sleep)'\.$")


def _clean_text(value: object, limit: int = _MAX_TEXT) -> str:
    """Redact credentials and collapse control characters in bounded text."""

    cleaned = _CONTROL_RE.sub(" ", redact_text(value)).strip()
    return cleaned[:limit]


def _clean_unit(value: object) -> str:
    candidate = _clean_text(value, 180)
    return candidate if _UNIT_RE.fullmatch(candidate) else ""


def _clean_interface(value: object) -> str:
    candidate = _clean_text(value, 32)
    if _MAC_RE.fullmatch(candidate) or not _SAFE_INTERFACE_RE.fullmatch(candidate):
        return ""
    return candidate


def _clean_device_node(value: object) -> str:
    candidate = _clean_text(value, 245)
    return candidate if _DEVICE_NODE_RE.fullmatch(candidate) else ""


def _event(
    *,
    category: str,
    name: str,
    severity: str,
    source: str,
    device_id: str = "",
    details: Mapping[str, Any] | None = None,
    outcome: str = "observed",
    error_message: str | None = None,
    dedup_key: str,
    dedup_window_seconds: int = 300,
) -> Event:
    return {
        "category": category,
        "name": name,
        "severity": severity,
        "source": source,
        "device_id": device_id,
        "details": dict(details or {}),
        "outcome": outcome,
        "error_message": _clean_text(error_message) if error_message else None,
        "dedup_key": dedup_key,
        "dedup_window_seconds": dedup_window_seconds,
    }


def _digest(value: str, length: int = 32) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


def _property_map(device: object, properties: Mapping[str, object] | None) -> dict[str, object]:
    result: dict[str, object] = {}
    if isinstance(device, Mapping):
        result.update({str(key).upper(): value for key, value in device.items()})
    else:
        candidate = getattr(device, "properties", None)
        if isinstance(candidate, Mapping):
            result.update({str(key).upper(): value for key, value in candidate.items()})
        for attribute, key in (("device_node", "DEVNAME"), ("sys_path", "DEVPATH")):
            value = getattr(device, attribute, None)
            if value:
                result[key] = value
    if properties:
        result.update({str(key).upper(): value for key, value in properties.items()})
    if not isinstance(device, Mapping) and isinstance(device, (str, os.PathLike)):
        text = os.fspath(device)
        result.setdefault("DEVNAME" if text.startswith("/dev/") else "DEVPATH", text)
    return result


def _cached_properties(
    cached: Mapping[str, object] | None,
    aliases: tuple[str, ...],
) -> dict[str, object]:
    if not isinstance(cached, Mapping):
        return {}
    records: list[object] = [cached]
    records.extend(cached.get(alias) for alias in aliases if alias and alias in cached)
    for record in reversed(records):
        if not isinstance(record, Mapping):
            continue
        result: dict[str, object] = {str(key).upper(): value for key, value in record.items()}
        nested = record.get("properties")
        if isinstance(nested, Mapping):
            result.update({str(key).upper(): value for key, value in nested.items()})
        details = record.get("details")
        if isinstance(details, Mapping):
            for key, value in details.items():
                result.setdefault(str(key).upper(), value)
        if result.get("DEVICE_ID") or any(
            result.get(key)
            for key in (
                "ID_WWN_WITH_EXTENSION",
                "ID_WWN",
                "ID_SERIAL_SHORT",
                "ID_SERIAL",
                "ID_FS_UUID",
                "ID_PART_ENTRY_UUID",
            )
        ):
            return result
    return {}


def _stable_device_identity(properties: Mapping[str, object]) -> tuple[str, str]:
    cached_id = _clean_text(properties.get("DEVICE_ID", ""), 180)
    if cached_id and not cached_id.startswith("node:"):
        return cached_id, "cached"

    wwn = _clean_text(
        properties.get("ID_WWN_WITH_EXTENSION") or properties.get("ID_WWN") or "",
        128,
    ).lower()
    if wwn:
        return f"wwn:{wwn}", "wwn"

    serial = _clean_text(
        properties.get("ID_SERIAL_SHORT") or properties.get("ID_SERIAL") or "",
        256,
    )
    if serial:
        return f"serial-sha256:{_digest(serial, 64)}", "serial_hash"

    filesystem_uuid = _clean_text(properties.get("ID_FS_UUID") or properties.get("FS_UUID") or "", 128)
    if filesystem_uuid:
        return f"fs-uuid:{filesystem_uuid.lower()}", "filesystem_uuid"

    partition_uuid = _clean_text(properties.get("ID_PART_ENTRY_UUID") or "", 128)
    if partition_uuid:
        return f"part-uuid:{partition_uuid.lower()}", "partition_uuid"

    vendor = _clean_text(properties.get("ID_VENDOR") or properties.get("VENDOR") or "", 96)
    model = _clean_text(properties.get("ID_MODEL") or properties.get("MODEL") or "", 128)
    label = _clean_text(properties.get("ID_FS_LABEL") or properties.get("LABEL") or "", 128)
    components = [part for part in (vendor, model, label) if part]
    if components:
        return f"identity-sha256:{_digest(chr(0).join(components), 64)}", "metadata_hash"
    return "", "unavailable"


def build_device_event(
    action: str,
    device: object,
    properties: Mapping[str, object] | None,
    cached: Mapping[str, object] | None,
) -> Event:
    """Build one sanitized udev device event with a stable identity when possible.

    Serial numbers are represented only as SHA-256 digests.  For removal
    events, callers can pass a mapping previously cached by device node or
    devpath; a volatile ``/dev/sdX`` name is never promoted to ``device_id``.
    """

    props = _property_map(device, properties)
    device_node = _clean_device_node(props.get("DEVNAME", ""))
    devpath = _clean_text(props.get("DEVPATH", ""), 320)
    cached_props = _cached_properties(cached, tuple(part for part in (device_node, devpath) if part))
    for key, value in cached_props.items():
        props.setdefault(key, value)

    stable_id, identity_source = _stable_device_identity(props)
    normalized_action = _clean_text(action, 40).lower().replace("_", "-")
    name_by_action = {
        "add": "device_connected",
        "device-add": "device_connected",
        "bind": "device_connected",
        "connect": "device_connected",
        "connected": "device_connected",
        "remove": "device_disconnected",
        "device-remove": "device_disconnected",
        "unbind": "device_disconnected",
        "disconnect": "device_disconnected",
        "disconnected": "device_disconnected",
        "mount": "device_mounted",
        "device-mount": "device_mounted",
        "unmount": "device_unmounted",
        "device-unmount": "device_unmounted",
        "change": "device_changed",
        "device-change": "device_changed",
    }
    name = name_by_action.get(normalized_action, "device_changed")

    details: dict[str, Any] = {
        "action": normalized_action or "unknown",
        "identity_source": identity_source,
    }
    if device_node:
        details["device_node"] = device_node
    for source_key, output_key, limit in (
        ("SUBSYSTEM", "subsystem", 40),
        ("DEVTYPE", "device_type", 40),
        ("ID_BUS", "bus", 40),
        ("ID_VENDOR", "vendor", 96),
        ("VENDOR", "vendor", 96),
        ("ID_MODEL", "model", 128),
        ("MODEL", "model", 128),
        ("ID_FS_UUID", "filesystem_uuid", 128),
        ("FS_UUID", "filesystem_uuid", 128),
        ("ID_FS_LABEL", "label", 128),
        ("LABEL", "label", 128),
        ("ID_FS_TYPE", "filesystem", 40),
        ("MOUNT_POINT", "mount_point", 320),
    ):
        value = _clean_text(props.get(source_key, ""), limit)
        if value and output_key not in details:
            details[output_key] = value

    serial = _clean_text(props.get("ID_SERIAL_SHORT") or props.get("ID_SERIAL") or "", 256)
    if serial:
        details["serial_sha256"] = _digest(serial, 64)
    wwn = _clean_text(props.get("ID_WWN_WITH_EXTENSION") or props.get("ID_WWN") or "", 128)
    if wwn:
        details["wwn"] = wwn.lower()
    for size_key in ("SIZE_BYTES", "UDISKS_SIZE"):
        try:
            size = int(str(props.get(size_key, "")))
        except ValueError:
            continue
        if size >= 0:
            details["size_bytes"] = size
            break

    read_only = _clean_text(props.get("RO") or props.get("READ_ONLY") or "", 8).lower()
    if read_only in {"0", "1", "true", "false", "yes", "no"}:
        details["read_only"] = read_only in {"1", "true", "yes"}

    identity_for_dedup = stable_id or _digest(devpath or device_node or "unknown", 32)
    return _event(
        category="hardware",
        name=name,
        severity="info",
        source="udev",
        device_id=stable_id,
        details=details,
        outcome="observed",
        dedup_key=f"udev:{name}:{identity_for_dedup}",
        dedup_window_seconds=10,
    )


def _validated_ip(value: object) -> str:
    candidate = _clean_text(value, 96).split()[0] if str(value).strip() else ""
    if not candidate:
        return ""
    try:
        address = ipaddress.ip_interface(candidate)
    except ValueError:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return ""
    return str(address)


def build_network_event(interface: str, action: str, env: Mapping[str, object] | None) -> Event:
    """Build an allowlisted NetworkManager dispatcher event.

    Arbitrary environment variables, BSSIDs/MACs, DNS data, command lines, and
    credential-like fields are intentionally ignored.
    """

    safe_env = {str(key).upper(): value for key, value in (env or {}).items()}
    iface = _clean_interface(interface or safe_env.get("DEVICE_IP_IFACE", ""))
    normalized_action = _clean_text(action, 48).lower().replace("_", "-")
    connection_type = _clean_text(safe_env.get("CONNECTION_TYPE", ""), 80).lower()
    is_wifi = "wireless" in connection_type or connection_type in {"wifi", "802-11-wireless"} or iface.startswith("wl")

    if normalized_action == "vpn-up":
        name, severity, outcome = "vpn_connected", "info", "recovery"
    elif normalized_action == "vpn-down":
        name, severity, outcome = "vpn_disconnected", "info", "observed"
    elif normalized_action in {"up", "connect", "connected"}:
        name = "wifi_connected" if is_wifi else "network_connected"
        severity, outcome = "info", "recovery"
    elif normalized_action in {"down", "disconnect", "disconnected", "pre-down"}:
        name = "wifi_disconnected" if is_wifi else "network_disconnected"
        severity, outcome = "info", "observed"
    elif normalized_action in {"dhcp4-change", "dhcp6-change"}:
        name, severity, outcome = "network_address_changed", "info", "observed"
    elif normalized_action == "connectivity-change":
        connectivity = _clean_text(safe_env.get("CONNECTIVITY_STATE", "unknown"), 32).lower()
        name = "network_online" if connectivity == "full" else "network_connectivity_changed"
        severity = "info"
        outcome = "recovery" if connectivity == "full" else "observed"
    else:
        name, severity, outcome = "network_state_changed", "info", "observed"

    details: dict[str, Any] = {"action": normalized_action or "unknown"}
    if iface:
        details["interface"] = iface
    if connection_type in {"802-11-wireless", "wifi", "vpn", "wireguard", "tun"}:
        details["connection_type"] = connection_type

    # A connection profile name may be the SSID.  Keep it only while connecting;
    # disconnect events do not create an unnecessary SSID history.
    if name in {"wifi_connected", "network_connected", "vpn_connected"}:
        connection = _clean_text(safe_env.get("CONNECTION_ID", ""), 128)
        if connection:
            details["ssid" if is_wifi else "connection"] = connection

    for key in ("IP4_ADDRESS_0", "IP6_ADDRESS_0"):
        address = _validated_ip(safe_env.get(key, ""))
        if address:
            details["ip_address"] = address
            break
    for key in ("IP4_GATEWAY", "IP6_GATEWAY"):
        gateway = _validated_ip(safe_env.get(key, ""))
        if gateway:
            details["gateway"] = gateway
            break
    connectivity = _clean_text(safe_env.get("CONNECTIVITY_STATE", ""), 32).lower()
    if connectivity in {"unknown", "none", "portal", "limited", "full"}:
        details["connectivity"] = connectivity

    identity = iface or "global"
    return _event(
        category="network",
        name=name,
        severity=severity,
        source="NetworkManager",
        device_id=f"interface:{iface}" if iface else "",
        details=details,
        outcome=outcome,
        dedup_key=f"network:{name}:{identity}",
        dedup_window_seconds=30,
    )


def build_lifecycle_event(action: str) -> Event:
    """Build a system lifecycle event from a systemd action."""

    normalized = _clean_text(action, 48).lower().replace("_", "-")
    aliases = {"post-suspend": "resume", "wake": "resume", "poweroff": "shutdown"}
    normalized = aliases.get(normalized, normalized)
    names = {
        "boot": "system_boot",
        "shutdown": "system_shutdown",
        "reboot": "system_reboot",
        "suspend": "system_suspend",
        "hibernate": "system_hibernate",
        "resume": "system_resume",
    }
    name = names.get(normalized, "system_lifecycle_changed")
    return _event(
        category="system",
        name=name,
        severity="info",
        source="systemd",
        details={"action": normalized or "unknown"},
        outcome="recovery" if normalized == "resume" else "observed",
        dedup_key=f"lifecycle:{name}",
        dedup_window_seconds=10,
    )


def _is_kernel(entry: Mapping[str, object]) -> bool:
    return entry.get("_TRANSPORT") == "kernel"


def _is_udisks(entry: Mapping[str, object]) -> bool:
    return entry.get("_SYSTEMD_UNIT") == "udisks2.service"


def _is_network_manager(entry: Mapping[str, object]) -> bool:
    return entry.get("_SYSTEMD_UNIT") == "NetworkManager.service"


def _is_smartd(entry: Mapping[str, object]) -> bool:
    return entry.get("_SYSTEMD_UNIT") == "smartd.service" or entry.get("SYSLOG_IDENTIFIER") == "smartd"


def _classify_smartd(message: str) -> Event | None:
    match = _SMARTD_ALERT_RE.match(message)
    if not match:
        return None
    device = _clean_device_node(match.group("device"))
    bridge = _clean_text(match.group("bridge"), 120)
    problem = _clean_text(match.group("problem"), 300)
    digest = _digest(f"{device}:{bridge}:{problem}")
    severity = "warning" if "No such device" in problem or "failed to read NVMe SMART/Health Information" in problem else "critical"
    event = _event(
        category="hardware",
        name="smartd_smart_alert",
        severity=severity,
        source="smartd",
        device_id=f"smartd:{_digest(device + ':' + bridge)}",
        details={"device_node": device, "bridge": bridge, "smartd_message": f"Device: {device} [{bridge}], {problem}"},
        outcome="failed",
        error_message=problem,
        dedup_key=f"smartd:smart-alert:{digest}",
        dedup_window_seconds=3600,
    )
    event["message"] = f"SMART disk alert: {problem}"
    return event


def _classify_kernel(entry: Mapping[str, object], message: str) -> Event | None:
    match = _OOM_RE.match(message)
    if match:
        pid = int(match.group("pid"))
        executable = Path(_clean_text(match.group("process"), 64)).name
        return _event(
            category="system",
            name="oom_kill",
            severity="critical",
            source="kernel",
            details={"pid": pid, "executable": executable},
            outcome="failed",
            error_message="kernel out-of-memory killer terminated a process",
            dedup_key=f"kernel:oom:{entry.get('_BOOT_ID', '')}:{pid}",
        )

    match = _KERNEL_PANIC_RE.match(message)
    if match:
        reason = _clean_text(match.group("reason") or "kernel panic", 240)
        return _event(
            category="system",
            name="kernel_panic",
            severity="emergency",
            source="kernel",
            details={"reason": reason},
            outcome="failed",
            error_message="kernel panic",
            dedup_key=f"kernel:panic:{entry.get('_BOOT_ID', '')}",
        )

    match = _KERNEL_OOPS_RE.match(message)
    if match:
        return _event(
            category="system",
            name="kernel_oops",
            severity="critical",
            source="kernel",
            details={"signature": _clean_text(match.group("kind"), 180)},
            outcome="failed",
            error_message="kernel oops",
            dedup_key=f"kernel:oops:{entry.get('_BOOT_ID', '')}:{_digest(match.group('kind'))}",
        )

    for pattern in _IO_ERROR_RES:
        match = pattern.match(message)
        if match:
            device = _clean_text(match.group("device"), 96)
            return _event(
                category="hardware",
                name="disk_io_error",
                severity="critical",
                source="kernel",
                details={"kernel_device": device},
                outcome="failed",
                error_message="kernel reported a block I/O error",
                dedup_key=f"kernel:io:{_digest(device)}",
            )

    match = _USB_RESET_RE.match(message)
    if match:
        port = match.group("port")
        return _event(
            category="hardware",
            name="usb_reset",
            severity="info",
            source="kernel",
            device_id=f"usb-port:{port}" if _USB_PORT_RE.fullmatch(port) else "",
            details={"usb_port": port, "device_number": int(match.group("number"))},
            dedup_key=f"kernel:usb-reset:{port}",
            dedup_window_seconds=300,
        )

    match = _USB_DISCONNECT_RE.match(message)
    if match:
        port = match.group("port")
        return _event(
            category="hardware",
            name="usb_disconnected",
            severity="info",
            source="kernel",
            device_id=f"usb-port:{port}" if _USB_PORT_RE.fullmatch(port) else "",
            details={"usb_port": port, "device_number": int(match.group("number"))},
            dedup_key=f"kernel:usb-disconnect:{port}",
            dedup_window_seconds=10,
        )

    match = _EXT_RO_RE.match(message) or _BTRFS_RO_RE.match(message)
    if match:
        device = _clean_text(match.group("device"), 96)
        filesystem = _clean_text(match.groupdict().get("filesystem", ""), 32)
        details = {"kernel_device": device}
        if filesystem:
            details["filesystem"] = filesystem.lower()
        return _event(
            category="hardware",
            name="filesystem_read_only",
            severity="critical",
            source="kernel",
            details=details,
            outcome="failed",
            error_message="filesystem was remounted read-only",
            dedup_key=f"kernel:read-only:{_digest(device)}",
        )

    match = _THERMAL_RE.match(message)
    if match:
        critical = "critical" in match.group("condition").lower()
        return _event(
            category="hardware",
            name="thermal_critical" if critical else "thermal_throttling",
            severity="critical" if critical else "warning",
            source="kernel",
            details={"sensor": _clean_text(match.group("subject"), 48)},
            outcome="failed" if critical else "observed",
            error_message="kernel reported a critical temperature" if critical else None,
            dedup_key=f"kernel:thermal:{_digest(match.group('subject'))}:{critical}",
        )

    if _HARDWARE_ERROR_RE.match(message):
        return _event(
            category="hardware",
            name="hardware_error",
            severity="critical",
            source="kernel",
            details={"type": "machine_check_or_edac"},
            outcome="failed",
            error_message="kernel reported a hardware error",
            dedup_key=f"kernel:hardware-error:{entry.get('_BOOT_ID', '')}:{_digest(message[:160])}",
        )
    return None


def _classify_systemd(entry: Mapping[str, object], message: str) -> Event | None:
    identifier = entry.get("SYSLOG_IDENTIFIER")
    if identifier != "systemd" and str(entry.get("_PID", "")) != "1":
        return None

    unit = _clean_unit(entry.get("UNIT", ""))
    job_result = _clean_text(entry.get("JOB_RESULT", ""), 48).lower()
    message_id = str(entry.get("MESSAGE_ID", ""))
    match = _SYSTEMD_FAILED_RE.match(message)
    if match:
        unit = _clean_unit(match.group("unit"))
        result = _clean_text(match.group("result"), 48)
    elif unit and job_result and job_result not in {"done", "skipped", "canceled"}:
        result = job_result
    elif unit and message_id == _SYSTEMD_FAILED_MESSAGE_ID:
        result = _clean_text(entry.get("RESULT", "failed"), 48) or "failed"
    else:
        start_match = _SYSTEMD_START_FAILED_RE.match(message)
        if not (start_match and unit):
            return None
        result = "start-failed"
    if not unit:
        return None
    return _event(
        category="service",
        name="systemd_unit_failed",
        severity="critical" if unit in {"NetworkManager.service", "firewalld.service"} else "warning",
        source="systemd",
        device_id=f"systemd-unit:{unit}",
        details={"unit": unit, "result": result},
        outcome="failed",
        error_message=f"systemd unit failed: {unit}",
        dedup_key=f"systemd:failed:{unit}:{result}",
    )


def _classify_udisks(message: str) -> Event | None:
    match = _UDISKS_UNSAFE_RE.match(message)
    if match:
        mount_point = _clean_text(match.group("mount"), 320)
        major_minor = f"{match.group('major')}:{match.group('minor')}"
        return _event(
            category="hardware",
            name="unsafe_device_removal",
            severity="warning",
            source="udisks2",
            details={"mount_point": mount_point, "major_minor": major_minor},
            outcome="failed",
            error_message="mounted device disappeared before clean unmount",
            dedup_key=f"udisks:unsafe:{_digest(mount_point)}",
            dedup_window_seconds=30,
        )

    match = _UDISKS_MOUNTED_RE.match(message)
    if match:
        device = _clean_device_node(match.group("device"))
        read_only = match.group("mode") == "Read-Only"
        return _event(
            category="hardware",
            name="device_mounted",
            severity="warning" if read_only else "info",
            source="udisks2",
            details={
                "device_node": device,
                "read_only": read_only,
                "label": _clean_text(match.group("label"), 128),
                "filesystem": _clean_text(match.group("filesystem"), 80),
            },
            outcome="observed",
            dedup_key=f"udisks:mounted:{_digest(device)}:{read_only}",
            dedup_window_seconds=10,
        )

    match = _UDISKS_MOUNTED_AT_RE.match(message)
    if match:
        device = _clean_device_node(match.group("device"))
        return _event(
            category="hardware",
            name="device_mounted",
            severity="info",
            source="udisks2",
            details={
                "device_node": device,
                "mount_point": _clean_text(match.group("mount"), 320),
                "uid": int(match.group("uid")),
            },
            dedup_key=f"udisks:mounted:{_digest(device)}",
            dedup_window_seconds=10,
        )

    match = _UDISKS_UNMOUNT_RE.match(message)
    if match:
        device = _clean_device_node(match.group("device"))
        details: dict[str, Any] = {"device_node": device}
        if match.groupdict().get("uid"):
            details["uid"] = int(match.group("uid"))
        return _event(
            category="hardware",
            name="device_unmounted",
            severity="info",
            source="udisks2",
            details=details,
            outcome="observed",
            dedup_key=f"udisks:unmounted:{_digest(device)}",
            dedup_window_seconds=10,
        )

    match = _UDISKS_FAILURE_RE.match(message)
    if match:
        operation = (match.group("verb") or match.group("gerund")[:-3]).lower()
        device = _clean_device_node(match.group("device"))
        error = _clean_text(match.group("error"), 320)
        details = {"device_node": device, "operation": operation}
        if match.group("mount"):
            details["mount_point"] = _clean_text(match.group("mount"), 320)
        return _event(
            category="hardware",
            name=f"device_{operation}_failed",
            severity="warning",
            source="udisks2",
            details=details,
            outcome="failed",
            error_message=error,
            dedup_key=f"udisks:{operation}-failed:{_digest(device + error)}",
        )

    match = _UDISKS_IO_RE.match(message)
    if match:
        device = _clean_device_node(match.group("device"))
        operation = _clean_text(match.group("operation"), 40)
        return _event(
            category="hardware",
            name="disk_io_error",
            severity="critical",
            source="udisks2",
            details={"device_node": device, "operation": operation},
            outcome="failed",
            error_message="I/O error while finalizing an external volume",
            dedup_key=f"udisks:io:{_digest(device)}",
        )
    return None


def _classify_network_manager(message: str) -> Event | None:
    match = _NM_STATE_RE.match(message)
    if match:
        interface = match.group("interface")
        old_state = match.group("old")
        new_state = match.group("new")
        if new_state == "activated":
            return build_network_event(interface, "up", {"CONNECTION_TYPE": "wifi" if interface.startswith("wl") else ""})
        if old_state == "activated" and new_state in {"deactivating", "disconnected", "failed", "unavailable", "unmanaged"}:
            event = build_network_event(interface, "down", {"CONNECTION_TYPE": "wifi" if interface.startswith("wl") else ""})
            event["details"].update({"old_state": old_state, "new_state": new_state})
            if new_state == "failed":
                event["severity"] = "warning"
                event["outcome"] = "failed"
            return event
        return None

    match = _NM_MANAGER_STATE_RE.match(message)
    if match:
        state = match.group("state")
        online = state == "CONNECTED_GLOBAL"
        offline = state in {"DISCONNECTED", "DISABLED (ASLEEP)"}
        return _event(
            category="network",
            name=(
                "networkmanager_online"
                if online
                else "networkmanager_offline"
                if offline
                else "networkmanager_state_changed"
            ),
            severity="info",
            source="NetworkManager",
            details={"state": state.lower().replace(" ", "_")},
            outcome="recovery" if online else "observed",
            dedup_key=f"networkmanager:state:{state}",
            dedup_window_seconds=30,
        )

    match = _NM_VPN_STATE_RE.match(message)
    if match:
        state = match.group("state")
        event = build_network_event("", "vpn-up" if state == "activated" else "vpn-down", {})
        event["details"]["state"] = state
        if state == "failed":
            event["name"] = "vpn_connection_failed"
            event["severity"] = "warning"
            event["outcome"] = "failed"
            event["error_message"] = "NetworkManager VPN connection failed"
            event["dedup_key"] = "network:vpn-failed:global"
        return event

    match = _NM_DHCP_RE.match(message)
    if match:
        interface = match.group("interface")
        address = _validated_ip(match.group("address"))
        return _event(
            category="network",
            name="network_address_changed",
            severity="info",
            source="NetworkManager",
            device_id=f"interface:{interface}",
            details={"interface": interface, "ip_address": address, "family": int(match.group("family"))},
            dedup_key=f"network:address:{interface}:{_digest(address)}",
            dedup_window_seconds=30,
        )

    match = _NM_DEFAULT_RE.match(message)
    if match:
        interface = match.group("interface")
        connection = _clean_text(match.group("connection"), 128)
        return _event(
            category="network",
            name="wifi_connected" if interface.startswith("wl") else "network_connected",
            severity="info",
            source="NetworkManager",
            device_id=f"interface:{interface}",
            details={
                "interface": interface,
                "ssid" if interface.startswith("wl") else "connection": connection,
            },
            outcome="recovery",
            dedup_key=f"network:default:{interface}:{_digest(connection)}",
            dedup_window_seconds=30,
        )
    return None


def _classify_coredump(entry: Mapping[str, object]) -> Event:
    executable = Path(
        _clean_text(entry.get("COREDUMP_EXE") or entry.get("COREDUMP_COMM") or "unknown", 320)
    ).name[:128]
    signal = _clean_text(
        entry.get("COREDUMP_SIGNAL_NAME") or entry.get("COREDUMP_SIGNAL") or "unknown",
        32,
    )
    unit = _clean_unit(entry.get("COREDUMP_UNIT", ""))
    uid_text = _clean_text(entry.get("COREDUMP_UID") or entry.get("_UID") or "", 20)
    uid = int(uid_text) if uid_text.isdigit() else None
    details: dict[str, Any] = {"executable": executable, "signal": signal, "uid": uid}
    if unit:
        details["unit"] = unit
    return _event(
        category="system",
        name="process_coredump",
        severity="warning",
        source="systemd-coredump",
        device_id=f"systemd-unit:{unit}" if unit else "",
        details=details,
        outcome="failed",
        error_message="process dumped core",
        dedup_key=f"coredump:{unit}:{executable}:{signal}",
        dedup_window_seconds=60,
    )


def classify_journal(entry: Mapping[str, object] | object) -> Event | None:
    """Classify one journal JSON mapping without retaining its raw payload."""

    if not isinstance(entry, Mapping):
        return None
    message_id = str(entry.get("MESSAGE_ID", ""))
    coredump_source = entry.get("SYSLOG_IDENTIFIER") == "systemd-coredump" or str(
        entry.get("_SYSTEMD_UNIT", "")
    ).startswith("systemd-coredump@")
    if message_id == _COREDUMP_MESSAGE_ID and coredump_source:
        graphics_event = classify_graphics_coredump(entry)
        return graphics_event or _classify_coredump(entry)

    raw_message = entry.get("MESSAGE", "")
    if not isinstance(raw_message, str) or not raw_message or len(raw_message) > _MAX_JOURNAL_LINE:
        return None
    message = _CONTROL_RE.sub(" ", raw_message).strip()

    graphics_event = classify_gnome_journal(entry, message)
    if graphics_event:
        return graphics_event
    if _is_kernel(entry):
        graphics_event = classify_graphics_kernel(entry, message)
        return graphics_event or _classify_kernel(entry, message)
    if _is_udisks(entry):
        event = _classify_udisks(message)
        if event:
            return event
    if _is_network_manager(entry):
        event = _classify_network_manager(message)
        if event:
            return event
    if _is_smartd(entry):
        event = _classify_smartd(message)
        if event:
            return event

    comm = entry.get("_COMM")
    identifier = entry.get("SYSLOG_IDENTIFIER")
    sleep_source = comm == "systemd-sleep" or identifier == "systemd-sleep"
    if sleep_source:
        match = _SLEEP_START_RE.match(message)
        if match:
            return build_lifecycle_event(match.group("mode"))
        match = _SLEEP_RETURN_RE.match(message)
        if match:
            event = build_lifecycle_event("resume")
            event["details"]["sleep_mode"] = match.group("mode")
            return event

    if identifier == "systemd-journald" and _UNCLEAN_JOURNAL_RE.match(message):
        return _event(
            category="system",
            name="unclean_shutdown_detected",
            severity="warning",
            source="systemd-journald",
            details={"journal_recovery": True},
            outcome="failed",
            error_message="journal detected an unclean shutdown",
            dedup_key=f"system:unclean-shutdown:{entry.get('_BOOT_ID', '')}",
        )

    return _classify_systemd(entry, message)


def _config_number(config: Mapping[str, object] | object, paths: tuple[tuple[str, ...], ...], default: int) -> int:
    if not isinstance(config, Mapping):
        return default
    for path in paths:
        value: object = config
        for part in path:
            if not isinstance(value, Mapping) or part not in value:
                break
            value = value[part]
        else:
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
                return int(value)
    return default


def _stored_cursor(db: object) -> str:
    try:
        state = db.get_state("journal_cursor", {})
    except (AttributeError, TypeError, ValueError):
        return ""
    if not isinstance(state, Mapping):
        return ""
    cursor = state.get("cursor")
    if not isinstance(cursor, str) or not cursor or len(cursor) > 1024 or _CONTROL_RE.search(cursor):
        return ""
    return cursor


def _cursor_is_valid(cursor: str, timeout: int) -> bool:
    if not cursor:
        return False
    try:
        result = subprocess.run(
            ["journalctl", f"--after-cursor={cursor}", "--lines=0", "--no-pager"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=max(1, min(timeout, 15)),
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _journal_command(cursor: str, lookback_seconds: int) -> list[str]:
    fields = ",".join(
        (
            "MESSAGE",
            "MESSAGE_ID",
            "PRIORITY",
            "_TRANSPORT",
            "SYSLOG_IDENTIFIER",
            "_SYSTEMD_UNIT",
            "_SYSTEMD_USER_UNIT",
            "UNIT",
            "JOB_RESULT",
            "RESULT",
            "_PID",
            "_COMM",
            "_UID",
            "_KERNEL_SUBSYSTEM",
            "_UDEV_SYSNAME",
            "_UDEV_DEVNODE",
            "COREDUMP_EXE",
            "COREDUMP_COMM",
            "COREDUMP_SIGNAL",
            "COREDUMP_SIGNAL_NAME",
            "COREDUMP_UNIT",
            "COREDUMP_UID",
        )
    )
    command = [
        "journalctl",
        "--follow",
        "--output=json",
        "--no-pager",
        f"--output-fields={fields}",
    ]
    if cursor:
        command.append(f"--after-cursor={cursor}")
    else:
        command.append(f"--since=-{lookback_seconds}s")
    # Each match group is an OR branch.  This keeps unrelated application logs
    # out of the follower and prevents accidental processing of private data.
    command.extend(
        (
            "_TRANSPORT=kernel",
            "+",
            "SYSLOG_IDENTIFIER=systemd",
            "+",
            "SYSLOG_IDENTIFIER=systemd-journald",
            "+",
            "SYSLOG_IDENTIFIER=systemd-sleep",
            "+",
            "_SYSTEMD_UNIT=udisks2.service",
            "+",
            "_SYSTEMD_UNIT=NetworkManager.service",
            "+",
            "_SYSTEMD_UNIT=smartd.service",
            "+",
            "SYSLOG_IDENTIFIER=gnome-shell",
            "+",
            "_COMM=gnome-shell",
            "+",
            "_SYSTEMD_USER_UNIT=org.gnome.Shell@wayland.service",
            "+",
            f"MESSAGE_ID={_COREDUMP_MESSAGE_ID}",
        )
    )
    return command


def _persist_event(db: object, event: Event) -> None:
    try:
        db.insert_events([event], dedup_window_seconds=int(event["dedup_window_seconds"]))
    except TypeError:
        # Supports the deliberately tiny fake DB used by integrations while the
        # production Database accepts the explicit deduplication window.
        db.insert_events([event])


def _persist_cursor(db: object, entry: Mapping[str, object]) -> None:
    state = _journal_identity(entry)
    if not state["cursor"]:
        return
    db.set_state("journal_cursor", state)


def _iso_from_unix(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _dbus_call_uint(method: str, sender: str) -> int | None:
    try:
        completed = subprocess.run(
            [
                "busctl",
                "--system",
                "call",
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                method,
                "s",
                sender,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    match = re.search(r"\bu\s+([0-9]+)\b", completed.stdout)
    return int(match.group(1)) if match else None


def _dbus_sender_identity(sender: str) -> dict[str, object]:
    identity: dict[str, object] = {"sender": sender}
    pid = _dbus_call_uint("GetConnectionUnixProcessID", sender)
    uid = _dbus_call_uint("GetConnectionUnixUser", sender)
    if pid is not None:
        identity["pid"] = pid
        try:
            identity["process"] = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8", errors="replace").strip()[:64]
        except OSError:
            pass
        try:
            identity["executable"] = Path(os.readlink(f"/proc/{pid}/exe")).name[:128]
        except OSError:
            pass
    if uid is not None:
        identity["uid"] = uid
        try:
            identity["user"] = pwd.getpwuid(uid).pw_name[:64]
        except KeyError:
            pass
    return identity


def _power_profile_event_from_dbus(lines: list[str], *, caller: Mapping[str, object] | None = None) -> Event | None:
    if not lines:
        return None
    header = _DBUS_METHOD_RE.match(lines[0])
    if not header:
        return None
    path = header.group("path")
    interface = header.group("interface")
    method = header.group("member")
    if path not in _POWER_PROFILE_DBUS_PATHS:
        return None
    if interface == "org.freedesktop.DBus.Properties" and method != "Set":
        return None
    if interface in _POWER_PROFILE_DBUS_INTERFACES and method not in {"HoldProfile", "ReleaseProfile"}:
        return None
    if interface not in {"org.freedesktop.DBus.Properties", *_POWER_PROFILE_DBUS_INTERFACES}:
        return None
    values: list[str] = []
    requested_profile = ""
    cookie: int | None = None
    for line in lines[1:]:
        string_match = _DBUS_STRING_RE.match(line)
        if string_match:
            values.append(string_match.group("value"))
            continue
        variant_match = _DBUS_VARIANT_STRING_RE.match(line)
        if variant_match:
            requested_profile = variant_match.group("value")
            continue
        uint_match = _DBUS_UINT_RE.match(line)
        if uint_match:
            cookie = int(uint_match.group("value"))
    details: dict[str, Any] = {"path": path, "interface": interface, "method": method}
    event_name = ""
    dedup_parts: list[object] = [method]
    if interface == "org.freedesktop.DBus.Properties":
        if len(values) < 2 or values[1] != "ActiveProfile" or requested_profile not in {"power-saver", "balanced", "performance"}:
            return None
        event_name = "power_profile_set_requested"
        details.update({"requested_profile": requested_profile, "property": values[1], "property_interface": values[0]})
        dedup_parts.extend((requested_profile,))
    elif method == "HoldProfile":
        if not values or values[0] not in {"power-saver", "balanced", "performance"}:
            return None
        event_name = "power_profile_hold_requested"
        details["requested_profile"] = values[0]
        if len(values) > 1:
            details["reason"] = _clean_text(values[1], 160)
        if len(values) > 2:
            details["application_id"] = _clean_text(values[2], 160)
        dedup_parts.extend(values[:3])
    elif method == "ReleaseProfile":
        if cookie is None:
            return None
        event_name = "power_profile_release_requested"
        details["cookie"] = cookie
        dedup_parts.append(cookie)
    else:
        return None
    timestamp = float(header.group("time"))
    sender = header.group("sender")
    details["caller"] = dict(caller or _dbus_sender_identity(sender))
    event = _event(
        category="system",
        name=event_name,
        severity="info",
        source="dbus-monitor",
        device_id="power-profile",
        details=details,
        outcome="observed",
        dedup_key=f"dbus:power-profile:{sender}:{':'.join(str(part) for part in dedup_parts)}:{timestamp:.6f}",
        dedup_window_seconds=0,
    )
    event["timestamp_utc"] = _iso_from_unix(timestamp)
    event["details"]["activitywatch"] = correlate_activitywatch(str(event["timestamp_utc"]))
    event["value"] = 1
    event["unit"] = "event"
    return event


def _power_profile_dbus_event_is_complete(lines: list[str]) -> bool:
    header = _DBUS_METHOD_RE.match(lines[0]) if lines else None
    if not header:
        return False
    method = header.group("member")
    if method == "Set":
        return any(_DBUS_VARIANT_STRING_RE.match(line) for line in lines[1:])
    if method == "HoldProfile":
        return sum(1 for line in lines[1:] if _DBUS_STRING_RE.match(line)) >= 3
    if method == "ReleaseProfile":
        return any(_DBUS_UINT_RE.match(line) for line in lines[1:])
    return False


def _persist_power_profile_dbus_lines(
    lines: list[str],
    db: object,
    on_event: Callable[[Event], object] | None,
) -> int:
    event = _power_profile_event_from_dbus(lines)
    if event is None:
        return 0
    db.insert_events([event], dedup_window_seconds=0)
    if on_event is not None:
        on_event(event)
    return 1


def _consume_power_profile_dbus_stream(
    process: subprocess.Popen[str],
    db: object,
    stop_event: object | None = None,
    on_event: Callable[[Event], object] | None = None,
) -> int:
    matched = 0
    current: list[str] = []
    assert process.stdout is not None
    while stop_event is None or not bool(getattr(stop_event, "is_set")()):
        line = process.stdout.readline()
        if line == "":
            break
        if _DBUS_METHOD_RE.match(line):
            if current:
                matched += _persist_power_profile_dbus_lines(current, db, on_event)
            current = [line]
            continue
        if not current:
            continue
        current.append(line)
        if not _power_profile_dbus_event_is_complete(current):
            continue
        matched += _persist_power_profile_dbus_lines(current, db, on_event)
        current = []
    if current:
        matched += _persist_power_profile_dbus_lines(current, db, on_event)
    return matched


def _platform_profile_snapshot(sys_root: Path = Path("/sys")) -> dict[str, Any]:
    profile_path = sys_root / "firmware" / "acpi" / "platform_profile"
    try:
        value = profile_path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        value = ""
    details: dict[str, Any] = {
        "path": str(profile_path),
        "platform_profile": _clean_text(value, 64) if value else "unavailable",
        "external_online": False,
        "batteries": [],
    }
    supplies = sys_root / "class" / "power_supply"
    try:
        supply_paths = sorted(supplies.iterdir())
    except OSError:
        supply_paths = []
    batteries: list[dict[str, Any]] = []
    for supply in supply_paths:
        try:
            supply_type = (supply / "type").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if supply_type in {"Mains", "USB", "USB_C"}:
            try:
                online = (supply / "online").read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                online = ""
            details["external_online"] = bool(details["external_online"] or online == "1")
        elif supply_type == "Battery":
            battery: dict[str, Any] = {"device": _clean_text(supply.name, 64)}
            try:
                status = (supply / "status").read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                status = ""
            if status:
                battery["status"] = _clean_text(status, 64)
            try:
                capacity = int((supply / "capacity").read_text(encoding="utf-8", errors="replace").strip())
            except (OSError, ValueError):
                capacity = -1
            if 0 <= capacity <= 100:
                battery["capacity_percent"] = capacity
            batteries.append(battery)
    details["batteries"] = batteries
    return details


def _record_platform_profile_snapshot(
    db: object,
    snapshot: Mapping[str, Any],
    *,
    on_event: Callable[[Event], object] | None = None,
) -> Event | None:
    current = _clean_text(snapshot.get("platform_profile", ""), 64)
    if not current or current == "unavailable":
        return None
    previous = db.get_state("platform_profile", {}, namespace="eventing")
    db.set_state("platform_profile", dict(snapshot), namespace="eventing")
    if not isinstance(previous, Mapping):
        return None
    old = _clean_text(previous.get("platform_profile", ""), 64)
    if not old or old == current:
        return None
    observed_at = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    event = _event(
        category="system",
        name="platform_profile_changed",
        severity="info",
        source="sysfs",
        device_id="platform",
        details={
            "previous": old,
            "current": current,
            "path": _clean_text(snapshot.get("path", ""), 320),
            "external_online": bool(snapshot.get("external_online")),
            "batteries": list(snapshot.get("batteries", [])) if isinstance(snapshot.get("batteries"), list) else [],
            "observed_at_utc": observed_at,
        },
        outcome="observed",
        dedup_key=f"sysfs:platform-profile:{old}:{current}:{observed_at}",
        dedup_window_seconds=0,
    )
    event["timestamp_utc"] = observed_at
    event["value"] = 1
    event["unit"] = "event"
    db.insert_events([event], dedup_window_seconds=0)
    if on_event is not None:
        on_event(event)
    return event


def stream_platform_profile(
    config: Mapping[str, object],
    db: object,
    stop_event: object | None = None,
    on_event: Callable[[Event], object] | None = None,
) -> int:
    """Persist only real ACPI platform_profile transitions from sysfs."""

    del config
    matched = 0
    while stop_event is None or not bool(getattr(stop_event, "is_set")()):
        event = _record_platform_profile_snapshot(db, _platform_profile_snapshot(), on_event=on_event)
        if event is not None:
            matched += 1
        if stop_event is None:
            break
        getattr(stop_event, "wait")(30)
    return matched


def _journal_identity(entry: Mapping[str, object]) -> dict[str, Any]:
    cursor_value = entry.get("__CURSOR")
    cursor = ""
    if (
        isinstance(cursor_value, str)
        and cursor_value
        and len(cursor_value) <= 1024
        and not _CONTROL_RE.search(cursor_value)
    ):
        cursor = _clean_text(cursor_value, 1024)
    identity: dict[str, Any] = {
        "cursor": cursor,
        "boot_id": _clean_text(entry.get("_BOOT_ID", ""), 64),
    }
    for input_key, output_key in (
        ("__MONOTONIC_TIMESTAMP", "monotonic"),
        ("__REALTIME_TIMESTAMP", "realtime"),
    ):
        value = entry.get(input_key)
        try:
            identity[output_key] = int(str(value))
        except (TypeError, ValueError):
            identity[output_key] = None
    return identity


def _consume_stream(
    process: subprocess.Popen[str],
    db: object,
    stop_event: object | None,
    on_event: Callable[[Event], object] | None,
    config: Mapping[str, object] | None = None,
) -> int:
    if process.stdout is None:
        return 0
    matched = 0

    if stop_event is None:
        line_iterator = iter(process.stdout.readline, "")
        for line in line_iterator:
            matched += _consume_journal_line(line, db, on_event, config)
        return matched

    try:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
    except (AttributeError, OSError, ValueError):
        # StringIO-style test doubles have no selectable file descriptor.
        for line in process.stdout:
            if bool(getattr(stop_event, "is_set")()):
                break
            matched += _consume_journal_line(line, db, on_event, config)
        return matched

    try:
        while not bool(getattr(stop_event, "is_set")()):
            if process.poll() is not None:
                break
            ready = selector.select(timeout=0.5)
            if not ready:
                continue
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                continue
            matched += _consume_journal_line(line, db, on_event, config)
    finally:
        selector.close()
    return matched


def _consume_journal_line(
    line: str,
    db: object,
    on_event: Callable[[Event], object] | None = None,
    config: Mapping[str, object] | None = None,
) -> int:
    if not line or len(line) > _MAX_JOURNAL_LINE:
        return 0
    try:
        entry = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return 0
    event = classify_journal(entry)
    if event is None:
        return 0
    journal_identity = _journal_identity(entry)
    event["details"]["journal_identity"] = journal_identity
    realtime = journal_identity["realtime"]
    if isinstance(realtime, int) and realtime >= 0:
        try:
            event["timestamp_utc"] = datetime.fromtimestamp(
                realtime / 1_000_000,
                tz=timezone.utc,
            ).isoformat(timespec="microseconds").replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            pass
    if is_graphics_incident(event):
        enrich_graphics_incident(config or {}, event)
    # At-least-once ordering: never advance the cursor until the event insert
    # (including deduplication) has completed successfully.
    _persist_event(db, event)
    if on_event is not None:
        on_event(event)
    _persist_cursor(db, entry)
    return 1


def stream_journal(
    config: Mapping[str, object],
    db: object,
    stop_event: object | None = None,
    on_event: Callable[[Event], object] | None = None,
) -> int:
    """Follow relevant journal sources, resuming from the last valid cursor.

    The optional *stop_event* follows the :class:`threading.Event` interface.
    Returning is intentional: systemd owns restart policy if ``journalctl``
    exits unexpectedly.
    """

    if stop_event is not None and bool(getattr(stop_event, "is_set")()):
        return 0
    timeout = _config_number(
        config,
        (("general", "command_timeout_seconds"), ("monitor", "command_timeout_seconds")),
        12,
    )
    lookback_seconds = _config_number(
        config,
        (("events", "journal_lookback_seconds"),),
        0,
    )
    if lookback_seconds <= 0:
        lookback_minutes = _config_number(
            config,
            (("collection", "journal_lookback_minutes"),),
            15,
        )
        lookback_seconds = lookback_minutes * 60

    cursor = _stored_cursor(db)
    if cursor and not _cursor_is_valid(cursor, timeout):
        cursor = ""
    command = _journal_command(cursor, lookback_seconds)
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        close_fds=True,
    )
    try:
        return _consume_stream(process, db, stop_event, on_event, config)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def stream_power_profile_dbus(
    config: Mapping[str, object],
    db: object,
    stop_event: object | None = None,
    on_event: Callable[[Event], object] | None = None,
) -> int:
    """Follow power-profile D-Bus requests and persist every ActiveProfile set."""

    del config
    if stop_event is not None and bool(getattr(stop_event, "is_set")()):
        return 0
    process = subprocess.Popen(
        ["dbus-monitor", "--system", *_POWER_PROFILE_DBUS_MATCHES],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        close_fds=True,
    )
    try:
        return _consume_power_profile_dbus_stream(process, db, stop_event, on_event)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


__all__ = [
    "build_device_event",
    "build_lifecycle_event",
    "build_network_event",
    "classify_journal",
    "stream_journal",
    "stream_platform_profile",
    "stream_power_profile_dbus",
]
