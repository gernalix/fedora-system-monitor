"""Summarize visible journal producers without returning message contents."""
from collections import Counter
import hashlib
import json
import time

from ..collectors.common import external
from ..collectors.unit_resources import split_unit


FIELDS = "_SYSTEMD_UNIT,_SYSTEMD_USER_UNIT,_UID,_TRANSPORT,_COMM,SYSLOG_IDENTIFIER,PRIORITY,MESSAGE"
MAX_OUTPUT = 4_000_000


def producer(row):
    if row.get("_SYSTEMD_USER_UNIT") and row.get("_UID"):
        return f"user:{row['_UID']}:{row['_SYSTEMD_USER_UNIT']}"
    if row.get("_SYSTEMD_UNIT"):
        return f"system:{row['_SYSTEMD_UNIT']}"
    for key in ("_COMM", "SYSLOG_IDENTIFIER"):
        name = row.get(key)
        if isinstance(name, str) and name.isprintable() and 0 < len(name) <= 128:
            return name
    return "unassigned"


def summarize(rows, limit):
    sources = {}
    for row in rows:
        name = producer(row)
        source = sources.setdefault(name, dict(unit=name, entries=0, message_bytes=0, unavailable_messages=0,
                                               by_transport=Counter(), by_priority=Counter(), digests=Counter()))
        source["entries"] += 1
        source["by_transport"][row.get("_TRANSPORT") or "unknown"] += 1
        priority = row.get("PRIORITY")
        source["by_priority"][priority if priority in ("0", "1", "2", "3", "4", "5", "6", "7")
                              else "unknown"] += 1
        message = row.get("MESSAGE")
        if isinstance(message, str):
            raw = message.encode("utf-8")
        elif isinstance(message, list) and all(isinstance(b, int) and 0 <= b <= 255 for b in message):
            raw = bytes(message)
        else:
            source["unavailable_messages"] += 1
            continue
        source["message_bytes"] += len(raw)
        source["digests"][hashlib.blake2s(raw).digest()] += 1
    ranked = sorted(sources.values(), key=lambda item: (-item["entries"], item["unit"]))
    for source in ranked:
        counts = source.pop("digests").values()
        source["most_repeated"] = max(counts, default=0)
        source["repeated_entries"] = sum(count for count in counts if count > 1)
    return ranked[:limit]


def report(args, *, now=None):
    end = time.time() if now is None else now
    start = end - 60 * args.minutes
    command = ["journalctl", "-b", "-q", "--no-pager", "--output=json",
               f"--output-fields={FIELDS}", f"--since=@{start:.6f}", f"--until=@{end:.6f}",
               f"--lines={args.lines + 1}"]
    if args.cursor:
        command.append("--after-cursor=" + args.cursor)
    if args.unit:
        manager, name = split_unit(args.unit)
        if manager == "system":
            command.append("_SYSTEMD_UNIT=" + name)
        else:
            command.extend(("_SYSTEMD_USER_UNIT=" + name, "_UID=" + manager.removeprefix("user:")))
    result = external({}, command, timeout=15, max_output=MAX_OUTPUT)
    if not result.ok or len(result.stdout) >= MAX_OUTPUT:
        raise ValueError("Lettura del journal incompleta: ridurre la finestra o il numero di righe.")
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    clipped = len(rows) > args.lines
    rows = rows[-args.lines:]
    cursor = (rows[-1].get("__CURSOR") if rows else None) or args.cursor
    return dict(entries=len(rows), producers=summarize(rows, args.limit), truncated=clipped,
                cursor=args.cursor if clipped else cursor), 0
