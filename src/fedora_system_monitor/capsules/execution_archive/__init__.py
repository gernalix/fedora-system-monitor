"""Private execution archive. Manifests own originals; SQLite is a rebuildable index.

No arbitrary file importer, argv/env serializer, browser or conversation source.
Content capture is restricted to fixed, environment-independent diagnostics.
"""
from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import time
import uuid
from pathlib import Path

SOURCES = {"bash", "manual", "diagnostic"}
LABELS = {"shell", "excluded", "date", "uname", "uptime", "true", "false", "demo"}
SAFE = {
    ("date",): ("/usr/bin/date",),
    ("date", "-u"): ("/usr/bin/date", "-u"),
    ("uname",): ("/usr/bin/uname",),
    ("uname", "-a"): ("/usr/bin/uname", "-a"),
    ("uptime",): ("/usr/bin/uptime",),
    ("true",): ("/usr/bin/true",),
    ("false",): ("/usr/bin/false",),
}
DEFAULTS = {"quota_bytes": 256 * 1024 * 1024, "retention_days": 30,
            "event_bytes": 8 * 1024 * 1024}
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def root_path() -> Path:
    # A fixed per-user root; never infer external storage or backup availability.
    return Path.home() / ".local/state/fedora-system-monitor/executions"


def private_dir(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("symlink refused")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_uid != os.getuid():
        raise ValueError("foreign owner refused")
    path.chmod(0o700)


def private_file(path: Path, mode: str = "wb"):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    flags |= os.O_APPEND if "a" in mode else os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    if os.fstat(fd).st_uid != os.getuid():
        os.close(fd)
        raise ValueError("foreign file refused")
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, mode)


def atomic_json(path: Path, value: dict) -> None:
    tmp = path.with_suffix(".tmp")
    with private_file(tmp) as f:
        f.write((json.dumps(value, sort_keys=True) + "\n").encode())
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fingerprint(pid: int) -> str:
    try:
        # start ticks plus boot ID prevents recovery mistakes on PID reuse.
        ticks = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + ticks
    except (OSError, IndexError):
        return ""


class Zstd:
    """Use the system libzstd, without a new Python environment or package."""
    def __init__(self):
        self.lib = ctypes.CDLL(ctypes.util.find_library("zstd") or "libzstd.so.1")
        for name, args in {
            "ZSTD_compressBound": [ctypes.c_size_t],
            "ZSTD_compress": [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                              ctypes.c_size_t, ctypes.c_int],
            "ZSTD_decompress": [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t],
            "ZSTD_isError": [ctypes.c_size_t],
        }.items():
            fn = getattr(self.lib, name)
            fn.argtypes = args
            fn.restype = ctypes.c_size_t

    def compress(self, data: bytes) -> bytes:
        target = ctypes.create_string_buffer(self.lib.ZSTD_compressBound(len(data)))
        size = self.lib.ZSTD_compress(target, len(target), data, len(data), 3)
        if self.lib.ZSTD_isError(size):
            raise ValueError("compression failed")
        return target.raw[:size]

    def decompress(self, data: bytes, size: int) -> bytes:
        if not 0 <= size <= 64 * 1024 * 1024:
            raise ValueError("invalid frame size")
        target = ctypes.create_string_buffer(max(1, size))
        actual = self.lib.ZSTD_decompress(target, len(target), data, len(data))
        if self.lib.ZSTD_isError(actual) or actual != size:
            raise ValueError("invalid compressed frame")
        return target.raw[:actual]


class Archive:
    def __init__(self, root: Path | None = None):
        self.root = root or root_path()
        private_dir(self.root)
        self.events = self.root / "events"
        private_dir(self.events)
        config = self.root / "config.json"
        self.config = DEFAULTS | (json.loads(config.read_text()) if config.exists() else {})
        for k in DEFAULTS:
            if not isinstance(self.config[k], int) or self.config[k] <= 0:
                raise ValueError("invalid archive limit")
        if self.config["event_bytes"] > 32 * 1024 * 1024:
            raise ValueError("event limit exceeds bounded recovery budget")

    @contextlib.contextmanager
    def lock(self):
        with private_file(self.root / "archive.lock", "ab") as f:
            deadline = time.monotonic() + .15
            while True:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("archive busy") from None
                    time.sleep(.005)
            yield

    def connect(self):
        db = self.root / "index.sqlite3"
        if db.is_symlink():
            raise ValueError("symlink index refused")
        if not db.exists():
            with private_file(db):
                pass
        db.chmod(0o600)
        conn = sqlite3.connect(db, timeout=2)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS events(
          id TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL, host TEXT NOT NULL,
          parent TEXT, correlation TEXT NOT NULL, pid INTEGER NOT NULL, started REAL NOT NULL,
          ended REAL, exit_code INTEGER, state TEXT NOT NULL, coverage TEXT NOT NULL,
          label TEXT NOT NULL, manifest TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS event_filter ON events(source,started);
        CREATE VIRTUAL TABLE IF NOT EXISTS search USING fts5(id UNINDEXED,text);
        """)
        for p in (db, self.root / "index.sqlite3-wal", self.root / "index.sqlite3-shm"):
            if p.exists():
                p.chmod(0o600)
        return conn

    def enabled(self) -> bool:
        return not (self.root / "disabled").exists()

    def begin(self, *, kind: str, source: str, label: str, pid: int,
              parent: str | None = None, capture: bool = False) -> dict:
        if kind not in {"session", "command"} or source not in SOURCES or label not in LABELS:
            raise ValueError("unapproved provenance")
        if parent is not None:
            parent = str(uuid.UUID(parent))
        if capture and (label not in LABELS - {"shell", "excluded"} or kind != "command"):
            raise ValueError("unapproved capture")
        with self.lock():
            self._maintain()
            event_id = str(uuid.uuid4())
            path = self.events / event_id
            private_dir(path)
            m = dict(id=event_id, kind=kind, source=source, host=os.uname().nodename,
                     parent=parent, correlation=parent or event_id, pid=pid,
                     owner_pid=os.getpid(), owner_fingerprint=fingerprint(os.getpid()),
                     started=time.time(), ended=None, exit_code=None, state="active",
                     coverage="output-only" if capture else "metadata-only", label=label,
                     input="never-recorded", streams="pty-combined" if capture else "excluded",
                     files={}, schema_version=1, bytes=0)
            atomic_json(path / "manifest.json", m)
            return m

    def append(self, m: dict, data: bytes, delay: float) -> None:
        if m["coverage"] not in {"output-only", "truncated"} or not data:
            return
        with self.lock():
            if (m["bytes"] + len(data) > self.config["event_bytes"] or
                    self.usage() + len(data) + 128 > self.config["quota_bytes"]):
                m["coverage"] = "truncated"
                atomic_json(self.events / m["id"] / "manifest.json", m)
                return
            # Once truncated, don't create a discontinuous replay stream.
            if m["coverage"] == "truncated":
                return
            path = self.events / m["id"]
            with private_file(path / "output.raw", "ab") as f:
                f.write(data)
                f.flush()
            with private_file(path / "timing.raw", "ab") as f:
                f.write(f"{max(0, delay):.6f} {len(data)}\n".encode())
                f.flush()
            m["bytes"] += len(data)

    def finish(self, m: dict, code: int | None, *, interrupted: bool = False) -> None:
        with self.lock():
            m["ended"] = time.time()
            m["exit_code"] = code
            m["state"] = "interrupted" if interrupted else "complete"
            self._seal(m)
            self._index(m)
            self._maintain()

    def _seal(self, m: dict) -> None:
        path = self.events / m["id"]
        # Preserve raw until every compressed frame and manifest is durable.
        for name in ("output", "timing"):
            raw = path / f"{name}.raw"
            if not raw.exists():
                continue
            data = raw.read_bytes()
            compressed = Zstd().compress(data)
            filename = f"{name}.zst"
            with private_file(path / (filename + ".tmp")) as f:
                f.write(compressed)
                f.flush()
                os.fsync(f.fileno())
            os.replace(path / (filename + ".tmp"), path / filename)
            m["files"][name] = dict(path=filename, size=len(data),
                                     sha256=hashlib.sha256(data).hexdigest(),
                                     compressed_sha256=hashlib.sha256(compressed).hexdigest())
        atomic_json(path / "manifest.json", m)
        for name in ("output", "timing"):
            (path / f"{name}.raw").unlink(missing_ok=True)

    def read(self, m: dict, name: str) -> bytes:
        item = m["files"][name]
        if item["path"] != f"{name}.zst":
            raise ValueError("invalid content reference")
        data = (self.events / str(uuid.UUID(m["id"])) / item["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != item["compressed_sha256"]:
            raise ValueError("compressed hash mismatch")
        raw = Zstd().decompress(data, item["size"])
        if hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("original hash mismatch")
        return raw

    def _index(self, m: dict) -> None:
        text = " ".join((m["label"], m["kind"], m["source"], m["coverage"], m["host"]))
        if "output" in m["files"]:
            readable = ANSI.sub("", self.read(m, "output").decode("utf-8", "replace"))
            text += " " + "".join(c for c in readable if c.isprintable() or c in "\n\t")
        conn = self.connect()
        try:
            with conn:
                conn.execute("INSERT OR REPLACE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                             tuple(m[k] for k in ("id", "kind", "source", "host", "parent",
                                   "correlation", "pid", "started", "ended", "exit_code", "state",
                                   "coverage", "label")) + (f"events/{m['id']}/manifest.json",))
                conn.execute("DELETE FROM search WHERE id=?", (m["id"],))
                conn.execute("INSERT INTO search(id,text) VALUES(?,?)", (m["id"], text))
        finally:
            conn.close()

    def recover(self, *, rebuild: bool = False) -> int:
        count = 0
        with self.lock():
            conn = self.connect()
            try:
                indexed = {r[0] for r in conn.execute("SELECT id FROM events")}
            finally:
                conn.close()
            for path in self.events.iterdir():
                if path.is_symlink() or not path.is_dir():
                    continue
                manifest = path / "manifest.json"
                if not manifest.exists():
                    continue
                m = json.loads(manifest.read_text())
                if str(uuid.UUID(m["id"])) != path.name:
                    raise ValueError("invalid event identity")
                if m["state"] == "active":
                    if fingerprint(m["owner_pid"]) == m["owner_fingerprint"]:
                        continue
                    # A crash between data and timing can leave an unpaired tail.
                    raw, timing = path / "output.raw", path / "timing.raw"
                    if raw.exists():
                        lines = timing.read_text().splitlines() if timing.exists() else []
                        valid, size = [], 0
                        for line in lines:
                            parts = line.split()
                            if len(parts) != 2:
                                break
                            n = int(parts[1])
                            if n < 0 or size + n > raw.stat().st_size:
                                break
                            float(parts[0])
                            valid.append(line)
                            size += n
                        recovered = raw.read_bytes()[:size]
                        with private_file(raw) as f:
                            f.write(recovered)
                        with private_file(timing) as f:
                            f.write(("\n".join(valid) + ("\n" if valid else "")).encode())
                        m["bytes"] = size
                    m.update(state="interrupted", ended=time.time(), exit_code=None)
                    self._seal(m)
                    count += 1
                if rebuild or m["id"] not in indexed:
                    self._index(m)
            self._maintain()
        return count

    def usage(self) -> int:
        return sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file() and not p.is_symlink())

    def _maintain(self) -> None:
        sealed = []
        for path in self.events.iterdir():
            if path.is_symlink() or not (path / "manifest.json").exists():
                continue
            m = json.loads((path / "manifest.json").read_text())
            if m["state"] != "active":
                sealed.append((m["ended"], m["id"], path))
        cutoff = time.time() - self.config["retention_days"] * 86400
        for ended, event_id, path in sorted(sealed):
            if ended >= cutoff and self.usage() <= self.config["quota_bytes"]:
                break
            # Delete derived rows before originals. A crash may reindex; never
            # leave index rows pointing at a deleted manifest after successful prune.
            conn = self.connect()
            try:
                with conn:
                    conn.execute("DELETE FROM events WHERE id=?", (event_id,))
                    conn.execute("DELETE FROM search WHERE id=?", (event_id,))
            finally:
                conn.close()
            shutil.rmtree(path)

    def query(self, query: str = "", *, source: str | None = None,
              since: float = 0, limit: int = 20) -> list[dict]:
        conn = self.connect()
        try:
            sql = "SELECT e.* FROM events e"
            values: list = []
            if query:
                sql += " JOIN search s ON s.id=e.id WHERE search MATCH ?"
                values.append(query)
            else:
                sql += " WHERE 1=1"
            if source:
                sql += " AND e.source=?"
                values.append(source)
            sql += " AND e.started>=? ORDER BY e.started DESC LIMIT ?"
            values += [since, max(1, min(limit, 200))]
            return [dict(r) for r in conn.execute(sql, values)]
        finally:
            conn.close()

    def status(self) -> dict:
        conn = self.connect()
        try:
            rows = conn.execute("SELECT kind,coverage,count(*) AS count FROM events GROUP BY kind,coverage")
            groups = [dict(r) for r in rows]
        finally:
            conn.close()
        active = sum(json.loads(p.read_text())["state"] == "active"
                     for p in self.events.glob("*/manifest.json"))
        return dict(enabled=self.enabled(), root=str(self.root), bytes=self.usage(), active=active,
                    limits=self.config, coverage=groups, input="excluded", shell_content="excluded",
                    content_policy="fixed-diagnostics-only", stdout_stderr="combined PTY",
                    chat_sources="never-imported", scheduler="shell startup / manual maintenance")
