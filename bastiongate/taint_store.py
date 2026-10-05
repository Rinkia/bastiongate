"""Shared flow-guard taint across gate processes (TODOS.md E4).

An MCP client runs one gate per server, so the lethal trifecta that crosses servers
(read a web page through `fetch`, a secret through `filesystem`, send it out through
either) is invisible to each gate alone. Gates that name the same `taint_group` write
their taint to one per-user SQLite file and read the group's rows on every egress check.

    group   `taint_group: <name>` in the policy, else env BASTIONGATE_TAINT_GROUP;
            `auto` = the MCP client that spawned this gate: on POSIX its process group
            (launchers like npx/uvx keep it), on Windows the nearest ancestor that is not
            a launcher (py, uv, uvx, cmd, a console-script shim, or the venv python.exe
            redirector directly above this interpreter)
    rows    one per (writer, kind U|P, source "server:tool"); a source read from several
            repos keeps repo NULL (never exempt). A writer holds at most MAX_ROWS_PER_WRITER
            rows, so one gate can never flood out the others' taint; past the cap its oldest
            private rows fold into one "server:*" row (never exempt) and untrusted rows are
            never evicted by private ones
    life    live writers re-stamp their rows every HEARTBEAT_SECONDS while their own taint
            is live; rows not re-stamped for STALE_SECONDS belong to a dead or idle gate and
            are ignored (a crashed client's taint never blocks the next session for long);
            a gate's own rows are cleared on `initialize`
    errors  never break the proxy: the caller falls back to its local taint

stdio only: an HTTP gate serves many clients and must not pool them (http_proxy refuses
a taint_group).
"""

from __future__ import annotations

import os
import re
import sqlite3
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

HEARTBEAT_SECONDS = 60
STALE_SECONDS = 180  # 3 missed heartbeats: the writer is gone or its taint expired
MAX_ROWS_PER_WRITER = 64
MAX_U_ROWS_PER_WRITER = 8  # one untrusted source is enough to taint; a few name it
MAX_ROWS_TOTAL = 20_000  # the whole file, all groups
GROUP_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
WRITE_TIMEOUT = 1.0  # seconds to wait for another gate's write lock
READ_TIMEOUT = 0.5  # the egress check sits on the proxy path: wait less


class StoreBusy(Exception):
    """Another gate held the lock past the timeout: transient, retried next time."""


@dataclass(frozen=True)
class Row:
    kind: str  # "U" untrusted | "P" private
    source: str  # "server:tool"
    repo: str | None  # None: no repo, or several (never exempt)
    writer: str = ""


def state_dir() -> Path:
    if os.environ.get("BASTIONGATE_STATE_DIR"):
        return Path(os.environ["BASTIONGATE_STATE_DIR"])
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "bastiongate"
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "bastiongate"


# image names that only start another process; python.exe counts only directly above
# this interpreter (the venv redirector), never further up (it may be a Python client)
LAUNCHERS = frozenset({"py.exe", "pyw.exe", "uv.exe", "uvx.exe", "cmd.exe", "conhost.exe",
                       "bastiongate.exe"})


def _windows_processes() -> dict[int, tuple[int, str]]:
    """{pid: (parent pid, lowercased image name)} via the Toolhelp snapshot (stdlib ctypes)."""
    import ctypes
    from ctypes import wintypes

    class Entry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if snap in (None, wintypes.HANDLE(-1).value):
        raise OSError("process snapshot failed")
    procs = {}
    try:
        entry = Entry()
        entry.dwSize = ctypes.sizeof(Entry)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            procs[entry.th32ProcessID] = (entry.th32ParentProcessID, entry.szExeFile.lower())
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return procs


def _auto_group() -> str:
    if os.name != "nt":
        return f"pgid:{os.getpgrp()}"
    pid = os.getppid()
    try:
        procs = _windows_processes()
        own_image = procs.get(os.getpid(), (0, ""))[1]
        parent, image = procs.get(pid, (0, ""))
        in_venv = sys.prefix != sys.base_prefix  # only a venv interpreter has a redirector parent
        if in_venv and image and image == own_image and parent:
            pid = parent
        for _ in range(16):  # ponytail: bounded walk; a deeper launcher chain stops here
            parent, image = procs.get(pid, (0, ""))
            if image not in LAUNCHERS or not parent:
                break
            pid = parent
    except OSError:
        pass  # fall back to the direct parent
    return f"client:{pid}"


def resolve_group(policy_value: str | None) -> str | None:
    """The group name, or None. Raises ValueError for an invalid env value (the policy
    value is validated when the policy loads)."""
    value = policy_value or os.environ.get("BASTIONGATE_TAINT_GROUP") or None
    if value is not None and not GROUP_RE.fullmatch(value):
        raise ValueError(f"BASTIONGATE_TAINT_GROUP {value[:80]!r} is not `auto` or a name of 1-64 "
                         "letters, digits or _.:- characters")
    return _auto_group() if value == "auto" else value


class SharedTaint:
    """One gate's view of its group's taint rows. Methods raise StoreBusy on a lock
    timeout (transient) and sqlite3.Error / OSError otherwise; FlowGuard handles both."""

    def __init__(self, group: str, server: str) -> None:
        self.group = group
        self.server = server
        self.writer = f"{os.getpid()}:{uuid.uuid4().hex[:12]}"  # this gate process
        directory = state_dir()
        if not directory.exists():
            directory.mkdir(mode=0o700, parents=True)  # only a dir we create gets our mode
        self.path = directory / "taint.sqlite"
        created = not self.path.exists()
        with self._db(WRITE_TIMEOUT) as db:
            db.execute("CREATE TABLE IF NOT EXISTS taint (grp TEXT, writer TEXT, kind TEXT, "
                       "source TEXT, repo TEXT, ts REAL)")
            db.execute("CREATE INDEX IF NOT EXISTS taint_grp ON taint (grp, ts)")
            db.execute("CREATE INDEX IF NOT EXISTS taint_writer ON taint (writer, kind, source)")
        if created and os.name != "nt":
            os.chmod(self.path, 0o600)

    def _db(self, timeout: float) -> _Closing:
        # default rollback journal: switching to WAL needs an exclusive lock that gates
        # starting together collide on; the busy timeout covers these tiny writes
        return _Closing(sqlite3.connect(self.path, timeout=timeout, isolation_level=None))

    def add(self, kind: str, tool: str, repo: str | None) -> None:
        """Record (or re-stamp) one taint source. One row per (writer, kind, source): a
        second repo for the same source turns the repo to NULL (never exempt)."""
        now, source = time.time(), f"{self.server}:{tool}"
        with self._db(WRITE_TIMEOUT) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM taint WHERE ts < ?", (now - STALE_SECONDS,))
            old = db.execute("SELECT rowid, repo FROM taint WHERE grp = ? AND writer = ? AND kind = ? "
                             "AND source = ?", (self.group, self.writer, kind, source)).fetchone()
            if old is None:
                db.execute("INSERT INTO taint VALUES (?, ?, ?, ?, ?, ?)",
                           (self.group, self.writer, kind, source, repo, now))
            else:
                db.execute("UPDATE taint SET ts = ?, repo = ? WHERE rowid = ?",
                           (now, old[1] if old[1] == repo else None, old[0]))
            self._cap_writer(db, now)
            db.execute("DELETE FROM taint WHERE rowid NOT IN (SELECT rowid FROM taint "
                       "ORDER BY ts DESC, rowid DESC LIMIT ?)", (MAX_ROWS_TOTAL,))
            db.execute("COMMIT")

    def _cap_writer(self, db: sqlite3.Connection, now: float) -> None:
        """Keep this writer under MAX_ROWS_PER_WRITER without ever losing its signal:
        at most MAX_U_ROWS_PER_WRITER untrusted rows (oldest dropped, the newest still
        taints), and the oldest private rows fold into one "<server>:*" row."""
        overflow = f"{self.server}:*"
        db.execute("DELETE FROM taint WHERE writer = ? AND kind = 'U' AND rowid NOT IN (SELECT rowid FROM taint "
                   "WHERE writer = ? AND kind = 'U' ORDER BY ts DESC, rowid DESC LIMIT ?)",
                   (self.writer, self.writer, MAX_U_ROWS_PER_WRITER))
        (count,) = db.execute("SELECT COUNT(*) FROM taint WHERE writer = ?", (self.writer,)).fetchone()
        if count <= MAX_ROWS_PER_WRITER:
            return
        has_overflow = db.execute("SELECT 1 FROM taint WHERE writer = ? AND source = ?",
                                  (self.writer, overflow)).fetchone() is not None
        extra = count - MAX_ROWS_PER_WRITER + (0 if has_overflow else 1)
        db.execute("DELETE FROM taint WHERE rowid IN (SELECT rowid FROM taint WHERE writer = ? AND kind = 'P' "
                   "AND source != ? ORDER BY ts, rowid LIMIT ?)", (self.writer, overflow, extra))
        if has_overflow:
            db.execute("UPDATE taint SET ts = ? WHERE writer = ? AND source = ?", (now, self.writer, overflow))
        else:
            db.execute("INSERT INTO taint VALUES (?, ?, 'P', ?, NULL, ?)", (self.group, self.writer, overflow, now))

    def heartbeat(self) -> None:
        """Re-stamp this writer's rows: they stay live while this gate's taint is."""
        with self._db(WRITE_TIMEOUT) as db:
            db.execute("UPDATE taint SET ts = ? WHERE writer = ?", (time.time(), self.writer))

    def rows(self) -> list[Row]:
        """The group's live rows (re-stamped within STALE_SECONDS), oldest first."""
        with self._db(READ_TIMEOUT) as db:
            cur = db.execute("SELECT kind, source, repo, writer FROM taint WHERE grp = ? AND ts >= ? "
                             "ORDER BY ts, rowid", (self.group, time.time() - STALE_SECONDS))
            return [Row(k, s, r, w) for k, s, r, w in cur.fetchall()]

    def clear_own(self) -> None:
        with self._db(WRITE_TIMEOUT) as db:
            db.execute("DELETE FROM taint WHERE grp = ? AND writer = ?", (self.group, self.writer))


class _Closing:
    """sqlite3's own context manager commits but never closes the connection; a lock
    timeout surfaces as StoreBusy (transient), everything else as itself."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    def __enter__(self) -> sqlite3.Connection:
        return self.db

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None and self.db.in_transaction:
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        self.db.close()
        if isinstance(exc, sqlite3.OperationalError) and "locked" in str(exc):
            raise StoreBusy(str(exc)) from exc
        return False
