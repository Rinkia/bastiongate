"""Shared flow-guard taint across gate processes (TODOS.md E4).

An MCP client runs one gate per server, so the lethal trifecta that crosses servers
(read a web page through `fetch`, a secret through `filesystem`, send it out through
either) is invisible to each gate alone. Gates that name the same `taint_group` write
their taint to one per-user SQLite file and read the group's rows on every egress check.

    group   `taint_group: <name>` in the policy, else env BASTIONGATE_TAINT_GROUP;
            `auto` = the MCP client that spawned this gate: on POSIX its process group
            (launchers like npx/uvx keep it), on Windows the nearest ancestor that is not
            a launcher (venv python.exe, py, uv, uvx, cmd, npx's node wrapper)
    rows    (group, writer, kind U|P, source "server:tool", repo, ts); a gate's own rows
            are cleared on `initialize`; rows idle past TAINT_IDLE_SECONDS expire
    errors  never break the proxy: the caller falls back to its local taint

stdio only: an HTTP gate serves many clients and must not pool them (http_proxy refuses
a taint_group).
"""

from __future__ import annotations

import os
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

TAINT_IDLE_SECONDS = 1800  # same as flows.TAINT_IDLE_SECONDS
MAX_ROWS_PER_GROUP = 512
GROUP_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_TIMEOUT = 2.0  # seconds to wait for another gate's write lock


@dataclass(frozen=True)
class Row:
    kind: str  # "U" untrusted | "P" private
    source: str  # "server:tool"
    repo: str | None
    writer: str = ""


def state_dir() -> Path:
    if os.environ.get("BASTIONGATE_STATE_DIR"):
        return Path(os.environ["BASTIONGATE_STATE_DIR"])
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "bastiongate"
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "bastiongate"


# image names that only start another process (they sit between the client and the gate)
LAUNCHERS = frozenset({"python.exe", "pythonw.exe", "py.exe", "pyw.exe", "uv.exe", "uvx.exe",
                       "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "bastiongate.exe"})


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
        for _ in range(16):  # ponytail: bounded walk; a deeper launcher chain stops here
            parent, image = procs.get(pid, (0, ""))
            if image not in LAUNCHERS or not parent:
                break
            pid = parent
    except OSError:
        pass  # fall back to the direct parent
    return f"client:{pid}"


def resolve_group(policy_value: str | None) -> str | None:
    value = policy_value or os.environ.get("BASTIONGATE_TAINT_GROUP") or None
    if value == "auto":
        return _auto_group()
    return value


class SharedTaint:
    """One gate's view of its group's taint rows. Every method may raise
    sqlite3.Error / OSError; FlowGuard catches them and falls back."""

    def __init__(self, group: str, server: str) -> None:
        self.group = group
        self.server = server
        self.writer = uuid.uuid4().hex  # this gate process
        directory = state_dir()
        directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(directory, 0o700)
        self.path = directory / "taint.sqlite"
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS taint (grp TEXT, writer TEXT, kind TEXT, "
                       "source TEXT, repo TEXT, ts REAL)")
            db.execute("CREATE INDEX IF NOT EXISTS taint_grp ON taint (grp, ts)")
        if os.name != "nt":
            os.chmod(self.path, 0o600)

    def _db(self) -> _Closing:
        # default rollback journal: switching to WAL needs an exclusive lock that gates
        # starting together collide on; the busy timeout covers these tiny writes
        return _Closing(sqlite3.connect(self.path, timeout=_TIMEOUT, isolation_level=None))

    def add(self, kind: str, tool: str, repo: str | None) -> None:
        now = time.time()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM taint WHERE ts < ?", (now - TAINT_IDLE_SECONDS,))
            db.execute("INSERT INTO taint VALUES (?, ?, ?, ?, ?, ?)",
                       (self.group, self.writer, kind, f"{self.server}:{tool}", repo, now))
            db.execute("DELETE FROM taint WHERE grp = ? AND rowid NOT IN "
                       "(SELECT rowid FROM taint WHERE grp = ? ORDER BY ts DESC, rowid DESC LIMIT ?)",
                       (self.group, self.group, MAX_ROWS_PER_GROUP))
            db.execute("COMMIT")

    def rows(self) -> list[Row]:
        """The group's live rows, oldest first."""
        with self._db() as db:
            cur = db.execute("SELECT kind, source, repo, writer FROM taint WHERE grp = ? AND ts >= ? "
                             "ORDER BY ts, rowid", (self.group, time.time() - TAINT_IDLE_SECONDS))
            return [Row(k, s, r, w) for k, s, r, w in cur.fetchall()]

    def clear_own(self) -> None:
        with self._db() as db:
            db.execute("DELETE FROM taint WHERE grp = ? AND writer = ?", (self.group, self.writer))


class _Closing:
    """sqlite3's own context manager commits but never closes the connection."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    def __enter__(self) -> sqlite3.Connection:
        return self.db

    def __exit__(self, *exc) -> None:
        self.db.close()
