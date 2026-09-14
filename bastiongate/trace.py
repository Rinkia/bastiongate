"""Append-only JSONL trace of everything the gate sees.

One line per event. Shape is close to bastiontrace's tool-call trace so the same
forensics tooling can read a gate log. Thread-safe (two pumps write to it).
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import IO


class Trace:
    def __init__(self, path: str | Path | None) -> None:
        self._lock = threading.Lock()
        self._fh: IO[str] | None = None
        if path:
            self._fh = Path(path).open("a", encoding="utf-8")

    def emit(self, event: str, **fields) -> None:
        if not self._fh:
            return
        row = {"ts": round(time.time(), 3), "event": event, **fields}
        with self._lock:
            self._fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh:
            with self._lock:
                self._fh.close()
                self._fh = None
