"""Append-only cycle events for the monitor.

The trail log stays human readable. This file is the same decisions as data:
one JSON object per line, tagged with the cycle. The monitor reads it instead
of recovering the decisions from log prose. Set ``HECATE_EVENTS_LOG`` to the
file; with it unset, ``emit`` does nothing.
"""

from __future__ import annotations

import contextvars
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

_cycle_id: contextvars.ContextVar[str] = contextvars.ContextVar("hecate_cycle_id", default="")
_lock = threading.Lock()


def bind_cycle(cycle_id: str) -> None:
    """Remember the cycle the current thread (and tasks it starts) is running."""
    _cycle_id.set(cycle_id)


def current_cycle() -> str:
    return _cycle_id.get()


def emit(event: dict[str, Any]) -> None:
    """Append one event. Fields must already be free of credentials and paths."""
    raw = os.environ.get("HECATE_EVENTS_LOG")
    if not raw:
        return
    path = Path(raw)
    row = {"ts": round(time.time(), 3), **event}
    if "cycle_id" not in row:
        row["cycle_id"] = current_cycle()
    try:
        line = json.dumps(row, separators=(",", ":"), default=str) + "\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        with _lock, path.open("a", encoding="utf-8") as handle:
            handle.write(line)
    except (OSError, TypeError, ValueError):
        return
