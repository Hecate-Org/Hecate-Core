"""Atomic file write utility using temp-file and rename pattern."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def default_file_mode() -> int:
    """Mode a plain open() would create: 0o666 masked by the process umask.

    mkstemp() hardcodes 0o600 and os.replace carries that mode onto the
    destination, so a file written through this helper ends up private to
    its owner rather than matching the 0o644 a plain write_text() produces
    under the service's umask. Callers that want ordinary file permissions
    pass this as `mode`.

    Read once at import, before any worker threads exist -- querying the
    umask means temporarily setting it, which is not thread-safe.
    """
    umask = os.umask(0o022)
    os.umask(umask)
    return 0o666 & ~umask


DEFAULT_FILE_MODE = default_file_mode()


def atomic_write_text(path: Path, content: str, mode: int = DEFAULT_FILE_MODE) -> None:
    """Write `content` to `path` atomically (write to a temp file in the same
    directory, then rename over the destination).

    `mode` is applied to the temp file before the rename, defaulting to what a
    plain write_text() would produce.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise
