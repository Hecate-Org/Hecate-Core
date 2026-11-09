"""Hunt ID allocation shared by every writer of a workspace's ``hunts/``.

The CLI (``hunt new`` and friends), the MCP tools, the LangGraph orchestrator
and Hecate-Runner all create hunt files in the same directory. Each used to
pick its own next ID -- the CLI from the highest file on disk, the graph a
fixed ``H-0000`` -- so two writers could hand out one ID and the second write
replaced the first. This is the Runner's protocol
(``hecate_runner.hunt_writer``), ported rather than imported because the
Runner depends on Hecate-Core: the same ``.hunt_id.lock`` flock, the same
``.hunt_id_counter`` high-water mark, and the same floors (hunts on disk,
Sigma rule directories under ``queries/``, and git history when no counter
exists yet). Keep the two in step: both writers read and advance one counter.
"""

import logging
import re
import subprocess  # nosec B404 - fixed argv, no shell
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from hecate_agent.core.atomic_write import atomic_write_text
from hecate_agent.core.research_manager import _DEFAULT_FILE_MODE

try:
    import fcntl as _fcntl_module
except ImportError:  # pragma: no cover - fcntl is POSIX-only
    _fcntl_module = None  # type: ignore[assignment]

#: None where flock is unavailable (Windows): allocation is then unlocked, as
#: research ID allocation already is there.
_fcntl: Optional[Any] = _fcntl_module

logger = logging.getLogger(__name__)

COUNTER_FILENAME = ".hunt_id_counter"
LOCK_FILENAME = ".hunt_id.lock"
_GIT_SEED_TIMEOUT_SEC = 30
_ID_RE = re.compile(r"H-(\d+)")


@contextmanager
def hunt_id_lock(hunts_root: Path) -> Iterator[None]:
    """Serialize ID allocation across processes, including a concurrent Runner cycle."""
    hunts_root.mkdir(parents=True, exist_ok=True)
    if _fcntl is None:
        yield
        return
    with open(hunts_root / LOCK_FILENAME, "w", encoding="utf-8") as lock_file:
        _fcntl.flock(lock_file, _fcntl.LOCK_EX)
        try:
            yield
        finally:
            _fcntl.flock(lock_file, _fcntl.LOCK_UN)


def _max_on_disk(hunts_root: Path) -> int:
    """Highest ID under hunts/, or flat at the workspace root where some workspaces keep hunts."""
    paths = [*hunts_root.rglob("H-*.md"), *hunts_root.parent.glob("H-*.md")]
    ids = [int(m.group(1)) for p in paths if (m := _ID_RE.match(p.stem))]
    return max(ids, default=0)


def _max_in_queries(hunts_root: Path) -> int:
    """Rule directories outlive deleted hunts; a reused ID would adopt their rules."""
    queries = hunts_root.parent / "queries"
    if not queries.is_dir():
        return 0
    ids = [int(m.group(1)) for d in queries.iterdir() if d.is_dir() and (m := re.fullmatch(r"H-(\d+)", d.name))]
    return max(ids, default=0)


def _max_in_git(hunts_root: Path) -> int:
    """Highest ID ever committed under hunts/, to seed a missing counter; 0 if git is unavailable."""
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["git", "log", "--all", "--pretty=format:", "--name-only", "--", hunts_root.name],
            cwd=hunts_root.parent,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GIT_SEED_TIMEOUT_SEC,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        logger.warning("Could not scan git history to seed the hunt ID counter; using on-disk max")
        return 0
    if proc.returncode != 0:
        return 0
    return max((int(m) for m in re.findall(r"H-(\d+)\.md", proc.stdout)), default=0)


def _read_counter(path: Path) -> int:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0


def _atomic_write(path: Path, text: str) -> None:
    """Write via temp file and rename, with the mode a plain write would get."""
    atomic_write_text(path, text, mode=_DEFAULT_FILE_MODE)


def next_hunt_id(hunts_root: Path) -> str:
    """Allocate the next hunt ID and persist it. Call inside :func:`hunt_id_lock`.

    The ID is burned at allocation: a run that stops before writing its draft
    leaves a gap rather than handing the same ID to the next run.
    """
    counter = hunts_root / COUNTER_FILENAME
    high_water = max(_max_on_disk(hunts_root), _max_in_queries(hunts_root))
    if counter.exists():
        high_water = max(high_water, _read_counter(counter))
    else:
        high_water = max(high_water, _max_in_git(hunts_root))
    allocated = high_water + 1
    _atomic_write(counter, f"{allocated}\n")
    return f"H-{allocated:04d}"


def allocate_hunt_id(hunts_root: Path) -> str:
    with hunt_id_lock(hunts_root):
        return next_hunt_id(hunts_root)
