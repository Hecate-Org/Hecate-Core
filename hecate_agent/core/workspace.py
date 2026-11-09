"""Locate the workspace whose knowledge files an agent should read.

Agents are frequently run as a subprocess by something else. The orchestrator
does set ``cwd`` to the workspace when it invokes ``hecate-agent``, so the
older ``Path.cwd() / "knowledge" / ...`` resolution worked for that caller --
but it made correctness depend on every caller remembering to do the same,
and silently returned "not found" for any that did not. A manual
``hecate-agent research new`` from another directory is exactly such a
caller, and writes its output there too.

Resolution mirrors ``mcp.utils.find_workspace`` but lives here because
``mcp`` is an optional dependency, and it returns a path instead of raising:
a missing workspace should degrade the prompt, exactly as it does today, not
crash a hunt cycle.
"""

import os
from pathlib import Path
from typing import Optional

#: Marker that identifies a directory as a workspace root.
_CONFIG_NAMES = (".hecateconfig.yaml", "config/.hecateconfig.yaml")


def workspace_root(explicit: Optional[Path] = None) -> Path:
    """Best guess at the workspace root.

    Order: explicit argument, ``HECATE_WORKSPACE``, the nearest ancestor of
    the working directory holding a workspace config, then the working
    directory itself.
    """
    if explicit is not None:
        return Path(explicit).expanduser().resolve()

    env_path = os.environ.get("HECATE_WORKSPACE")
    if env_path:
        return Path(env_path).expanduser().resolve()

    current = Path.cwd()
    for parent in [current, *current.parents]:
        for name in _CONFIG_NAMES:
            if (parent / name).exists():
                return parent

    return current


def knowledge_file(filename: str, explicit: Optional[Path] = None) -> Path:
    """Path to one file under the workspace's ``knowledge/`` directory.

    The file is not required to exist; callers decide what a missing file
    means for their prompt.
    """
    return workspace_root(explicit) / "knowledge" / filename


def load_workspace_env() -> None:
    """Load .env files with workspace auto-discovery.

    Precedence:
    1. Existing environment variables (override=False)
    2. Local directory .env (if present)
    3. Workspace root .env (from HECATE_WORKSPACE, .hecateconfig.yaml discovery,
       or the current working directory)
    """
    from dotenv import load_dotenv

    had_ws = "HECATE_WORKSPACE" in os.environ

    # 1. Local cwd .env (developer override)
    load_dotenv(Path.cwd() / ".env", override=False)

    # 2. Discovered workspace root .env
    ws = workspace_root()
    if (ws / ".env").is_file():
        load_dotenv(ws / ".env", override=False)
    # Preserve environment isolation: if HECATE_WORKSPACE was not set before
    # loading .env, don't let .env define it in os.environ and break tests
    # that verify dynamic cwd walk-up resolution.
    if not had_ws and "HECATE_WORKSPACE" in os.environ:
        del os.environ["HECATE_WORKSPACE"]


