"""Unit tests for run_process_group utility."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from hecate_agent.core.subprocess_utils import run_process_group


def test_run_process_group_successful_execution() -> None:
    res = run_process_group(["echo", "hello_antigravity"])
    assert res.returncode == 0
    assert "hello_antigravity" in res.stdout


def test_run_process_group_captures_stderr() -> None:
    res = run_process_group(["sh", "-c", "echo error_msg >&2; exit 42"])
    assert res.returncode == 42
    assert "error_msg" in res.stderr


def test_run_process_group_check_raises_called_process_error() -> None:
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        run_process_group(["sh", "-c", "exit 3"], check=True)
    assert exc_info.value.returncode == 3


def test_run_process_group_timeout_raises_timeout_expired() -> None:
    with pytest.raises(subprocess.TimeoutExpired) as exc_info:
        run_process_group(["sleep", "10"], timeout=0.1)
    assert exc_info.value.cmd == ["sleep", "10"]


@pytest.mark.skipif(sys.platform == "win32", reason="Process group killpg and POSIX sh are unix-only")
def test_run_process_group_kills_orphaned_grandchildren_on_timeout() -> None:
    """Ensure background grandchild processes are killed with os.killpg when timeout expires."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        pid_file = f.name

    try:
        # Spawn a background sleep process, write its PID to file, then sleep parent
        shell_cmd = f"sleep 30 & echo $! > {pid_file} ; sleep 30"
        with pytest.raises(subprocess.TimeoutExpired):
            run_process_group(["sh", "-c", shell_cmd], timeout=0.2)

        time.sleep(0.1)
        content = Path(pid_file).read_text().strip()
        assert content, "PID file was not written"
        grandchild_pid = int(content)

        # Confirm the background process was killed and does not remain running as an orphan
        with pytest.raises(ProcessLookupError):
            os.kill(grandchild_pid, 0)
    finally:
        Path(pid_file).unlink(missing_ok=True)
