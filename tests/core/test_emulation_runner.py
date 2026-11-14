"""Unit tests for EmulationRunner and Sandboxed Detonation."""

import shutil
import subprocess
from pathlib import Path

import pytest

from hecate_agent.core.emulation_runner import (
    BwrapBackend,
    EmulationRunner,
    MockBackend,
    SimulationBackend,
    SubprocessBackend,
)


def _strace_can_trace() -> bool:
    strace = shutil.which("strace")
    if strace is None:
        return False
    try:
        result = subprocess.run(
            [strace, "-qq", "-o", "/dev/null", "-e", "trace=execve", "true"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def test_mock_backend_emulation() -> None:
    mock_events = [
        {"category": "process_creation", "CommandLine": "vshell_loader.exe -stage2", "Image": "vshell_loader.exe"},
        {"category": "network_connection", "DestinationIp": "38.207.178.192", "DestinationPort": 443},
    ]
    mock_backend = MockBackend(mock_events=mock_events, exit_code=0, stdout="test detonation completed")
    runner = EmulationRunner(backend=mock_backend)

    result = runner.run_command("vshell_loader.exe -stage2")
    assert result.success is True
    assert result.exit_code == 0
    assert result.backend == "mock"
    assert len(result.events) == 2

    # Closed-loop evaluation against a Sigma rule
    rule_yaml = """
title: VShell IOC Connection
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '38.207.178.192'
    condition: selection
"""
    report = result.evaluate(rule_yaml)
    assert report.true_positives == 1
    assert report.fired_on_intrusion is True
    assert report.is_clean is True


@pytest.mark.skipif(
    shutil.which("bwrap") is None or not _strace_can_trace(),
    reason="bwrap and working ptrace support are required for sandbox telemetry",
)
def test_bwrap_sandbox_execution_and_isolation() -> None:
    runner = EmulationRunner(backend="bwrap")
    test_marker = "/tmp/hecate_art_test_marker.txt"

    # Ensure host marker doesn't exist before test
    assert not Path(test_marker).exists()

    cmd = f"echo 'purple_team_payload' > {test_marker} && cat {test_marker}"
    result = runner.run_command(cmd)

    assert result.success is True
    assert result.exit_code == 0
    assert result.backend == "bwrap"
    assert "purple_team_payload" in result.stdout

    # Verify filesystem isolation: file written inside sandbox MUST NOT exist on host!
    assert not Path(test_marker).exists(), "Sandbox isolation violated: file leaked to host filesystem"

    # /home is an empty tmpfs — the real host username must not appear.
    host_user = Path.home().name
    home_list = runner.run_command("ls -A /home 2>/dev/null; echo HOME_OK")
    assert home_list.success is True
    assert "HOME_OK" in home_list.stdout
    assert host_user not in home_list.stdout

    # Network must be disabled inside the sandbox.
    net = runner.run_command(
        "python3 -c 'import socket; socket.create_connection((\"1.1.1.1\", 80), 1)' "
        ">/dev/null 2>&1 || echo net_blocked"
    )
    assert "net_blocked" in net.stdout

    # Verify telemetry harvesting
    proc_events = [e for e in result.events if e.get("category") == "process_creation"]
    file_events = [e for e in result.events if e.get("category") == "file_event"]

    assert len(proc_events) > 0, "No process_creation events captured"
    assert len(file_events) > 0, "No file_event events captured"
    assert any(test_marker in e.get("TargetFilename", "") for e in file_events)


def test_subprocess_backend_disabled_by_default() -> None:
    backend = SubprocessBackend()
    assert backend.is_available() is False
    with pytest.raises(RuntimeError, match="Unsandboxed"):
        backend.run("echo should_not_run")


def test_subprocess_backend_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_ALLOW_UNSANDBOXED_EMULATION", "1")
    runner = EmulationRunner(backend=SubprocessBackend(allow_unsandboxed=True))
    result = runner.run_command("echo 'subprocess_fallback'")
    assert result.success is True
    assert "subprocess_fallback" in result.stdout


def test_auto_backend_never_selects_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(BwrapBackend, "is_available", lambda self: False)
    from hecate_agent.core import emulation_runner as er

    monkeypatch.setattr(er.DockerBackend, "is_available", lambda self: False)
    runner = EmulationRunner(backend=None)
    assert isinstance(runner.backend, SimulationBackend)


def test_requested_subprocess_without_opt_in_uses_simulation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HECATE_ALLOW_UNSANDBOXED_EMULATION", raising=False)
    runner = EmulationRunner(backend="subprocess")
    assert isinstance(runner.backend, SimulationBackend)


def test_emulation_runner_run_atomic_test() -> None:
    mock_events = [
        {"category": "process_creation", "CommandLine": "whoami /all", "Image": "/usr/bin/whoami"},
    ]
    runner = EmulationRunner(backend=MockBackend(mock_events=mock_events))

    art_test = {
        "name": "System Discovery via Whoami",
        "command": "whoami /all",
        "telemetry": "Sysmon Event ID 1",
    }
    result = runner.run_atomic_test(art_test)
    assert result.success is True
    assert result.command == "whoami /all"
    assert len(result.events) == 1


def test_emulation_runner_run_technique() -> None:
    mock_events = [
        {"category": "process_creation", "CommandLine": "procdump.exe -ma lsass.exe lsass.dmp"},
    ]
    runner = EmulationRunner(backend=MockBackend(mock_events=mock_events))

    # T1003.001 is curated in ATOMIC_TESTS_MAP
    result = runner.run_technique("T1003.001", test_index=0)
    assert result.success is True
    assert "procdump" in result.command


@pytest.mark.skipif(
    shutil.which("bwrap") is None or not _strace_can_trace(),
    reason="bwrap and working ptrace support are required for telemetry harvesting",
)
def test_closed_loop_detonation_and_detection_self_evaluation() -> None:
    """Full closed-loop evaluation: command execution -> harvested telemetry -> Sigma rule evaluation."""
    runner = EmulationRunner(backend="bwrap")

    cmd = "sh -c 'echo detonation_test > /tmp/art_signal.tmp && cat /tmp/art_signal.tmp'"
    result = runner.run_command(cmd)
    assert result.success is True

    # Rule matching the file event created in sandbox
    matching_rule = """
title: Detection of Temporary Signal File Creation
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 'art_signal.tmp'
    condition: selection
"""
    report = result.evaluate(matching_rule)
    assert report.true_positives >= 1
    assert report.fired_on_intrusion is True
