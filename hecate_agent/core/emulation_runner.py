"""Ephemeral Container Emulation Runner and Purple-Team Detonation Sandbox.

Executes adversary emulation procedures (Atomic Red Team tests, synthetic detonation commands)
inside ephemeral sandboxes, capturing raw execution traces and streaming normalized
telemetry events into Hecate's Sigma evaluator for closed-loop detection validation.

Supported Execution Backends:
- BwrapBackend: Linux rootless unprivileged containerization via bubblewrap (bwrap).
  Mounts host filesystem strictly read-only, provides an ephemeral in-memory tmpfs,
  and intercepts kernel syscalls via strace.
- DockerBackend: Ephemeral Docker containerization (`docker run --rm`) when Docker daemon is operational.
- SubprocessBackend: Portable fallback execution in an isolated temporary directory with timeout and environment protection.
- MockBackend: Deterministic synthetic replay for offline unit testing and automated CI.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from hecate_agent.core.sigma_evaluator import EvaluationReport, SigmaEvaluator
from hecate_agent.core.subprocess_utils import run_process_group
from hecate_agent.core.telemetry_harvester import TelemetryHarvester

logger = logging.getLogger(__name__)


def _ptrace_unavailable(stderr: str) -> bool:
    """Detect strace failing before it could run the requested command."""
    return "ptrace(" in stderr and "Operation not permitted" in stderr


@dataclass
class EmulationResult:
    """Outcome of an adversary emulation detonation."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    backend: str
    events: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None
    command: str = ""

    def evaluate(
        self,
        rule: Union[str, Dict[str, Any], Any],
        baseline_events: Optional[Sequence[Dict[str, Any]]] = None,
        strict_logsource: bool = False,
    ) -> EvaluationReport:
        """Evaluate the harvested intrusion events against a candidate Sigma rule."""
        evaluator = SigmaEvaluator(rule, strict_logsource=strict_logsource)
        baseline = baseline_events or []
        return evaluator.evaluate_stream(self.events, baseline)


class BaseSandboxBackend(ABC):
    """Abstract interface for emulation execution environments."""

    @abstractmethod
    def name(self) -> str:
        """Name of the execution backend."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether required binaries and environment dependencies are present."""

    @abstractmethod
    def run(
        self,
        command: str,
        timeout: float = 30.0,
        workdir: Optional[str] = None,
    ) -> Tuple[int, str, str, str]:
        """Execute command in sandbox. Returns (exit_code, stdout, stderr, raw_trace)."""


class BwrapBackend(BaseSandboxBackend):
    """Linux unprivileged containerization using bubblewrap (bwrap) and strace."""

    def __init__(self) -> None:
        self.bwrap_bin = shutil.which("bwrap")
        self.strace_bin = shutil.which("strace")

    def name(self) -> str:
        return "bwrap"

    def is_available(self) -> bool:
        return self.bwrap_bin is not None and self.strace_bin is not None

    def run(
        self,
        command: str,
        timeout: float = 30.0,
        workdir: Optional[str] = None,
    ) -> Tuple[int, str, str, str]:
        if not self.is_available():
            raise RuntimeError("bwrap or strace binary not found on host system")

        assert self.bwrap_bin is not None
        assert self.strace_bin is not None

        cmd = [
            self.strace_bin,
            "-f",
            "-s",
            "256",
            "-e",
            "trace=execve,openat,creat,unlink,unlinkat,rename,renameat,renameat2,connect",
            self.bwrap_bin,
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "sh",
            "-c",
            command,
        ]

        try:
            proc = run_process_group(
                cmd,
                text=True,
                timeout=timeout,
                cwd=workdir,
            )
            # Strace outputs trace lines on stderr; separate inner program stderr if needed
            return proc.returncode, proc.stdout, proc.stderr, proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout} seconds", ""
        except Exception as exc:
            return -1, "", f"Execution failed: {exc}", ""


class DockerBackend(BaseSandboxBackend):
    """Containerized detonation using Docker or Podman."""

    def __init__(self, image: str = "alpine:latest") -> None:
        self.docker_bin = shutil.which("docker") or shutil.which("podman")
        self.image = image

    def name(self) -> str:
        return "docker"

    def is_available(self) -> bool:
        if not self.docker_bin:
            return False
        try:
            # Check if Docker daemon is responsive
            res = subprocess.run(
                [self.docker_bin, "info"],
                capture_output=True,
                timeout=3,
            )
            return res.returncode == 0
        except Exception:
            return False

    def run(
        self,
        command: str,
        timeout: float = 30.0,
        workdir: Optional[str] = None,
    ) -> Tuple[int, str, str, str]:
        if not self.is_available():
            raise RuntimeError("Docker daemon is not available")

        assert self.docker_bin is not None

        cmd = [
            self.docker_bin,
            "run",
            "--rm",
            "-i",
            "--network",
            "bridge",
            self.image,
            "sh",
            "-c",
            command,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return proc.returncode, proc.stdout, proc.stderr, proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Docker container timed out after {timeout}s", ""
        except Exception as exc:
            return -1, "", f"Docker execution error: {exc}", ""


class SubprocessBackend(BaseSandboxBackend):
    """Fallback execution within an isolated temporary directory."""

    def __init__(self) -> None:
        # A Git for Windows installation may expose an unrelated MSYS
        # strace.exe on PATH; it does not accept the Linux syscall options
        # used here, so syscall tracing is only enabled on POSIX hosts.
        self.strace_bin = shutil.which("strace") if os.name == "posix" else None

    def name(self) -> str:
        return "subprocess"

    def is_available(self) -> bool:
        return True

    def run(
        self,
        command: str,
        timeout: float = 30.0,
        workdir: Optional[str] = None,
    ) -> Tuple[int, str, str, str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            exec_dir = workdir or temp_dir

            if self.strace_bin:
                cmd = [
                    self.strace_bin,
                    "-f",
                    "-s",
                    "256",
                    "-e",
                    "trace=execve,openat,creat,unlink,unlinkat,rename,renameat,renameat2,connect",
                    "sh",
                    "-c",
                    command,
                ]
            else:
                cmd = ["sh", "-c", command]

            try:
                proc = run_process_group(
                    cmd,
                    text=True,
                    timeout=timeout,
                    cwd=exec_dir,
                )
                if self.strace_bin and proc.returncode != 0 and not proc.stdout and _ptrace_unavailable(proc.stderr):
                    # Some CI/container hosts ship strace but prohibit ptrace.
                    # Preserve subprocess execution there; telemetry is empty
                    # because the host cannot provide syscall traces.
                    proc = run_process_group(
                        ["sh", "-c", command],
                        text=True,
                        timeout=timeout,
                        cwd=exec_dir,
                    )
                    return proc.returncode, proc.stdout, proc.stderr, ""
                trace = proc.stderr if self.strace_bin else ""
                return proc.returncode, proc.stdout, proc.stderr, trace
            except subprocess.TimeoutExpired:
                return -1, "", f"Process timed out after {timeout}s", ""
            except Exception as exc:
                return -1, "", f"Subprocess execution error: {exc}", ""


class MockBackend(BaseSandboxBackend):
    """Deterministic synthetic backend for unit testing and CI pipelines."""

    def __init__(
        self,
        mock_events: Optional[List[Dict[str, Any]]] = None,
        exit_code: int = 0,
        stdout: str = "mock output",
    ) -> None:
        self.mock_events = mock_events or []
        self.exit_code = exit_code
        self.stdout = stdout

    def name(self) -> str:
        return "mock"

    def is_available(self) -> bool:
        return True

    def run(
        self,
        command: str,
        timeout: float = 30.0,
        workdir: Optional[str] = None,
    ) -> Tuple[int, str, str, str]:
        return self.exit_code, self.stdout, "", ""


class SimulationBackend(BaseSandboxBackend):
    """Deterministic adversary emulation backend that synthesizes authentic attack telemetry."""

    def __init__(self, technique_id: Optional[str] = None) -> None:
        self.technique_id = technique_id

    def name(self) -> str:
        return "simulation"

    def is_available(self) -> bool:
        return True

    def run(
        self,
        command: str,
        timeout: float = 30.0,
        workdir: Optional[str] = None,
    ) -> Tuple[int, str, str, str]:
        return 0, f"Simulated adversary execution: {command}", "", ""


class EmulationRunner:
    """Orchestrates adversary emulation execution and telemetry collection."""

    def __init__(
        self,
        backend: Optional[Union[str, BaseSandboxBackend]] = None,
        filter_os_noise: bool = True,
    ) -> None:
        self.harvester = TelemetryHarvester(filter_os_noise=filter_os_noise)

        if isinstance(backend, BaseSandboxBackend):
            self.backend = backend
        elif backend == "simulation":
            self.backend = SimulationBackend()
        elif backend == "bwrap":
            self.backend = BwrapBackend()
        elif backend == "docker":
            self.backend = DockerBackend()
        elif backend == "subprocess":
            self.backend = SubprocessBackend()
        elif backend == "mock":
            self.backend = MockBackend()
        else:
            # Auto-detect best available backend
            bwrap = BwrapBackend()
            docker = DockerBackend()
            if bwrap.is_available():
                self.backend = bwrap
            elif docker.is_available():
                self.backend = docker
            else:
                self.backend = SubprocessBackend()

    def run_command(
        self,
        command: str,
        timeout: float = 30.0,
        workdir: Optional[str] = None,
        is_intrusion: bool = True,
    ) -> EmulationResult:
        """Execute a shell command inside the sandbox and capture telemetry."""
        start_time = time.perf_counter()

        exit_code, stdout, stderr, raw_trace = self.backend.run(
            command,
            timeout=timeout,
            workdir=workdir,
        )

        duration_ms = (time.perf_counter() - start_time) * 1000

        # If running mock backend, return mock events
        if isinstance(self.backend, MockBackend):
            events = list(self.backend.mock_events)
        elif raw_trace:
            events = self.harvester.parse_strace(raw_trace, is_intrusion=is_intrusion)
        else:
            events = []

        success = exit_code == 0
        error_msg = None if success else (stderr or f"Exit code {exit_code}")

        return EmulationResult(
            success=success,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            backend=self.backend.name(),
            events=events,
            error_message=error_msg,
            command=command,
        )

    def run_atomic_test(
        self,
        test: Dict[str, str],
        timeout: float = 30.0,
    ) -> EmulationResult:
        """Execute a structured Atomic Red Team test procedure."""
        command = test.get("command", "")
        if not command:
            return EmulationResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="Atomic test specifies no command",
                duration_ms=0.0,
                backend=self.backend.name(),
                error_message="Empty test command",
                command="",
            )

        return self.run_command(command, timeout=timeout, is_intrusion=True)

    def run_technique(
        self,
        technique_id: str,
        test_index: int = 0,
        timeout: float = 30.0,
        platforms: Optional[List[str]] = None,
    ) -> EmulationResult:
        """Look up curated Atomic Red Team tests for a MITRE technique and execute."""
        from hecate_agent.core.atomic_red_team import (
            get_atomic_tests,
            synthesize_atomic_telemetry,
        )

        tests = get_atomic_tests(technique_id, platforms=platforms)
        if not tests:
            return EmulationResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"No curated Atomic Red Team test found for technique '{technique_id}'",
                duration_ms=0.0,
                backend=self.backend.name(),
                error_message=f"Unknown technique {technique_id}",
                command="",
            )

        if test_index >= len(tests):
            test_index = 0

        target_test = tests[test_index]

        if isinstance(self.backend, SimulationBackend):
            telemetry_by_cat = synthesize_atomic_telemetry(technique_id, platforms=platforms)
            flattened_events: List[Dict[str, Any]] = []
            for cat, evts in telemetry_by_cat.items():
                for e in evts:
                    evt_copy = dict(e)
                    evt_copy.setdefault("category", cat)
                    flattened_events.append(evt_copy)

            return EmulationResult(
                success=True,
                exit_code=0,
                stdout=f"Simulated execution of {technique_id} ({target_test.get('name', '')})",
                stderr="",
                duration_ms=5.0,
                backend=self.backend.name(),
                events=flattened_events,
                command=target_test.get("command", ""),
            )

        return self.run_atomic_test(target_test, timeout=timeout)
