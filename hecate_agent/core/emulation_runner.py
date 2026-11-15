"""Ephemeral Container Emulation Runner and Purple-Team Detonation Sandbox.

Executes adversary emulation procedures (Atomic Red Team tests, synthetic detonation commands)
inside ephemeral sandboxes, capturing raw execution traces and streaming normalized
telemetry events into Hecate's Sigma evaluator for closed-loop detection validation.

Supported Execution Backends:
- BwrapBackend: Linux rootless unprivileged containerization via bubblewrap (bwrap).
  Binds only runtime paths read-only, hides home/root, disables network, and uses
  an ephemeral tmpfs for /tmp; intercepts syscalls via strace.
- DockerBackend: Ephemeral Docker/Podman containers with no network, read-only root,
  no-new-privileges, and all capabilities dropped.
- SubprocessBackend: Explicit opt-in only (HECATE_ALLOW_UNSANDBOXED_EMULATION=1 or
  allow_unsandboxed=True). Never selected automatically.
- MockBackend / SimulationBackend: Deterministic synthetic backends for CI and safe default.
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
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from hecate_agent.core.sigma_evaluator import EvaluationReport, SigmaEvaluator
from hecate_agent.core.subprocess_utils import run_process_group
from hecate_agent.core.telemetry_harvester import TelemetryHarvester

logger = logging.getLogger(__name__)

_UNSANDBOXED_ENV = "HECATE_ALLOW_UNSANDBOXED_EMULATION"


def _ptrace_unavailable(stderr: str) -> bool:
    """Detect strace failing before it could run the requested command."""
    return "ptrace(" in stderr and "Operation not permitted" in stderr


def _unsandboxed_emulation_allowed(explicit: bool = False) -> bool:
    return explicit or os.environ.get(_UNSANDBOXED_ENV, "").strip() == "1"


def _bwrap_ro_binds() -> List[str]:
    """Host paths required to run a minimal shell command, bound read-only."""
    args: List[str] = []
    for path in ("/usr", "/bin", "/lib", "/lib64", "/sbin"):
        if Path(path).exists():
            args.extend(["--ro-bind", path, path])
    for path in (
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/alternatives",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/group",
    ):
        if Path(path).exists():
            args.extend(["--ro-bind", path, path])
    return args


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

        binds = _bwrap_ro_binds()
        if not binds:
            raise RuntimeError("bwrap sandbox could not bind any host runtime paths")

        # Network is disabled; home/root/var are replaced with empty tmpfs so
        # host secrets under those trees are not readable from the sandbox.
        bwrap_cmd = [
            self.bwrap_bin,
            "--die-with-parent",
            "--new-session",
            "--unshare-net",
            "--unshare-pid",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin:/usr/sbin:/sbin",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            *binds,
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/home",
            "--tmpfs",
            "/root",
            "--tmpfs",
            "/var",
            "--tmpfs",
            "/run",
            "--chdir",
            "/tmp",
            "sh",
            "-c",
            command,
        ]

        cmd = [
            self.strace_bin,
            "-f",
            "-s",
            "256",
            "-e",
            "trace=execve,openat,creat,unlink,unlinkat,rename,renameat,renameat2,connect",
            *bwrap_cmd,
        ]

        try:
            proc = run_process_group(
                cmd,
                text=True,
                timeout=timeout,
                cwd=workdir,
            )
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
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,exec,nosuid,nodev,size=64m",
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--user",
            "65534:65534",
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
    """Host-process fallback. Disabled unless explicitly opted in.

    This backend runs ``sh -c`` on the host and must never be the automatic
    choice for purple-team detonation. Opt in with ``allow_unsandboxed=True``
    or ``HECATE_ALLOW_UNSANDBOXED_EMULATION=1``.
    """

    def __init__(self, *, allow_unsandboxed: bool = False) -> None:
        self.allow_unsandboxed = _unsandboxed_emulation_allowed(allow_unsandboxed)
        self.strace_bin = shutil.which("strace") if os.name == "posix" else None

    def name(self) -> str:
        return "subprocess"

    def is_available(self) -> bool:
        return self.allow_unsandboxed

    def run(
        self,
        command: str,
        timeout: float = 30.0,
        workdir: Optional[str] = None,
    ) -> Tuple[int, str, str, str]:
        if not self.allow_unsandboxed:
            raise RuntimeError(
                "Unsandboxed subprocess emulation is disabled. Use bwrap/docker "
                f"or set {_UNSANDBOXED_ENV}=1 only for controlled local debugging."
            )

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
                if (
                    self.strace_bin
                    and proc.returncode != 0
                    and not proc.stdout
                    and _ptrace_unavailable(proc.stderr)
                ):
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
            sp = SubprocessBackend()
            if sp.is_available():
                self.backend = sp
            else:
                logger.warning(
                    "Subprocess emulation requested but unsandboxed mode is disabled; "
                    "using simulation backend instead"
                )
                self.backend = SimulationBackend()
        elif backend == "mock":
            self.backend = MockBackend()
        else:
            # Auto-detect: real sandboxes only; never fall back to host subprocess.
            bwrap = BwrapBackend()
            docker = DockerBackend()
            if bwrap.is_available():
                self.backend = bwrap
            elif docker.is_available():
                self.backend = docker
            else:
                logger.info(
                    "No bwrap/docker sandbox available; using simulation backend "
                    "(refusing unsandboxed host execution)"
                )
                self.backend = SimulationBackend()

    def run_command(
        self,
        command: str,
        timeout: float = 30.0,
        workdir: Optional[str] = None,
        is_intrusion: bool = True,
    ) -> EmulationResult:
        """Execute a shell command inside the sandbox and capture telemetry."""
        start_time = time.perf_counter()

        try:
            exit_code, stdout, stderr, raw_trace = self.backend.run(
                command,
                timeout=timeout,
                workdir=workdir,
            )
        except RuntimeError as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000
            return EmulationResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_ms=duration_ms,
                backend=self.backend.name(),
                error_message=str(exc),
                command=command,
            )

        duration_ms = (time.perf_counter() - start_time) * 1000

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
