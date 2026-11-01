"""Host, runner status, and telemetry sampling for Hecate monitor."""

from __future__ import annotations

import json
import logging
import os
import re
import select
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hecate_agent.core.sqlite_utils import connect_sqlite

logger = logging.getLogger(__name__)

_LOG_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ \[(\w+)\] ([\w.]+): (.*)$")
_TRAIL_RE = re.compile(r"^\[([a-f0-9]+) \+\s*([\d.]+)s\]\s+(\S+)\s+(.*)$")


@dataclass
class TrailEvent:
    timestamp: str
    cycle_id: str
    elapsed: float
    stage: str
    message: str


@dataclass
class HostSample:
    cpu_percent: Optional[float]
    memory_used: Optional[int]
    memory_total: Optional[int]
    disks: List["DiskSample"]
    gpu_name: str = "unavailable"
    gpu_percent: Optional[float] = None
    gpu_memory_used: Optional[int] = None
    gpu_memory_total: Optional[int] = None


@dataclass
class DiskSample:
    mount: str
    used: int
    total: int


@dataclass
class RunnerStatus:
    installed: bool = False
    timer_active: bool = False
    daemon_active: bool = False
    service_state: str = "unknown"
    next_run: Optional[datetime] = None
    drafts_today: Optional[int] = None
    drafts_limit: Optional[int] = None
    research_today: Optional[int] = None
    research_limit: Optional[int] = None
    total_drafts: Optional[int] = None
    parked_items: Optional[int] = None
    #: The workspace the service writes to; the service's state says nothing about any other.
    workspace: Optional[Path] = None
    cost_today: Optional[float] = None
    cost_limit: Optional[float] = None
    pending_queries: Optional[int] = None
    cti_provider: Optional[str] = None
    parked_reasons: Dict[str, int] = field(default_factory=dict)
    query_provider: str = "mock"
    cooldown_remaining_sec: Optional[float] = None
    github_pending_prs: int = 0
    github_confirmed_promotions: int = 0
    misp_confirmed_exports: int = 0
    misp_pending_exports: int = 0


def _read_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.split("#", 1)[0].strip().strip("\"'")
    return values


def _env_int(env: Dict[str, str], key: str) -> Optional[int]:
    try:
        return int(env[key])
    except (KeyError, TypeError, ValueError):
        return None


@dataclass
class _HeavyRunnerData:
    drafts_today: Optional[int] = None
    drafts_limit: Optional[int] = None
    research_today: Optional[int] = None
    research_limit: Optional[int] = None
    total_drafts: Optional[int] = None
    parked_items: Optional[int] = None
    workspace: Optional[Path] = None
    cost_limit: Optional[float] = None
    pending_queries: Optional[int] = None
    cti_provider: Optional[str] = None
    parked_reasons: Dict[str, int] = field(default_factory=dict)
    query_provider: str = "mock"
    github_pending_prs: int = 0
    github_confirmed_promotions: int = 0
    misp_confirmed_exports: int = 0
    misp_pending_exports: int = 0


class RunnerStatusSampler:
    """Read service scheduling and quota state without starting Runner work."""

    SERVICE = "hecate-runner-orchestrator.service"
    TIMER = "hecate-runner-orchestrator.timer"
    DAEMON = "hecate-runner-daemon.service"

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self._fast_checked_at = 0.0
        self._heavy_checked_at = 0.0
        self._cached = RunnerStatus()
        self._units: Dict[str, Dict[str, str]] = {}
        self._heavy_data: Optional[_HeavyRunnerData] = None

    def _sample_heavy(self, runner_dir: Path) -> _HeavyRunnerData:
        env: Dict[str, str] = {}
        # Unified environment discovery: loads workspace .env first, then runner .env as local override
        candidate_files = [
            self.workspace / ".env",
            self.workspace / "Hecate-Workspace" / ".env",
            Path.home() / "betas" / "Hecate-Workspace" / ".env",
            runner_dir / ".env",
        ]
        seen_paths = set()
        for cand in candidate_files:
            try:
                resolved = cand.resolve()
            except OSError:
                continue
            if resolved not in seen_paths and cand.is_file():
                seen_paths.add(resolved)
                for k, v in _read_env_file(cand).items():
                    env[k] = v
        quota_workspace = Path(env.get("HECATE_WORKSPACE", str(self.workspace))).expanduser()
        if not quota_workspace.is_absolute():
            quota_workspace = runner_dir / quota_workspace
        state: Dict[str, Any] = {}
        try:
            state = json.loads((quota_workspace / ".orchestrator_state.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            pass
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        same_day = state.get("date") == today
        queue_dir = Path(env.get("HECATE_RUNNER_CTI_QUEUE_DIR", str(quota_workspace / "cti_queue")).strip("\"'"))
        if not queue_dir.is_absolute():
            queue_dir = runner_dir / queue_dir
        parked_reasons: Dict[str, int] = {}
        try:
            parked_files = list((queue_dir / "parked").glob("*.json"))
            parked = len(parked_files)
            for pf in parked_files[:30]:
                try:
                    pdata = json.loads(pf.read_text(encoding="utf-8"))
                    reason = str(pdata.get("reason", "unknown")).lower()
                    if "commentary" in reason:
                        cat = "commentary"
                    elif "behavior" in reason:
                        cat = "no_behavior"
                    elif "unsupported" in reason:
                        cat = "unsupported"
                    elif "freshness" in reason or "age" in reason:
                        cat = "stale"
                    else:
                        cat = reason.split()[0] if reason else "other"
                    parked_reasons[cat] = parked_reasons.get(cat, 0) + 1
                except Exception:
                    pass
        except OSError:
            parked = None

        pending_queries: Optional[int] = None
        pending_dir = quota_workspace / ".pending_queries"
        try:
            if pending_dir.exists():
                pending_queries = len(list(pending_dir.glob("*.json")))
        except OSError:
            pass

        cti_provider = env.get("HECATE_RUNNER_CTI_PROVIDER")
        if cti_provider == "multi":
            sub_prov = env.get("HECATE_RUNNER_CTI_MULTI_PROVIDERS", "rss,otx,misp")
            cti_provider = f"multi ({sub_prov})"

        cost_limit_val: Optional[float] = None
        try:
            if "HECATE_RUNNER_DAILY_BUDGET_USD" in env:
                cost_limit_val = float(env["HECATE_RUNNER_DAILY_BUDGET_USD"])
            else:
                cost_limit_val = 20.0
        except (ValueError, TypeError):
            cost_limit_val = 20.0

        target_ws = self.workspace if (self.workspace / ".hecate").exists() else quota_workspace
        gh_published, gh_pending = 0, 0
        gh_db = target_ws / ".hecate" / "publisher" / "promotion-outbox.sqlite3"
        if not gh_db.exists():
            gh_db = target_ws / ".hecate" / "github" / "outbox.sqlite3"
        if gh_db.exists():
            try:
                conn = connect_sqlite(gh_db, timeout=2.0, wal=False, busy_timeout_ms=3000)
                try:
                    for s, count in conn.execute("SELECT status, count(*) FROM promotions GROUP BY status").fetchall():
                        if str(s).lower() in ("published", "merged", "closed"):
                            gh_published += count
                        else:
                            gh_pending += count
                finally:
                    conn.close()
            except Exception:
                pass

        misp_confirmed, misp_pending = 0, 0
        misp_db = target_ws / ".hecate" / "misp" / "outbox.sqlite3"
        if misp_db.exists():
            try:
                conn = connect_sqlite(misp_db, timeout=2.0, wal=False, busy_timeout_ms=3000)
                try:
                    for s, count in conn.execute("SELECT status, count(*) FROM exports GROUP BY status").fetchall():
                        if str(s).lower() == "confirmed":
                            misp_confirmed += count
                        else:
                            misp_pending += count
                finally:
                    conn.close()
            except Exception:
                pass

        return _HeavyRunnerData(
            drafts_today=(
                int(state.get("drafts_today", 0)) if same_day and "drafts_today" in state else (0 if same_day else None)
            ),
            drafts_limit=_env_int(env, "HECATE_RUNNER_MAX_DRAFTS_PER_DAY"),
            research_today=(
                int(state.get("research_runs_today", 0))
                if same_day and "research_runs_today" in state
                else (0 if same_day else None)
            ),
            research_limit=_env_int(env, "HECATE_RUNNER_MAX_RESEARCH_RUNS_PER_DAY"),
            total_drafts=int(state["total_drafts_ever"]) if "total_drafts_ever" in state else None,
            parked_items=parked,
            workspace=quota_workspace,
            cost_limit=cost_limit_val,
            pending_queries=pending_queries,
            cti_provider=cti_provider,
            parked_reasons=parked_reasons,
            query_provider=env.get("HECATE_RUNNER_QUERY_PROVIDER") or "mock",
            github_pending_prs=gh_pending,
            github_confirmed_promotions=gh_published,
            misp_confirmed_exports=misp_confirmed,
            misp_pending_exports=misp_pending,
        )

    def sample(self, force: bool = False) -> RunnerStatus:
        now = time.monotonic()
        # Fast tier: check systemctl units every 2.0s
        if force or (now - self._fast_checked_at >= 2.0) or not self._units:
            self._fast_checked_at = now
            try:
                result = subprocess.run(
                    [
                        "systemctl",
                        "show",
                        self.TIMER,
                        self.SERVICE,
                        self.DAEMON,
                        "-p",
                        "Id",
                        "-p",
                        "LoadState",
                        "-p",
                        "ActiveState",
                        "-p",
                        "WorkingDirectory",
                    ],
                    capture_output=True,
                    check=True,
                    text=True,
                    timeout=1.5,
                )
                units: Dict[str, Dict[str, str]] = {}
                for block in result.stdout.split("\n\n"):
                    values = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
                    if values.get("Id"):
                        units[values["Id"]] = values
                self._units = units
            except (OSError, subprocess.SubprocessError):
                self._units = {}

        timer = self._units.get(self.TIMER, {})
        service = self._units.get(self.SERVICE, {})
        daemon = self._units.get(self.DAEMON, {})
        installed = (
            timer.get("LoadState") not in {None, "not-found"}
            or service.get("LoadState") not in {None, "not-found"}
            or daemon.get("LoadState") not in {None, "not-found"}
        )
        daemon_active = daemon.get("ActiveState") == "active"
        if daemon_active:
            timer_active = False
            service_state = "active"
            next_run = None
        else:
            timer_active = timer.get("ActiveState") == "active"
            service_state = service.get("ActiveState", "unknown")
            next_run = self._next_timer_run() if timer_active else None

        runner_dir = Path(
            daemon.get("WorkingDirectory") or service.get("WorkingDirectory") or self.workspace.parent / "Hecate-Runner"
        )

        # Heavy tier: disk reads, parked queue JSON parsing, SQLite outbox queries every 12.0s
        if force or (self._heavy_data is None) or (now - self._heavy_checked_at >= 12.0):
            self._heavy_checked_at = now
            self._heavy_data = self._sample_heavy(runner_dir)

        hd = self._heavy_data
        self._cached = RunnerStatus(
            installed=installed,
            timer_active=timer_active,
            daemon_active=daemon_active,
            service_state=service_state,
            next_run=next_run,
            drafts_today=hd.drafts_today,
            drafts_limit=hd.drafts_limit,
            research_today=hd.research_today,
            research_limit=hd.research_limit,
            total_drafts=hd.total_drafts,
            parked_items=hd.parked_items,
            workspace=hd.workspace,
            cost_limit=hd.cost_limit,
            pending_queries=hd.pending_queries,
            cti_provider=hd.cti_provider,
            parked_reasons=hd.parked_reasons,
            query_provider=hd.query_provider,
            github_pending_prs=hd.github_pending_prs,
            github_confirmed_promotions=hd.github_confirmed_promotions,
            misp_confirmed_exports=hd.misp_confirmed_exports,
            misp_pending_exports=hd.misp_pending_exports,
        )
        return self._cached

    @classmethod
    def _next_timer_run(cls) -> Optional[datetime]:
        try:
            result = subprocess.run(
                ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend", cls.TIMER],
                capture_output=True,
                check=True,
                text=True,
                timeout=1.5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 5 or cls.TIMER not in fields:
                continue
            try:
                scheduled = datetime.strptime(" ".join(fields[:3]), "%a %Y-%m-%d %H:%M:%S")
                return scheduled.replace(tzinfo=datetime.now().astimezone().tzinfo)
            except ValueError:
                continue
        return None


class HostSampler:
    """Read inexpensive host metrics without requiring a monitoring package."""

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self._cpu_previous: Optional[Tuple[int, int]] = None
        self._gpu_last_check = 0.0
        self._gpu_cache: Dict[str, Any] = {}

    def sample(self) -> HostSample:
        cpu = self._cpu_percent()
        memory_used, memory_total = self._memory()
        disks = self._disks(self.workspace)
        if time.monotonic() - self._gpu_last_check >= 3:
            self._gpu_cache = self._gpu()
            self._gpu_last_check = time.monotonic()
        return HostSample(
            cpu_percent=cpu,
            memory_used=memory_used,
            memory_total=memory_total,
            disks=disks,
            **self._gpu_cache,
        )

    @staticmethod
    def _disks(workspace: Path) -> List[DiskSample]:
        """Collect local filesystems backing Hecate's workspace and mounted data."""
        disks: List[DiskSample] = []
        seen_devices = set()
        workspace_path = workspace.resolve()
        try:
            mounts = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
        except OSError:
            return disks

        for line in mounts:
            fields = line.split()
            if len(fields) < 3:
                continue
            source, target = fields[:2]
            if not source.startswith("/dev/") or source.startswith("/dev/loop"):
                continue
            # /proc/mounts encodes spaces and tabs as octal escapes.
            target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), target)
            mount_path = Path(target)
            if not (
                workspace_path == mount_path
                or workspace_path.is_relative_to(mount_path)
                or mount_path.is_relative_to(workspace_path)
            ):
                continue
            try:
                device_id = os.stat(mount_path).st_dev
                if device_id in seen_devices:
                    continue
                usage = shutil.disk_usage(mount_path)
            except OSError:
                continue
            seen_devices.add(device_id)
            label = target if target == "/" else str(mount_path)
            disks.append(DiskSample(label, usage.used, usage.total))
        return disks

    def _cpu_percent(self) -> Optional[float]:
        try:
            fields = Path("/proc/stat").read_text(encoding="ascii").splitlines()[0].split()[1:]
            values = [int(value) for value in fields]
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            total = sum(values)
        except (OSError, ValueError, IndexError):
            return None
        previous = self._cpu_previous
        self._cpu_previous = (idle, total)
        if previous is None:
            return None
        idle_delta = idle - previous[0]
        total_delta = total - previous[1]
        if total_delta <= 0:
            return None
        return max(0.0, min(100.0, 100.0 * (1 - idle_delta / total_delta)))

    @staticmethod
    def _memory() -> Tuple[Optional[int], Optional[int]]:
        try:
            values: Dict[str, int] = {}
            for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
                key, raw = line.split(":", 1)
                values[key] = int(raw.strip().split()[0]) * 1024
            total = values["MemTotal"]
            available = values.get("MemAvailable", values.get("MemFree", total))
            return max(0, total - available), total
        except (OSError, ValueError, KeyError, IndexError):
            return None, None

    @staticmethod
    def _gpu() -> Dict[str, Any]:
        try:
            result = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=name,utilization.gpu,memory.used,memory.total",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                check=True,
                text=True,
                timeout=0.8,
            )
            fields = [field.strip() for field in result.stdout.splitlines()[0].split(",")]
            return {
                "gpu_name": fields[0],
                "gpu_percent": float(fields[1]),
                "gpu_memory_used": int(fields[2]) * 1024 * 1024,
                "gpu_memory_total": int(fields[3]) * 1024 * 1024,
            }
        except (OSError, subprocess.SubprocessError, ValueError, IndexError):
            return {"gpu_name": "not detected", "gpu_percent": None, "gpu_memory_used": None, "gpu_memory_total": None}


def _tail(path: Path, limit: int = 180) -> List[str]:
    """Read only the last part of an append-only log."""
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 160_000))
            raw = handle.read().decode("utf-8", errors="replace")
        return raw.splitlines()[-limit:]
    except OSError:
        return []


def _read_events(log_path: Path) -> List[TrailEvent]:
    events: List[TrailEvent] = []
    for line in _tail(log_path):
        match = _LOG_RE.match(line)
        if not match or match.group(3) != "hecate_runner.trail":
            continue
        trail = _TRAIL_RE.match(match.group(4))
        if not trail:
            continue
        cycle_id, elapsed, stage, message = trail.groups()
        events.append(TrailEvent(match.group(1), cycle_id, float(elapsed), stage, message))
    return events


_RECENT_ERROR_CACHE: Dict[str, Tuple[int, int, str]] = {}
_LATEST_METRICS_CACHE: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}


def clear_sampler_caches() -> None:
    """Clear in-memory samplers cache."""
    _RECENT_ERROR_CACHE.clear()
    _LATEST_METRICS_CACHE.clear()


def _read_recent_error(log_path: Path) -> str:
    try:
        stat = log_path.stat()
        mtime_ns = stat.st_mtime_ns
        size = stat.st_size
        key = str(log_path.resolve())
        cached = _RECENT_ERROR_CACHE.get(key)
        if cached is not None and cached[0] == mtime_ns and cached[1] == size:
            return cached[2]
    except OSError:
        return ""

    error_block = []
    in_error = False

    for line in _tail(log_path, limit=300):
        match = _LOG_RE.match(line)
        if match:
            level = match.group(2)
            if level in {"ERROR", "CRITICAL"}:
                in_error = True
                error_block = [line]
            else:
                in_error = False
        else:
            if in_error or error_block:
                error_block.append(line)

    res = "\n".join(error_block[-20:]) if error_block else ""
    _RECENT_ERROR_CACHE[key] = (mtime_ns, size, res)
    return res


def _latest_metrics(metrics_path: Path) -> Dict[str, Any]:
    try:
        stat = metrics_path.stat()
        mtime_ns = stat.st_mtime_ns
        size = stat.st_size
        key = str(metrics_path.resolve())
        cached = _LATEST_METRICS_CACHE.get(key)
        if cached is not None and cached[0] == mtime_ns and cached[1] == size:
            return cached[2]
    except OSError:
        return {}

    lines = _tail(metrics_path, limit=2000)
    aggregate = {
        "llm_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "estimated_cost_usd": 0.0,
        "completed_cycles": 0,
        "cost_today_usd": 0.0,
        "calls_today": 0,
        "cycles_today": 0,
    }
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cost_today_usd = 0.0
    calls_today = 0
    cycles_today = 0
    latest_val: Dict[str, Any] = {}
    latest_with_llm: Dict[str, Any] = {}
    for line in lines:
        try:
            val = json.loads(line)
            if isinstance(val, dict) and isinstance(val.get("stages"), list):
                aggregate["completed_cycles"] += 1
                latest_val = val
                started_at = str(val.get("started_at", ""))
                is_today = started_at.startswith(today)
                if is_today:
                    cycles_today += 1
                has_llm = any(isinstance(s, dict) and (s.get("llm_calls") or 0) > 0 for s in val["stages"])
                if has_llm:
                    latest_with_llm = val
                for stage in val["stages"]:
                    if isinstance(stage, dict):
                        calls = int(stage.get("llm_calls") or 0)
                        inp = int(stage.get("input_tokens") or 0)
                        outp = int(stage.get("output_tokens") or 0)
                        cost = float(stage.get("estimated_cost_usd") or 0.0)
                        aggregate["llm_calls"] += calls
                        aggregate["input_tokens"] += inp
                        aggregate["output_tokens"] += outp
                        aggregate["estimated_cost_usd"] += cost
                        if is_today:
                            calls_today += calls
                            cost_today_usd += cost
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    aggregate["cost_today_usd"] = cost_today_usd
    aggregate["calls_today"] = calls_today
    aggregate["cycles_today"] = cycles_today
    if latest_with_llm and not any(
        isinstance(s, dict) and (s.get("llm_calls") or 0) > 0 for s in latest_val.get("stages", [])
    ):
        latest_val = dict(latest_val)
        latest_val["stages"] = latest_with_llm.get("stages", [])
        latest_val["models"] = latest_with_llm.get("models", [])
        latest_val["hunt_id"] = latest_with_llm.get("hunt_id")
        latest_val["research_id"] = latest_with_llm.get("research_id")
    latest_val["aggregate"] = aggregate
    _LATEST_METRICS_CACHE[key] = (mtime_ns, size, latest_val)
    return latest_val


def _is_runner_process_running(workspace: Optional[Path] = None) -> bool:
    """Check if any hecate-runner process is currently running on the host for the given workspace."""
    try:
        current_pid = os.getpid()
        ws_resolved = workspace.resolve() if workspace else None
        for pid_dir in Path("/proc").glob("[0-9]*"):
            try:
                pid = int(pid_dir.name)
                if pid == current_pid:
                    continue
                cmdline = (pid_dir / "cmdline").read_bytes().decode("utf-8", errors="ignore").replace("\x00", " ")
                cmdline_lower = cmdline.lower()
                if (
                    "hecate-runner" in cmdline_lower
                    or "replay.py" in cmdline_lower
                    or "run_two_evals.py" in cmdline_lower
                    or "run_three_evals.py" in cmdline_lower
                    or ("hecate-agent" in cmdline_lower and "monitor" not in cmdline_lower)
                ):
                    if ws_resolved is None:
                        return True
                    parts = cmdline.split()
                    for idx, part in enumerate(parts):
                        if part in ("--workspace", "-w") and idx + 1 < len(parts):
                            try:
                                if Path(parts[idx + 1]).resolve() == ws_resolved:
                                    return True
                            except OSError:
                                pass
                    try:
                        cwd = Path(f"/proc/{pid}/cwd").resolve()
                        if cwd == ws_resolved:
                            return True
                    except (OSError, ValueError):
                        pass
            except (OSError, ValueError):
                continue
    except Exception:
        pass
    return False


def find_eval_workspace(eval_base: Path = Path("/tmp/eval_runs"), check_procs: bool = True) -> Optional[Path]:
    """Find the actively running evaluation workspace, or the most recent one in eval_base."""
    if not eval_base.exists():
        return None
    if check_procs:
        try:
            for pid_dir in Path("/proc").glob("[0-9]*"):
                try:
                    cmdline = (pid_dir / "cmdline").read_bytes().decode("utf-8", errors="ignore").replace("\x00", " ")
                    if "replay.py" in cmdline:
                        parts = cmdline.split()
                        for i, p in enumerate(parts):
                            if p == "--workspace" and i + 1 < len(parts):
                                ws = Path(parts[i + 1])
                                if ws.is_dir() and (ws / "logs" / "orchestrator.log").exists():
                                    return ws
                except (OSError, ValueError):
                    continue
        except Exception:
            pass

    candidates = [p for p in eval_base.iterdir() if p.is_dir() and (p / "logs" / "orchestrator.log").exists()]
    if candidates:
        candidates.sort(key=lambda p: (p / "logs" / "orchestrator.log").stat().st_mtime, reverse=True)
        return candidates[0]
    return None


def _service_running(runner: RunnerStatus, workspace: Path) -> Optional[bool]:
    """Whether the Runner service or process is working, or None when it is not writing to ``workspace``."""
    if runner.installed and runner.workspace is not None:
        try:
            if runner.workspace.resolve() == workspace.resolve() and runner.service_state in {"active", "activating"}:
                return True
        except OSError:
            pass

    if _is_runner_process_running(workspace):
        return True

    if not runner.installed or runner.workspace is None:
        return None
    try:
        if runner.workspace.resolve() != workspace.resolve():
            return None
    except OSError:
        return None
    return False


def _duration(seconds: Optional[float]) -> str:
    total = int(seconds or 0)
    minutes, secs = divmod(total, 60)
    return f"{minutes}m {secs:02d}s" if minutes else f"{secs}s"


def _percent(used: Optional[int], total: Optional[int]) -> Optional[float]:
    if used is None or not total:
        return None
    return max(0.0, min(100.0, used * 100 / total))


def _check_key(timeout: float = 0.0) -> Optional[str]:
    """Non-blocking check for keyboard character on sys.stdin."""
    if not sys.stdin.isatty():
        return None
    try:
        rlist, _, _ = select.select([sys.stdin], [], [], timeout)
        if rlist:
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                rlist2, _, _ = select.select([sys.stdin], [], [], 0.05)
                if rlist2:
                    seq = sys.stdin.read(2)
                    return f"\x1b{seq}"
            return ch
    except Exception:
        pass
    return None
