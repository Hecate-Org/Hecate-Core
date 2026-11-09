"""Live terminal dashboard for Hecate Runner activity and host metrics."""

from __future__ import annotations

import logging
import sys
import time
from datetime import datetime
from types import ModuleType
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import termios as _termios
    import tty as _tty

    termios: Any = _termios
    tty: Any = _tty
except ImportError:
    termios = None
    tty = None

import click
from rich.live import Live

from hecate_agent.commands.monitor_integrations import (
    _INTEGRATION_IDS,
    _SOURCE_INTEGRATIONS,
    _confirmed_integration,
    _credential_status,
    _credential_summary,
    _integration_style,
    _integrations_panel,
)
from hecate_agent.commands import monitor_views
from hecate_agent.commands.monitor_samplers import (
    DiskSample,
    HostSample,
    HostSampler,
    RunnerStatus,
    RunnerStatusSampler,
    TrailEvent,
    _check_key,
    _duration,
    _is_runner_process_running,
    _latest_metrics,
    _percent,
    _read_events,
    _read_recent_error,
    _service_running,
    _tail,
    find_eval_workspace,
)
from hecate_agent.commands.monitor_metrics import (
    HuntsMetrics,
    PurpleTeamMetrics,
    SiemDriftMetrics,
    _collect_hunts_metrics,
    _collect_purple_team_metrics,
    _collect_siem_drift_metrics,
)
from hecate_agent.commands.monitor_views import (
    _STAGES,
    _LIVE_USAGE_CACHE,
    console,
    _LOG_RE,
    _TRAIL_RE,
    _bytes,
    _bar,
    _resource_panel,
    _host_telemetry_ribbon,
    _QUIET_SECONDS,
    _SELF_STARTING,
    _parse_time,
    _pipeline_state,
    _stage_in_progress,
    _stage_table,
    _stage_order,
    _STAGE_COLORS,
    _get_stage_color,
    _LINES_PER_EVENT,
    _recent_events,
    _activity_table,
    _calculate_llm_metrics,
    _build_summary_table,
    _narrow_usage_rows,
    _NARROW_USAGE_PANEL_HEIGHT,
    _NARROW_LLM_PANEL_HEIGHT,
    _INTEGRATIONS_PANEL_HEIGHT,
    _HUNTS_PANEL_HEIGHT,
    _MITRE_PANEL_HEIGHT,
    _DETAILED_MITRE_PANEL_HEIGHT,
    _PURPLE_PANEL_HEIGHT,
    _BOTTOM_DETAIL_PANELS_HEIGHT,
    _usage_rows,
    _USAGE_PANEL_HEIGHT,
    _BOTTOM_ROW_HEIGHT,
    _stage_line,
    _usage_panel,
    _search_count,
    _live_usage,
    _live_usage_panel,
    _hunts_panel,
    _hunts_summary_panel,
    _mitre_metrics_panel,
    _detections_panel,
    _purple_team_panel,
    _detection_rules_panel,
    _threat_observables_panel,
    _collect_outbound_metrics,
    _outbound_panel,
    _compact_progress,
    _compact_resources,
    _disk_summary,
    _disk_panel,
    _backlog_observation,
    _quota_text,
    _until_next_run,
    _runner_compact_summary,
    _get_cooldown_str,
    _tab_nav_bar,
    _hunts_table,
    _cti_feeds_panel,
    _ingestion_funnel_panel,
    _github_outbox_panel,
    _misp_outbox_panel,
    _bas_status_panel,
    _bas_events_panel,
    _runner_panel,
    _get_inbox_counts,
    _format_cycle_outcome,
    _siem_sync_panel,
    _siem_drift_diff_panel,
    _siem_drift_events_table,
    _siem_query_versions_table,
    _render_dashboard,
)
from hecate_agent.core.workspace import workspace_root

logger = logging.getLogger(__name__)

class _MonitorModule(ModuleType):
    @property
    def console(self) -> Any:
        return monitor_views.console

    @console.setter
    def console(self, value: Any) -> None:
        monitor_views.console = value

sys.modules[__name__].__class__ = _MonitorModule

__all__ = [
    "_STAGES",
    "_LIVE_USAGE_CACHE",
    "monitor",
    "console",
    "DiskSample",
    "HostSample",
    "HostSampler",
    "RunnerStatus",
    "RunnerStatusSampler",
    "TrailEvent",
    "HuntsMetrics",
    "PurpleTeamMetrics",
    "SiemDriftMetrics",
    "_collect_hunts_metrics",
    "_collect_purple_team_metrics",
    "_collect_siem_drift_metrics",
    "_integrations_panel",
    "_INTEGRATION_IDS",
    "_SOURCE_INTEGRATIONS",
    "_confirmed_integration",
    "_credential_status",
    "_credential_summary",
    "_integration_style",
    "_duration",
    "_percent",
    "_service_running",
    "_tail",
    "_read_events",
    "_read_recent_error",
    "_latest_metrics",
    "_check_key",
    "_is_runner_process_running",
    "find_eval_workspace",
    "console",
    "_LOG_RE",
    "_TRAIL_RE",
    "_bytes",
    "_bar",
    "_resource_panel",
    "_host_telemetry_ribbon",
    "_QUIET_SECONDS",
    "_SELF_STARTING",
    "_parse_time",
    "_pipeline_state",
    "_stage_in_progress",
    "_stage_table",
    "_stage_order",
    "_STAGE_COLORS",
    "_get_stage_color",
    "_LINES_PER_EVENT",
    "_recent_events",
    "_activity_table",
    "_calculate_llm_metrics",
    "_build_summary_table",
    "_narrow_usage_rows",
    "_NARROW_USAGE_PANEL_HEIGHT",
    "_NARROW_LLM_PANEL_HEIGHT",
    "_INTEGRATIONS_PANEL_HEIGHT",
    "_HUNTS_PANEL_HEIGHT",
    "_MITRE_PANEL_HEIGHT",
    "_DETAILED_MITRE_PANEL_HEIGHT",
    "_PURPLE_PANEL_HEIGHT",
    "_BOTTOM_DETAIL_PANELS_HEIGHT",
    "_usage_rows",
    "_USAGE_PANEL_HEIGHT",
    "_BOTTOM_ROW_HEIGHT",
    "_stage_line",
    "_usage_panel",
    "_search_count",
    "_live_usage",
    "_live_usage_panel",
    "_hunts_panel",
    "_hunts_summary_panel",
    "_mitre_metrics_panel",
    "_detections_panel",
    "_purple_team_panel",
    "_detection_rules_panel",
    "_threat_observables_panel",
    "_collect_outbound_metrics",
    "_outbound_panel",
    "_compact_progress",
    "_compact_resources",
    "_disk_summary",
    "_disk_panel",
    "_backlog_observation",
    "_quota_text",
    "_until_next_run",
    "_runner_compact_summary",
    "_get_cooldown_str",
    "_tab_nav_bar",
    "_hunts_table",
    "_cti_feeds_panel",
    "_ingestion_funnel_panel",
    "_github_outbox_panel",
    "_misp_outbox_panel",
    "_bas_status_panel",
    "_bas_events_panel",
    "_runner_panel",
    "_get_inbox_counts",
    "_format_cycle_outcome",
    "_siem_sync_panel",
    "_siem_drift_diff_panel",
    "_siem_drift_events_table",
    "_siem_query_versions_table",
    "_render_dashboard",
]

@click.command()
@click.option(
    "--workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Hecate workspace to monitor.",
)
@click.option(
    "--eval",
    "eval_mode",
    is_flag=True,
    help="Monitor the active or most recent evaluation run in /tmp/eval_runs.",
)
@click.option(
    "--interval",
    type=click.FloatRange(min=0.5, max=30),
    default=1.0,
    show_default=True,
    help="Screen refresh interval in seconds.",
)
def monitor(workspace: Optional[Path], eval_mode: bool = False, interval: float = 1.0) -> None:
    """Open a live htop-style dashboard for Hecate pipeline activity."""
    if eval_mode:
        detected = find_eval_workspace()
        if detected:
            workspace = detected
        else:
            console.print("[yellow]No evaluation workspace found in /tmp/eval_runs.[/]")
            return
    elif workspace is None:
        default_root = workspace_root(None)
        active_eval = find_eval_workspace()
        if active_eval and _is_runner_process_running(active_eval):
            workspace = active_eval
        else:
            runner_sampler_check = RunnerStatusSampler(default_root)
            runner_check = runner_sampler_check.sample()
            if (
                runner_check.installed
                and runner_check.workspace
                and runner_check.workspace.exists()
                and (runner_check.workspace / "logs" / "orchestrator.log").exists()
            ):
                workspace = runner_check.workspace
            elif (
                runner_check.installed
                and runner_check.workspace
                and (runner_check.workspace / "Hecate-Workspace" / "logs" / "orchestrator.log").exists()
            ):
                workspace = runner_check.workspace / "Hecate-Workspace"
            elif (default_root / "Hecate-Workspace" / "logs" / "orchestrator.log").exists():
                workspace = default_root / "Hecate-Workspace"
            elif (
                runner_check.installed
                and runner_check.workspace
                and runner_check.workspace.exists()
                and (runner_check.workspace / "hunts").exists()
                and any((runner_check.workspace / "hunts").glob("*.md"))
            ):
                workspace = runner_check.workspace
            elif (default_root / "Hecate-Workspace" / "hunts").exists():
                workspace = default_root / "Hecate-Workspace"
            elif (Path.home() / "betas" / "Hecate-Workspace" / "hunts").exists():
                workspace = Path.home() / "betas" / "Hecate-Workspace"
            elif (default_root / "hunts").exists() and any((default_root / "hunts").glob("*.md")):
                workspace = default_root
            elif active_eval and (active_eval / "logs" / "orchestrator.log").exists():
                workspace = active_eval
            else:
                workspace = default_root

    root = workspace_root(workspace)
    log_path = root / "logs" / "orchestrator.log"
    metrics_path = root / "logs" / "stage_metrics.jsonl"
    call_log = root / "logs" / "llm_calls.jsonl"
    sampler = HostSampler(root)
    runner_sampler = RunnerStatusSampler(root)

    active_tab = 1
    errors_only = False
    paused = False

    events: List[TrailEvent] = []
    recent_error: str = ""
    metrics: Dict[str, Any] = {}
    calls: Optional[Dict[str, Any]] = None

    old_term_settings = None
    if sys.stdin.isatty() and termios is not None and tty is not None:
        try:
            old_term_settings = termios.tcgetattr(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
        except Exception:
            old_term_settings = None

    try:
        with Live(console=console, screen=True, refresh_per_second=4, transient=False) as live:
            while True:
                if not log_path.exists() and (root / "Hecate-Workspace" / "logs" / "orchestrator.log").exists():
                    root = root / "Hecate-Workspace"
                    log_path = root / "logs" / "orchestrator.log"
                    metrics_path = root / "logs" / "stage_metrics.jsonl"
                    call_log = root / "logs" / "llm_calls.jsonl"
                    sampler = HostSampler(root)
                    runner_sampler = RunnerStatusSampler(root)
                if not paused:
                    events = _read_events(log_path)
                    recent_error = _read_recent_error(log_path)
                    metrics = _latest_metrics(metrics_path)
                    calls = _live_usage(call_log)
                host = sampler.sample()
                runner = runner_sampler.sample()
                live.update(
                    _render_dashboard(
                        root,
                        events,
                        metrics,
                        host,
                        datetime.now(),
                        runner,
                        recent_error,
                        calls,
                        active_tab=active_tab,
                        errors_only=errors_only,
                        paused=paused,
                    ),
                    refresh=True,
                )
                deadline = time.monotonic() + interval
                while time.monotonic() < deadline:
                    wait_time = max(0.0, min(0.1, deadline - time.monotonic()))
                    key = _check_key(wait_time)
                    if key is not None:
                        if key in ("q", "Q", "\x03", "\x04"):
                            raise KeyboardInterrupt
                        elif key in ("1", "2", "3", "4", "5"):
                            active_tab = int(key)
                            break
                        elif key in ("\t", "\x1b[C"):
                            active_tab = (active_tab % 5) + 1
                            break
                        elif key == "\x1b[D":
                            active_tab = 5 if active_tab == 1 else (active_tab - 1)
                            break
                        elif key in ("e", "E"):
                            errors_only = not errors_only
                            break
                        elif key in ("p", "P", " "):
                            paused = not paused
                            break
    except KeyboardInterrupt:
        pass
    finally:
        if old_term_settings is not None and termios is not None:
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_term_settings)
            except Exception:
                pass
        console.show_cursor(True)
