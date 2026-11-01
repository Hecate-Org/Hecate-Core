"""Live terminal dashboard for Hecate Runner activity and host metrics."""

from __future__ import annotations

import re
import sqlite3
import sys
import textwrap
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import termios as _termios
    import tty as _tty

    termios: Any = _termios
    tty: Any = _tty
except ImportError:
    termios = None
    tty = None

import click
import yaml
from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hecate_agent.commands.monitor_integrations import (
    _INTEGRATION_IDS as _INTEGRATION_IDS,
    _SOURCE_INTEGRATIONS as _SOURCE_INTEGRATIONS,
    _confirmed_integration as _confirmed_integration,
    _credential_status as _credential_status,
    _credential_summary as _credential_summary,
    _integration_style as _integration_style,
    _integrations_panel,
)

from hecate_agent.core.llm_activity import summarize_calls
from hecate_agent.core.workspace import workspace_root

from hecate_agent.commands.monitor_metrics import (
    HuntsMetrics,
    PurpleTeamMetrics,
    _collect_hunts_metrics,
    _collect_purple_team_metrics,
    _HUNTS_METRICS_CACHE as _HUNTS_METRICS_CACHE,
    _PURPLE_METRICS_CACHE as _PURPLE_METRICS_CACHE,
    _EXCLUDED_HUNT_DOCS as _EXCLUDED_HUNT_DOCS,
)
from hecate_agent.commands.monitor_samplers import (
    DiskSample as DiskSample,
    HostSample,
    HostSampler,
    RunnerStatus,
    RunnerStatusSampler,
    TrailEvent,
    _check_key,
    _duration,
    _env_int as _env_int,
    _is_runner_process_running,
    _latest_metrics,
    _percent,
    _read_env_file as _read_env_file,
    _read_events,
    _read_recent_error,
    _service_running,
    _tail,
    find_eval_workspace,
)

console = Console()

_LOG_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ \[(\w+)\] ([\w.]+): (.*)$")
_TRAIL_RE = re.compile(r"^\[([a-f0-9]+) \+\s*([\d.]+)s\]\s+(\S+)\s+(.*)$")
_STAGES: Tuple[Tuple[str, str], ...] = (
    ("intake", "Intake"),
    ("source", "Source extraction"),
    ("research", "Research"),
    ("hypothesis", "Hypothesis"),
    ("techniques", "Technique mapping"),
    ("scope", "Platform and claims"),
    ("write", "Draft write"),
    ("sigma", "Rule generation"),
    ("review", "Review and finish"),
)


def _bytes(value: Optional[int]) -> str:
    if value is None:
        return "n/a"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return "n/a"


def _bar(value: Optional[float], width: int = 22) -> Text:
    if value is None:
        return Text("[ telemetry unavailable ]", style="dim")
    value = max(0.0, min(100.0, value))
    full = round(width * value / 100)
    color = "bright_magenta" if value >= 85 else "bright_cyan"
    return Text("█" * full + "░" * (width - full) + f" {value:5.1f}%", style=color)


def _resource_panel(title: str, value: Optional[float], detail: str = "") -> Panel:
    body = Group(_bar(value), Text(detail or " ", style="dim"))
    return Panel(body, title=f"[bold bright_cyan]{title}[/]", border_style="bright_magenta", box=box.ROUNDED)


def _host_telemetry_ribbon(host: HostSample) -> Panel:
    cpu_pct = host.cpu_percent
    cpu_str = f"{cpu_pct:.0f}%" if cpu_pct is not None else "n/a"
    cpu_bar_str = _bar(cpu_pct, width=8).plain if cpu_pct is not None else "░░░░░░░░"

    mem_pct = _percent(host.memory_used, host.memory_total)
    mem_str = f"{mem_pct:.0f}%" if mem_pct is not None else "n/a"
    mem_bar_str = _bar(mem_pct, width=8).plain if mem_pct is not None else "░░░░░░░░"
    mem_detail = f"{_bytes(host.memory_used)}/{_bytes(host.memory_total)}"

    gpu_pct = host.gpu_percent
    gpu_str = f"{gpu_pct:.0f}%" if gpu_pct is not None else "0%"
    gpu_name = host.gpu_name if host.gpu_name != "unavailable" else "GPU"
    if host.gpu_memory_used and host.gpu_memory_total:
        gpu_detail = f"{gpu_name} ({gpu_str} · {_bytes(host.gpu_memory_used)}/{_bytes(host.gpu_memory_total)})"
    else:
        gpu_detail = f"{gpu_name} ({gpu_str})"

    disk_str = _disk_summary(host, compact=True)

    table = Table(box=None, expand=True, show_header=False, padding=(0, 1))
    table.add_column("CPU", ratio=1)
    table.add_column("RAM", ratio=1)
    table.add_column("GPU", ratio=1)
    table.add_column("STORAGE", ratio=1)

    c_cpu = Text.assemble(("CPU ", "bold bright_cyan"), (f"{cpu_str} ", "bright_white"), (f"[{cpu_bar_str}]", "dim bright_cyan"), (" host", "dim"))
    c_mem = Text.assemble(("RAM ", "bold bright_cyan"), (f"{mem_str} ", "bright_white"), (f"[{mem_bar_str}] ", "dim bright_cyan"), (f"{mem_detail}", "dim"))
    c_gpu = Text.assemble(("GPU ", "bold bright_cyan"), (gpu_detail, "bright_white"))
    c_disk = Text.assemble(("DRIVES ", "bold bright_cyan"), (disk_str, "bright_white"))

    table.add_row(c_cpu, c_mem, c_gpu, c_disk)
    return Panel(
        table,
        title="[bold bright_cyan]HOST TELEMETRY[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
        padding=(0, 0),
    )


#: With no service to ask, a cycle whose log has been quiet this long is taken as stopped.
#: One model call can run for many minutes without logging, so this cannot be short.
_QUIET_SECONDS = 30 * 60
#: Stages that log a line when they begin; every other stage logs only when it is finished.
_SELF_STARTING = frozenset({"research", "hypothesis", "sigma"})


def _parse_time(timestamp: str) -> Optional[datetime]:
    try:
        return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _pipeline_state(
    events: List[TrailEvent], service_running: Optional[bool] = None, now: Optional[datetime] = None
) -> Tuple[Optional[TrailEvent], bool, Optional[float]]:
    """(latest event, whether its cycle is running, seconds the cycle has taken).

    ``service_running`` is the Runner service's own state when it works on the
    monitored workspace: a crashed cycle then reads as stopped at once, not
    after the log has been quiet for half an hour. ``None`` (no service, or a
    different workspace such as a replay's) falls back to log freshness.
    """
    if not events:
        return None, False, None
    now = now or datetime.now()
    if now.tzinfo is not None:
        now = now.replace(tzinfo=None)
    latest = events[-1]
    current_events = [event for event in events if event.cycle_id == latest.cycle_id]
    last_update = _parse_time(latest.timestamp)
    fresh = last_update is not None and (now - last_update).total_seconds() < _QUIET_SECONDS
    active = latest.stage != "done" and (fresh if service_running is None else service_running)
    logged = max((event.elapsed for event in current_events), default=latest.elapsed)
    # A stage logs when it ends, so the log's own clock stops at the last line:
    # ten minutes into source extraction it still read "elapsed 4s".
    started = _parse_time(current_events[0].timestamp)
    if active and started is not None:
        elapsed = max(logged, (now - started).total_seconds() + current_events[0].elapsed)
    else:
        elapsed = logged
    return latest, active, elapsed


def _stage_in_progress(events: List[TrailEvent]) -> int:
    """Index in ``_STAGES`` of the stage the latest cycle is working on, or -1 with no events.

    Most stages log one line, when they finish, so the stage named on the
    latest line is the one just completed and the work in hand is the next.
    Research, the hypothesis and rule generation also log when they begin and
    are in progress until their "done" line; source extraction logs "starting"
    and is in progress until its next line.
    """
    if not events:
        return -1
    cycle = [event for event in events if event.cycle_id == events[-1].cycle_id]
    drafting_started = any(event.stage.startswith("sigma") or event.stage == "write" for event in cycle)
    furthest = -1
    for event in cycle:
        if event.stage == "done":
            return len(_STAGES) - 1
        # Grounding is logged twice: before the draft is written and after the rules.
        order = _stage_order("scope" if event.stage == "grounding" and not drafting_started else event.stage)
        if order < 0:
            continue
        key = _STAGES[order][0]
        if event.stage == "source":
            # Source extraction logs "starting" and then one line when it is finished.
            finished = not event.message.startswith("starting")
        else:
            finished = key not in _SELF_STARTING or re.search(r"\bdone\b", event.message) is not None
        furthest = max(furthest, min(order + 1, len(_STAGES) - 1) if finished else order)
    return furthest


def _stage_table(
    current: Optional[TrailEvent],
    active: bool,
    stale: bool,
    in_progress: Optional[int] = None,
    step_elapsed: Optional[float] = None,
) -> Table:
    table = Table(box=None, expand=True, padding=(0, 1))
    table.add_column("STATE", width=14)
    table.add_column("PIPELINE STAGE", ratio=1)
    current_order = in_progress if in_progress is not None else (_stage_order(current.stage) if current else -1)
    for index, (key, label) in enumerate(_STAGES):
        if current and current.stage == "done":
            ev_time = _parse_time(current.timestamp) if current.timestamp else None
            is_fresh = ev_time and (datetime.now() - ev_time).total_seconds() < _QUIET_SECONDS
            if is_fresh:
                state, style = "DONE", "bright_green"
            else:
                state, style = "WAIT", "dim"
        elif index < current_order:
            state, style = "DONE", "bright_green"
        elif index == current_order:
            if stale:
                state, style = "STALE", "bold bright_red"
            else:
                if active:
                    dur_str = f" ({_duration(step_elapsed)})" if step_elapsed is not None and step_elapsed >= 0 else ""
                    state, style = f"ACTIVE{dur_str}", "bold bright_magenta"
                else:
                    state, style = "DONE", "bright_green"
        else:
            state, style = "WAIT", "dim"
        table.add_row(Text(state, style=style), Text(label, style=style if state != "WAIT" else "white"))
    return table


def _stage_order(stage: str) -> int:
    aliases = {
        "start": "intake",
        "route": "intake",
        "guidance": "source",
        "triage": "intake",
        "quota": "intake",
        "claims": "scope",
        "grounding": "review",
    }
    normalized = aliases.get(stage, stage)
    if normalized.startswith("technique"):
        normalized = "techniques"
    if normalized.startswith("hypothesis"):
        normalized = "hypothesis"
    if normalized.startswith("sigma"):
        normalized = "sigma"
    return next((index for index, (key, _) in enumerate(_STAGES) if key == normalized), -1)


_STAGE_COLORS = {
    "intake": "dim white",
    "source": "cyan",
    "research": "yellow",
    "hypothesis": "magenta",
    "techniques": "blue",
    "scope": "bright_white",
    "write": "bright_cyan",
    "sigma": "bright_yellow",
    "review": "bright_green",
}


def _get_stage_color(stage: str) -> str:
    return _STAGE_COLORS.get(stage.lower(), "white")


#: An event's message may wrap onto this many lines before it is cut.
_LINES_PER_EVENT = 1


def _recent_events(events: List[TrailEvent], rows: int, width: int) -> List[Tuple[TrailEvent, str]]:
    """The newest events that fit in ``rows`` lines of ``width`` characters, oldest first.

    A panel clips what overflows it from the bottom, which is where the newest
    lines are: eight long events in a short panel hid the cycle's "done" line.
    So the events are chosen to fit, newest first, and long messages are cut.
    """
    width = max(20, width)
    chosen: List[Tuple[TrailEvent, str]] = []
    used = 0
    for event in reversed(events):
        # Wrapped here, not by the table: its own wrapping can take a third line.
        lines = textwrap.wrap(event.message, width=width, max_lines=_LINES_PER_EVENT, placeholder="…") or [""]
        if chosen and used + len(lines) > rows:
            break
        chosen.append((event, "\n".join(lines)))
        used += len(lines)
    return chosen[::-1]


def _activity_table(events: List[TrailEvent], rows: int = 8, width: int = 100, errors_only: bool = False) -> Table:
    table = Table(box=None, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("TIME", width=10, style="dim")
    table.add_column("STAGE", width=10)
    table.add_column("ACTIVITY", ratio=1, overflow="ellipsis", no_wrap=True)

    if errors_only:
        filtered = [
            e
            for e in events
            if e.stage in ("error", "fail", "warn", "warning")
            or "error" in e.message.lower()
            or "exception" in e.message.lower()
            or "fail" in e.message.lower()
            or "warn" in e.message.lower()
            or "parked" in e.message.lower()
        ]
        if not filtered:
            table.add_row("--:--:--", "[bold green]CLEAN[/]", "[green]No error events detected in current log stream[/]")
            return table
        events = filtered

    for event, message in _recent_events(events, rows, width):
        color = _get_stage_color(event.stage)
        table.add_row(event.timestamp[-8:], f"[{color}]{event.stage[:10]}[/]", message)
    if not events:
        table.add_row("--:--:--", "[dim white]idle[/]", "Waiting for Runner events in logs/orchestrator.log")
    return table


def _calculate_llm_metrics(llm_stages: List[Dict[str, Any]]) -> Tuple[int, int, int, List[str], str]:
    calls = sum(int(stage.get("llm_calls") or 0) for stage in llm_stages)
    input_tokens = sum(int(stage.get("input_tokens") or 0) for stage in llm_stages)
    output_tokens = sum(int(stage.get("output_tokens") or 0) for stage in llm_stages)
    models = sorted({model for stage in llm_stages for model in (stage.get("models") or [])})
    duration_ms = sum(int(stage.get("duration_ms") or 0) for stage in llm_stages)
    if duration_ms > 0:
        tps = (input_tokens + output_tokens) / (duration_ms / 1000)
        speed_text = f"{tps:.1f} tok/s ({duration_ms / 1000:.1f}s)"
    else:
        speed_text = "unknown"
    return calls, input_tokens, output_tokens, models, speed_text


def _build_summary_table(
    compact: bool,
    calls: int,
    input_tokens: int,
    output_tokens: int,
    speed_text: str,
    search_count: str,
    models: List[str],
    workspace: Optional[Path],
    usage_note: str,
    has_stages: bool,
    stage_line: str = "",
    narrow: bool = False,
) -> Table:
    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=10, min_width=10, no_wrap=True)
    table.add_column("value", style="bright_white", ratio=1, overflow="ellipsis", no_wrap=True)
    if narrow:
        _narrow_usage_rows(
            table,
            f"{calls} calls" if has_stages else "no usage recorded",
            f"{input_tokens:,} in / {output_tokens:,} out" if has_stages else "—",
            speed_text,
            ", ".join(models) or "not reported",
            search_count,
            stage_line,
            usage_note,
            workspace,
        )
    elif compact:
        llm_summary = f"{calls} calls · {input_tokens:,} in / {output_tokens:,} out" if has_stages else "no completed metrics"
        table.add_row("LLM", llm_summary)
        table.add_row("Speed", speed_text)
        table.add_row("Latency", usage_note)
        table.add_row("Model", ", ".join(models) or "not reported")
    else:
        llm_summary = f"{calls} calls · {input_tokens:,} in / {output_tokens:,} out" if has_stages else "no usage recorded"
        _usage_rows(
            table,
            f"{llm_summary} · speed {speed_text}",
            ", ".join(models) or "not reported",
            stage_line,
            usage_note,
        )
    return table


def _narrow_usage_rows(
    table: Table,
    llm: str,
    tokens: str,
    speed: str,
    model: str,
    searches: str,
    by_stage: str,
    latency: str,
    workspace: Optional[Path] = None,
) -> None:
    """The usage rows for a column a third of the screen wide: one fact a row."""
    table.add_row("LLM", llm)
    table.add_row("Tokens", tokens)
    table.add_row("Speed", speed)
    table.add_row("Latency", latency)
    table.add_row("Model", model)
    first, _, second = by_stage.partition("\n")
    table.add_row("By stage", first)
    if second:
        table.add_row("", second)


#: Rows of the LLM panel in a side column, with its border.
_NARROW_USAGE_PANEL_HEIGHT = 9
_NARROW_LLM_PANEL_HEIGHT = 9
_INTEGRATIONS_PANEL_HEIGHT = 14
_HUNTS_PANEL_HEIGHT = 7
_MITRE_PANEL_HEIGHT = 12
_DETAILED_MITRE_PANEL_HEIGHT = 20
_PURPLE_PANEL_HEIGHT = 14
# Reserve enough rows for all integrations, including disabled sources, in the four-column grid.
_BOTTOM_DETAIL_PANELS_HEIGHT = 14


def _usage_rows(table: Table, llm: str, model: str, by_stage: str, latency: str) -> None:
    """The full layout's four usage rows: the panel is this tall and no taller."""
    table.add_row("LLM", llm)
    table.add_row("Model", model)
    table.add_row("By stage", by_stage)
    table.add_row("Latency", latency)


#: Rows of the usage panel in the full layout, with its border.
_USAGE_PANEL_HEIGHT = 6
#: Height of the bottom usage/summary/integrations row in horizontal dashboard layouts.
_BOTTOM_ROW_HEIGHT = 12


def _stage_line(llm_stages: List[Dict[str, Any]], tokens: bool = True) -> str:
    """Each stage's calls, and its tokens where there is room, on one line; the cycle total is the LLM row."""
    parts = []
    for stage in llm_stages:
        if stage.get("stage") == "cycle":
            continue
        part = f"{str(stage.get('stage', 'unknown')).removesuffix('_generation').removesuffix('_evidence')} {stage.get('llm_calls') or 0}"
        if tokens:
            part += f" ({int(stage.get('input_tokens') or 0):,}/{int(stage.get('output_tokens') or 0):,})"
        parts.append(part)
    if not parts:
        return "none recorded"
    if tokens:
        return " · ".join(parts) + "  (calls, tokens in/out)"
    half = (len(parts) + 1) // 2  # two rows in a narrow column
    return " · ".join(parts[:half]) + "\n" + (" · ".join(parts[half:]) + " calls").strip()


def _usage_panel(
    metrics: Dict[str, Any],
    current: Optional[TrailEvent],
    active: bool,
    events: List[TrailEvent],
    compact: bool = False,
    workspace: Optional[Path] = None,
    live: Optional[Dict[str, Any]] = None,
    now: Optional[datetime] = None,
    narrow: bool = False,
) -> Panel:
    if (active or (live and live.get("in_flight", 0) > 0)) and current and live:
        # The running cycle's own calls, not the totals of the last one to finish.
        return _live_usage_panel(live, current, events, compact, workspace, now or datetime.now(), narrow)

    stages = metrics.get("stages") or []
    llm_stages = [stage for stage in stages if isinstance(stage, dict) and stage.get("llm_calls") is not None]
    calls, input_tokens, output_tokens, models, cost_text = _calculate_llm_metrics(llm_stages)
    search_count = _search_count(current, events)

    duration_ms = sum(int(stage.get("duration_ms") or 0) for stage in llm_stages)
    if active and current and current.stage in {"source", "research", "hypothesis", "sigma"}:
        usage_note = "Live token totals are written when the cycle ends."
    elif not metrics:
        usage_note = "No completed cycle metrics found yet."
    elif duration_ms > 0 and calls > 0:
        avg_latency = duration_ms / calls / 1000
        usage_note = f"{avg_latency:.1f}s per call"
    else:
        usage_note = "unknown"

    table = _build_summary_table(
        compact,
        calls,
        input_tokens,
        output_tokens,
        cost_text,
        search_count,
        models,
        workspace,
        usage_note,
        bool(llm_stages),
        _stage_line(llm_stages, tokens=not narrow),
        narrow,
    )
    return Panel(table, title="[bold bright_cyan]LLM[/]", border_style="bright_magenta", box=box.ROUNDED)


def _search_count(current: Optional[TrailEvent], events: List[TrailEvent]) -> str:
    if current:
        for event in reversed(events):
            if event.cycle_id != current.cycle_id or event.stage != "research":
                continue
            searches = re.search(r"(\d+)\s+web\s+search(?:es|\(es\))?", event.message)
            if searches:
                return searches.group(1)
            break
        if current.stage == "research":
            return "in progress..."
    return "pending"


_LIVE_USAGE_CACHE: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}


def _live_usage(call_log: Path) -> Dict[str, Any]:
    """The running cycle's provider calls so far; empty when the Runner keeps no call log."""
    try:
        stat = call_log.stat()
        mtime_ns = stat.st_mtime_ns
        size = stat.st_size
        key = str(call_log.resolve())
        cached = _LIVE_USAGE_CACHE.get(key)
        if cached is not None and cached[0] == mtime_ns and cached[1] == size:
            return cached[2]
    except OSError:
        return summarize_calls([])

    res = summarize_calls(_tail(call_log, limit=2000))
    _LIVE_USAGE_CACHE[key] = (mtime_ns, size, res)
    return res


def _live_usage_panel(
    live: Dict[str, Any],
    current: TrailEvent,
    events: List[TrailEvent],
    compact: bool,
    workspace: Optional[Path],
    now: datetime,
    narrow: bool = False,
) -> Panel:
    calls, in_flight, failed = live["llm_calls"], live["in_flight"], live["failed"]
    call_text = f"{calls} done"
    if in_flight:
        waited = _duration(max(0.0, now.timestamp() - live["last_start"]))
        call_text += (
            f" · {in_flight} in flight ({waited})" if narrow else f" · {in_flight} in flight (latest sent {waited} ago)"
        )
    if failed:
        call_text += f" · {failed} failed"
    duration_ms = live.get("duration_ms", 0)
    if duration_ms > 0 and live["llm_calls"] > 0:
        tps = (live["input_tokens"] + live["output_tokens"]) / (duration_ms / 1000)
        avg_latency = duration_ms / live["llm_calls"] / 1000
        speed_text = f"{tps:.1f} tok/s · {avg_latency:.1f}s/call"
        last_end = live.get("last_end")
        last_end_str = f" (last reply at {datetime.fromtimestamp(last_end):%H:%M:%S})" if last_end else ""
        latency_text = f"avg {avg_latency:.1f}s{last_end_str}"
    elif duration_ms > 0:
        tps = (live["input_tokens"] + live["output_tokens"]) / (duration_ms / 1000)
        speed_text = f"{tps:.1f} tok/s"
        latency_text = "in progress"
    else:
        speed_text = "unknown"
        latency_text = "no replies yet"

    models = ", ".join(live["models"]) or "not reported yet"
    search_count = _search_count(current, events)

    ended_calls = live.get("ended_calls", [])
    stage_counts = {}  # type: ignore
    cycle_events = [e for e in events if e.cycle_id == current.cycle_id]
    _STAGE_NORM = {
        "guidance": "source",
        "intake": "source",
        "route": "source",
        "source_evidence": "source",
        "research_new": "research",
        "hypothesis_generator": "hypothesis",
        "hypothesis_generation": "hypothesis",
        "sigma_generator": "sigma",
        "sigma_generation": "sigma",
    }
    for call in ended_calls:
        call_ts = call.get("ts", 0.0)
        active_stage = "unknown"
        for event in cycle_events:
            ev_time = _parse_time(event.timestamp)
            if ev_time and ev_time.timestamp() <= call_ts:
                active_stage = event.stage
            elif ev_time and ev_time.timestamp() > call_ts:
                break
        clean_stage = _STAGE_NORM.get(active_stage, active_stage.removesuffix("_generation").removesuffix("_evidence"))
        stage_counts[clean_stage] = stage_counts.get(clean_stage, 0) + 1

    if stage_counts:
        live_stage_line = " · ".join(f"{stage} {count}" for stage, count in stage_counts.items() if stage != "cycle")
    else:
        live_stage_line = "no usage recorded yet"

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=10, min_width=10, no_wrap=True)
    table.add_column("value", style="bright_white", ratio=1, overflow="ellipsis", no_wrap=True)
    if narrow:
        _narrow_usage_rows(
            table,
            call_text,
            f"{live['input_tokens']:,} in / {live['output_tokens']:,} out",
            speed_text,
            models,
            search_count,
            live_stage_line,
            latency_text,
            workspace,
        )
    elif compact:
        table.add_row("LLM", f"{call_text} · {live['input_tokens']:,} in / {live['output_tokens']:,} out")
        table.add_row("Speed", speed_text)
        table.add_row("Latency", latency_text)
        table.add_row("Model", models)
    else:
        _usage_rows(
            table,
            f"{call_text} · {live['input_tokens']:,} in / {live['output_tokens']:,} out · speed {speed_text}",
            models,
            live_stage_line,
            latency_text,
        )
    return Panel(table, title="[bold bright_cyan]LLM[/]", border_style="bright_magenta", box=box.ROUNDED)



def _hunts_panel(
    workspace: Optional[Path] = None,
    narrow: bool = True,
    compact: bool = False,
    metrics: Optional[HuntsMetrics] = None,
) -> Panel:
    """A combined panel displaying summary metrics for hunts, threat observables, and factual grounding fidelity."""
    h_metrics = metrics or _collect_hunts_metrics(workspace)

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=10, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    if (
        h_metrics.total_hunts == 0
        and h_metrics.network_total == 0
        and h_metrics.host_total == 0
        and h_metrics.threats_count == 0
    ):
        table.add_row("HUNTS", Text("0 generated · standby", style="dim"))
        table.add_row("THREATS", Text("0 tracked", style="dim"))
        table.add_row("NETWORK", Text("0 IOCs · standby", style="dim"))
        table.add_row("ENDPOINT", Text("0 IOCs · standby", style="dim"))
        if not compact:
            table.add_row("FIDELITY", Text("100% target · 0 unsupp", style="dim"))
    else:
        if h_metrics.total_hunts > 0:
            hunts_text = f"{h_metrics.total_hunts} total"
            hunts_sub = (
                f"{h_metrics.drafts_count} drafts"
                if not h_metrics.completed_count
                else f"{h_metrics.drafts_count} drf · {h_metrics.completed_count} done"
            )
            hunts_parts = [(hunts_text, "bright_white"), (" · ", "dim"), (hunts_sub, "bright_cyan")]
            table.add_row("HUNTS", Text.assemble(*hunts_parts))
        else:
            table.add_row("HUNTS", Text("0 generated · standby", style="dim"))

        threats_val = f"{h_metrics.threats_count} threats" if not narrow else f"{h_metrics.threats_count}"
        threats_sub = f"{h_metrics.actors_count} act, {h_metrics.campaigns_count} camp, {h_metrics.malware_count} mal"
        table.add_row(
            "THREATS",
            Text.assemble((threats_val, "bright_white"), (" · ", "dim"), (threats_sub, "bright_cyan")),
        )

        net_str = f"{h_metrics.network_total:,} IOCs"
        net_sub = f"{h_metrics.network_ips} IP, {h_metrics.network_domains} dom"
        if h_metrics.network_urls and not narrow:
            net_sub += f", {h_metrics.network_urls} url"
        table.add_row(
            "NETWORK",
            Text.assemble((net_str, "bright_white"), (" · ", "dim"), (net_sub, "bright_cyan")),
        )

        host_str = f"{h_metrics.host_total:,} IOCs"
        host_sub = f"{h_metrics.host_hashes} hash, {h_metrics.host_paths} path"
        table.add_row(
            "ENDPOINT",
            Text.assemble((host_str, "bright_white"), (" · ", "dim"), (host_sub, "bright_cyan")),
        )

        if not compact and (h_metrics.fingerprints_count > 0 or h_metrics.cloud_ops_count > 0):
            infra_str = f"{h_metrics.fingerprints_count} JA4/JARM" if h_metrics.fingerprints_count else "JA4 standby"
            cloud_sub = f"{h_metrics.cloud_ops_count} cloud/k8s" if h_metrics.cloud_ops_count else "cloud ready"
            table.add_row(
                "INFRA/CLOUD",
                Text.assemble((infra_str, "bright_white"), (" · ", "dim"), (cloud_sub, "bright_cyan")),
            )

        if not compact:
            unsupp_style = "bold bright_red" if h_metrics.grounding_unsupported > 0 else "dim"
            table.add_row(
                "FIDELITY",
                Text.assemble(
                    (f"{h_metrics.grounding_asserted} asrt", "bright_green"),
                    (" · ", "dim"),
                    (f"{h_metrics.grounding_derived} drv", "bright_cyan"),
                    (" · ", "dim"),
                    (f"{h_metrics.grounding_unsupported} unsupp", unsupp_style),
                ),
            )

    return Panel(
        table,
        title="[bold bright_cyan]HUNTS[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _hunts_summary_panel(
    workspace: Optional[Path] = None,
    narrow: bool = True,
    compact: bool = False,
    metrics: Optional[HuntsMetrics] = None,
) -> Panel:
    return _hunts_panel(workspace=workspace, narrow=narrow, compact=compact, metrics=metrics)


def _mitre_metrics_panel(
    workspace: Optional[Path] = None,
    narrow: bool = False,
    compact: bool = False,
    metrics: Optional[HuntsMetrics] = None,
    detailed: bool = False,
) -> Panel:
    """A dedicated panel displaying MITRE ATT&CK Enterprise, Cloud, and Container coverage metrics."""
    h_metrics = metrics or _collect_hunts_metrics(workspace)

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=10, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    ent = h_metrics.enterprise_ttps or {}
    cloud = h_metrics.cloud_ttps or {}
    containers = h_metrics.containers_ttps or {}

    ent_total = h_metrics.enterprise_total or sum(ent.values())
    cloud_total = h_metrics.cloud_total or sum(cloud.values())
    container_total = h_metrics.containers_total or sum(containers.values())

    cloud_tactics = sum(v > 0 for v in cloud.values())
    container_tactics = sum(v > 0 for v in containers.values())

    recon = ent.get("reconnaissance", 0)
    resdev = ent.get("resource-development", 0)
    initacc = ent.get("initial-access", 0)
    exec_cnt = ent.get("execution", 0)
    persist = ent.get("persistence", 0)
    privesc = ent.get("privilege-escalation", 0)
    stealth = ent.get("stealth", 0)
    defimp = ent.get("defense-impairment", 0)
    credacc = ent.get("credential-access", 0)
    disc = ent.get("discovery", 0)
    latmove = ent.get("lateral-movement", 0)
    collect = ent.get("collection", 0)
    c2 = ent.get("command-and-control", 0)
    exfil = ent.get("exfiltration", 0)
    impact = ent.get("impact", 0)

    active_tactics = sum(1 for v in ent.values() if v > 0)
    subtitle = None

    if detailed:
        table = Table(box=None, show_header=False, expand=True, padding=(0, 0))
        table.add_column("tactic", ratio=1, min_width=19, no_wrap=True, overflow="ellipsis")
        for name in ("TTPs", "IOCs", "Hunts", "Rules"):
            table.add_column(name, width=5, justify="right", no_wrap=True)
        table.add_row(
            Text(f"ENTERPRISE ({active_tactics} / 15 tactics) ({ent_total} Unique TTPs)", style="bold bright_cyan"),
            *(Text(label, style="bold bright_cyan") for label in ("TTPs", "IOCs", "Hunts", "Rules")),
        )
        subtitle = None
        for tactic, label in (
            ("reconnaissance", "Reconnaissance"),
            ("resource-development", "Resource Development"),
            ("initial-access", "Initial Access"),
            ("execution", "Execution"),
            ("persistence", "Persistence"),
            ("privilege-escalation", "Privilege Escalation"),
            ("stealth", "Stealth"),
            ("defense-impairment", "Defense Impairment"),
            ("credential-access", "Credential Access"),
            ("discovery", "Discovery"),
            ("lateral-movement", "Lateral Movement"),
            ("collection", "Collection"),
            ("command-and-control", "Command and Control"),
            ("exfiltration", "Exfiltration"),
            ("impact", "Impact"),
        ):
            count = ent.get(tactic, 0)
            iocs = h_metrics.tactic_iocs.get("enterprise", {}).get(tactic, 0)
            hunts = h_metrics.tactic_hunts.get("enterprise", {}).get(tactic, 0)
            rules = h_metrics.tactic_rules.get("enterprise", {}).get(tactic, 0)
            table.add_row(
                Text(label, style="dim"),
                Text(str(count), style="bright_white" if count else "dim"),
                Text(str(iocs), style="bright_cyan" if iocs else "dim"),
                Text(str(hunts), style="bright_cyan" if hunts else "dim"),
                Text(str(rules), style="bright_green" if rules else "dim"),
            )
        table.add_row(
            Text(f"CLOUD ({cloud_tactics} / 12 tactics) ({cloud_total} Unique TTPs)", style="bright_cyan"),
            Text(str(cloud_total), style="bright_cyan"),
            Text(str(h_metrics.matrix_iocs.get("cloud", 0)), style="bright_cyan"),
            Text(str(h_metrics.matrix_hunts.get("cloud", 0)), style="bright_cyan"),
            Text(str(h_metrics.matrix_rules.get("cloud", 0)), style="bright_cyan"),
        )
        table.add_row(
            Text(f"CONTAINERS ({container_tactics} / 10 tactics) ({container_total} Unique TTPs)", style="bright_cyan"),
            Text(str(container_total), style="bright_cyan"),
            Text(str(h_metrics.matrix_iocs.get("containers", 0)), style="bright_cyan"),
            Text(str(h_metrics.matrix_hunts.get("containers", 0)), style="bright_cyan"),
            Text(str(h_metrics.matrix_rules.get("containers", 0)), style="bright_cyan"),
        )
    elif compact:
        if ent_total == 0 and h_metrics.ttps_count == 0:
            table.add_row("ENTERPRISE", Text("(0 / 15 tactics) (0 Unique TTPs)", style="dim"))
            table.add_row(" Ingress", Text("Recon 0 · ResDev 0 · InitAcc 0", style="dim"))
            table.add_row(" Execution", Text("Exec 0 · Persist 0 · PrivEsc 0", style="dim"))
            table.add_row(" Defense", Text("Stealth 0 · DefImp 0 · CredAcc 0", style="dim"))
            table.add_row(" Actions", Text("Disc 0 · C2 0 · Impact 0", style="dim"))
            table.add_row("CLOUD & K8S", Text("(0/12) (0 TTPs) · (0/10) (0 TTPs)", style="dim"))
        else:
            table.add_row(
                "ENTERPRISE",
                Text(f"({active_tactics} / 15 tactics) ({ent_total} Unique TTPs)", style="bright_white"),
            )
            table.add_row(
                " Ingress",
                Text.assemble(
                    ("Recon ", "dim"),
                    (str(recon), "bright_white"),
                    (" · ", "dim"),
                    ("ResDev ", "dim"),
                    (str(resdev), "bright_white"),
                    (" · ", "dim"),
                    ("InitAcc ", "dim"),
                    (str(initacc), "bright_white"),
                ),
            )
            table.add_row(
                " Execution",
                Text.assemble(
                    ("Exec ", "dim"),
                    (str(exec_cnt), "bright_white"),
                    (" · ", "dim"),
                    ("Persist ", "dim"),
                    (str(persist), "bright_white"),
                    (" · ", "dim"),
                    ("PrivEsc ", "dim"),
                    (str(privesc), "bright_white"),
                ),
            )
            table.add_row(
                " Defense",
                Text.assemble(
                    ("Stealth ", "dim"),
                    (str(stealth), "bright_white"),
                    (" · ", "dim"),
                    ("DefImp ", "dim"),
                    (str(defimp), "bright_white"),
                    (" · ", "dim"),
                    ("CredAcc ", "dim"),
                    (str(credacc), "bright_white"),
                ),
            )
            table.add_row(
                " Actions",
                Text.assemble(
                    ("Disc ", "dim"),
                    (str(disc), "bright_white"),
                    (" · ", "dim"),
                    ("C2 ", "dim"),
                    (str(c2), "bright_white"),
                    (" · ", "dim"),
                    ("Impact ", "dim"),
                    (str(impact), "bright_white"),
                ),
            )
            cloud_str = f"Cloud ({cloud_tactics}/12) ({cloud_total} Unique TTPs)"
            k8s_str = f"K8s ({container_tactics}/10) ({container_total} Unique TTPs)"
            table.add_row(
                "CLOUD & K8S",
                Text.assemble(
                    (cloud_str, "bright_cyan" if cloud_total else "dim"),
                    (" · ", "dim"),
                    (k8s_str, "bright_cyan" if container_total else "dim"),
                ),
            )
    else:
        if ent_total == 0 and h_metrics.ttps_count == 0:
            table.add_row("ENTERPRISE", Text("(0 / 15 tactics) (0 Unique TTPs)", style="dim"))
            table.add_row(" Pre-Attack", Text("Recon 0 · ResDev 0", style="dim"))
            table.add_row(" Initial", Text("InitAcc 0 · Exec 0", style="dim"))
            table.add_row(" Persist", Text("Persist 0 · PrivEsc 0", style="dim"))
            table.add_row(" Defense", Text("Stealth 0 · DefImp 0", style="dim"))
            table.add_row(" Discovery", Text("Disc 0 · CredAcc 0", style="dim"))
            table.add_row(" Movement", Text("LatMove 0 · Collect 0", style="dim"))
            table.add_row(" Actions", Text("C2 0 · Exfil 0 · Impact 0", style="dim"))
            table.add_row("CLOUD", Text("(0 / 12 tactics) (0 Unique TTPs)", style="dim"))
            table.add_row("CONTAINERS", Text("(0 / 10 tactics) (0 Unique TTPs)", style="dim"))
        else:
            table.add_row(
                "ENTERPRISE",
                Text(f"({active_tactics} / 15 tactics) ({ent_total} Unique TTPs)", style="bright_white"),
            )
            table.add_row(
                " Pre-Attack",
                Text.assemble(
                    ("Recon ", "dim"),
                    (str(recon), "bright_white"),
                    (" · ", "dim"),
                    ("ResDev ", "dim"),
                    (str(resdev), "bright_white"),
                ),
            )
            table.add_row(
                " Initial",
                Text.assemble(
                    ("InitAcc ", "dim"),
                    (str(initacc), "bright_white"),
                    (" · ", "dim"),
                    ("Exec ", "dim"),
                    (str(exec_cnt), "bright_white"),
                ),
            )
            table.add_row(
                " Persist",
                Text.assemble(
                    ("Persist ", "dim"),
                    (str(persist), "bright_white"),
                    (" · ", "dim"),
                    ("PrivEsc ", "dim"),
                    (str(privesc), "bright_white"),
                ),
            )
            table.add_row(
                " Defense",
                Text.assemble(
                    ("Stealth ", "dim"),
                    (str(stealth), "bright_white"),
                    (" · ", "dim"),
                    ("DefImp ", "dim"),
                    (str(defimp), "bright_white"),
                ),
            )
            table.add_row(
                " Discovery",
                Text.assemble(
                    ("Disc ", "dim"),
                    (str(disc), "bright_white"),
                    (" · ", "dim"),
                    ("CredAcc ", "dim"),
                    (str(credacc), "bright_white"),
                ),
            )
            table.add_row(
                " Movement",
                Text.assemble(
                    ("LatMove ", "dim"),
                    (str(latmove), "bright_white"),
                    (" · ", "dim"),
                    ("Collect ", "dim"),
                    (str(collect), "bright_white"),
                ),
            )
            table.add_row(
                " Actions",
                Text.assemble(
                    ("C2 ", "dim"),
                    (str(c2), "bright_white"),
                    (" · ", "dim"),
                    ("Exfil ", "dim"),
                    (str(exfil), "bright_white"),
                    (" · ", "dim"),
                    ("Impact ", "dim"),
                    (str(impact), "bright_white"),
                ),
            )

            table.add_row(
                "CLOUD",
                Text(
                    f"({cloud_tactics} / 12 tactics) ({cloud_total} Unique TTPs)",
                    style="bright_cyan" if cloud_total else "dim",
                ),
            )

            table.add_row(
                "CONTAINERS",
                Text(
                    f"({container_tactics} / 10 tactics) ({container_total} Unique TTPs)",
                    style="bright_cyan" if container_total else "dim",
                ),
            )

    return Panel(
        table,
        title="[bold bright_cyan]MITRE[/]",
        subtitle=None,
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _detections_panel(
    workspace: Optional[Path] = None,
    metrics: Optional[HuntsMetrics] = None,
    runner: Optional[RunnerStatus] = None,
    events: Optional[List[TrailEvent]] = None,
    purple_metrics: Optional[PurpleTeamMetrics] = None,
    narrow: bool = False,
    compact: bool = False,
) -> Panel:
    """A combined panel displaying Sigma detection rules, SIEM query targets, rule tests, self-tuning, and BAS simulation."""
    h_metrics = metrics or _collect_hunts_metrics(workspace)
    p_metrics = purple_metrics or _collect_purple_team_metrics(workspace, events)
    q_prov = runner.query_provider if runner and runner.query_provider else "mock"
    pending = runner.pending_queries if runner else None

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=10, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    rules_cnt = h_metrics.sigma_rules_count
    rules_str = f"{rules_cnt:,} rules" if rules_cnt else "0 rules drafted"
    val_status = "pySigma compliant" if rules_cnt else "pySigma ready"
    table.add_row(
        "RULES",
        Text.assemble((rules_str, "bright_white"), (" · ", "dim"), (val_status, "bright_cyan")),
    )

    pending_str = f"{pending} pending" if pending else "0 pending"
    pending_style = "bold bright_yellow" if pending else "bright_white"
    table.add_row(
        "SIEM QUERY",
        Text.assemble(
            (f"{q_prov.upper()} backend", "bright_white"),
            (" · ", "dim"),
            (pending_str, pending_style),
        ),
    )

    active_val = p_metrics.validated_rules > 0 or p_metrics.bas_runs > 0
    test_sub = f"{p_metrics.hunts_validated} hunts"
    if p_metrics.validated_rules:
        test_sub += f" · {p_metrics.precision_rate:.0%} prec"
    table.add_row(
        "RULE TESTS",
        Text.assemble(
            (f"{p_metrics.validated_rules} rules tested", "bright_white" if active_val else "dim"),
            (" · ", "dim"),
            (test_sub, "bright_cyan" if active_val else "dim"),
        ),
    )

    table.add_row(
        "SELF-TUNING",
        Text.assemble(
            (f"{p_metrics.tuned_rules} tuned", "bright_cyan" if active_val else "dim"),
            (" · ", "dim"),
            (f"{p_metrics.false_positive_count} FP", "bright_white" if active_val else "dim"),
        ),
    )

    bas_runs = p_metrics.bas_runs
    bas_sub = f"{p_metrics.bas_verified} verified · {p_metrics.bas_detection_misses} missed"
    table.add_row(
        "BREACH SIM",
        Text.assemble(
            (f"{bas_runs} runs", "bright_white" if bas_runs else "dim"),
            (" · ", "dim"),
            (bas_sub if bas_runs else "standby", "bright_cyan" if bas_runs else "dim"),
        ),
    )

    if not compact and (p_metrics.bas_telemetry_missing or p_metrics.bas_failures):
        gap_style = "bright_red"
        table.add_row(
            "BAS GAPS",
            Text(f"{p_metrics.bas_telemetry_missing} sensor gaps · {p_metrics.bas_failures} failed", style=gap_style),
        )

    return Panel(
        table,
        title="[bold bright_cyan]DETECTIONS[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _purple_team_panel(
    workspace: Optional[Path] = None,
    events: Optional[List[TrailEvent]] = None,
    narrow: bool = True,
    compact: bool = False,
    metrics: Optional[PurpleTeamMetrics] = None,
) -> Panel:
    """Show rule replay and breach-and-attack simulation in one validation panel."""
    measured = metrics or _collect_purple_team_metrics(workspace, events)
    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=11, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)
    active = measured.validated_rules > 0 or measured.bas_runs > 0
    table.add_row("STATUS", Text("ACTIVE" if active else "STANDBY", style="bold bright_green" if active else "dim"))
    rules = f"{measured.validated_rules} rules" if compact else f"{measured.validated_rules} rules tested"
    table.add_row("RULE TESTS", Text(f"{rules} · {measured.hunts_validated} hunts", style="bright_white" if active else "dim"))
    tuned = f"{measured.tuned_rules} tuned" if compact else f"{measured.tuned_rules} logic re-tuned"
    table.add_row("SELF-TUNING", Text(f"{tuned} · {measured.false_positive_count} FP", style="bright_cyan" if active else "dim"))
    if not compact:
        precision = f"{measured.precision_rate:.0%} precision" if measured.validated_rules else "awaiting rule results"
        table.add_row("PRECISION", Text(precision, style="bright_green" if measured.validated_rules else "dim"))
    if measured.bas_mode_label:
        table.add_row("BAS MODE", Text(measured.bas_mode_label, style="bright_cyan"))
    if measured.bas_scope_label:
        table.add_row("BAS SCOPE", Text(measured.bas_scope_label, style="dim"))
        table.add_row("BAS CHECKS", Text(f"{measured.bas_runs - measured.bas_control_runs} hunt checks · {measured.bas_control_runs} sensor controls", style="dim"))
    table.add_row(
        "BREACH SIM",
        Text(f"{measured.bas_runs} runs · {measured.bas_live_runs} live, {measured.bas_mock_runs} mock", style="bright_white" if measured.bas_runs else "dim"),
    )
    table.add_row(
        "ATTACKS",
        Text(f"{measured.bas_techniques} techniques · {measured.bas_detections} " + ("rule matches" if measured.bas_scope_label else "detections"), style="bright_cyan" if measured.bas_runs else "dim"),
    )
    table.add_row(
        "BAS RESULTS",
        Text(f"{measured.bas_verified} verified · {measured.bas_detection_misses} missed", style="bright_white" if measured.bas_runs else "dim"),
    )
    if not compact:
        gap_style = "bright_red" if measured.bas_telemetry_missing or measured.bas_failures else "dim"
        table.add_row("BAS GAPS", Text(f"{measured.bas_telemetry_missing} sensor gaps · {measured.bas_failures} failed", style=gap_style))
        table.add_row(
            "BAS SENSORS",
            Text(f"{measured.bas_telemetry_runs}/{measured.bas_runs} observed · {measured.bas_matched_events} events", style="bright_white" if measured.bas_runs else "dim"),
        )
        if measured.bas_skipped:
            table.add_row("BAS SKIPPED", Text(f"{measured.bas_skipped} · {measured.bas_last_skip_reason}", style="dim"))
    if not compact and not narrow:
        table.add_row("REPLAY DATA", Text(f"{measured.total_telemetry_events:,} telemetry events", style="dim"))
        if measured.last_duration_sec:
            table.add_row("LAST REPLAY", Text(f"{measured.last_validated_count} in {measured.last_duration_sec:.1f}s", style="bright_cyan"))
        providers = " · ".join(f"{name.upper()} {count}" for name, count in sorted(measured.bas_providers.items()))
        table.add_row("BAS ENGINES", Text(providers or "no simulations yet", style="dim"))
        if measured.bas_last_status:
            last = measured.bas_last_status.replace("_", " ")
            if measured.bas_last_duration_sec:
                last += f" · {measured.bas_last_duration_sec:.1f}s"
            table.add_row("LAST BAS", Text(last, style="bright_cyan"))
    return Panel(table, title="[bold bright_cyan]VALIDATION[/]", border_style="magenta", box=box.ROUNDED)


def _detection_rules_panel(
    workspace: Optional[Path] = None,
    metrics: Optional[HuntsMetrics] = None,
    runner: Optional[RunnerStatus] = None,
    narrow: bool = False,
) -> Panel:
    return _detections_panel(workspace=workspace, metrics=metrics, runner=runner, narrow=narrow)


def _threat_observables_panel(
    workspace: Optional[Path] = None,
    metrics: Optional[HuntsMetrics] = None,
    narrow: bool = False,
) -> Panel:
    return _hunts_panel(workspace=workspace, metrics=metrics, narrow=narrow)


def _collect_outbound_metrics(workspace: Optional[Path] = None, runner: Optional[RunnerStatus] = None) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        "github_published": 0,
        "github_pending": 0,
        "github_failed": 0,
        "github_latest_hunt": None,
        "github_latest_pr": None,
        "misp_confirmed": 0,
        "misp_pending": 0,
        "misp_failed": 0,
        "misp_latest_hunt": None,
        "misp_target": None,
    }
    if runner:
        res["github_published"] = runner.github_confirmed_promotions or 0
        res["github_pending"] = runner.github_pending_prs or 0
        res["misp_confirmed"] = runner.misp_confirmed_exports or 0
        res["misp_pending"] = runner.misp_pending_exports or 0

    if workspace:
        db_path = workspace / ".hecate" / "publisher" / "promotion-outbox.sqlite3"
        if not db_path.exists():
            db_path = workspace / ".hecate" / "github" / "outbox.sqlite3"
        if db_path.exists():
            try:
                conn = sqlite3.connect(db_path, timeout=1.0)
                conn.row_factory = sqlite3.Row
                try:
                    rows = conn.execute("SELECT status, hunt_id, pr_number FROM promotions").fetchall()
                    pub = sum(1 for r in rows if str(r["status"]).lower() in ("published", "merged"))
                    pend = sum(1 for r in rows if str(r["status"]).lower() in ("queued", "publishing", "pending"))
                    fail = sum(1 for r in rows if str(r["status"]).lower() in ("retry", "failed"))
                    res["github_published"] = max(res["github_published"], pub)
                    res["github_pending"] = max(res["github_pending"], pend)
                    res["github_failed"] = fail
                    if rows:
                        res["github_latest_hunt"] = rows[-1]["hunt_id"]
                        if rows[-1]["pr_number"]:
                            res["github_latest_pr"] = f"PR #{rows[-1]['pr_number']}"
                finally:
                    conn.close()
            except Exception:
                pass

        misp_db = workspace / ".hecate" / "misp" / "outbox.sqlite3"
        if misp_db.exists():
            try:
                conn = sqlite3.connect(misp_db, timeout=1.0)
                conn.row_factory = sqlite3.Row
                try:
                    rows = conn.execute("SELECT status, hunt_id, event_id, target FROM exports").fetchall()
                    conf = sum(1 for r in rows if str(r["status"]).lower() == "confirmed")
                    pend = sum(1 for r in rows if str(r["status"]).lower() in ("queued", "publishing", "pending"))
                    fail = sum(1 for r in rows if str(r["status"]).lower() in ("retry", "failed"))
                    res["misp_confirmed"] = max(res["misp_confirmed"], conf)
                    res["misp_pending"] = max(res["misp_pending"], pend)
                    res["misp_failed"] = fail
                    if rows:
                        res["misp_latest_hunt"] = rows[-1]["hunt_id"]
                        res["misp_target"] = rows[-1]["target"]
                finally:
                    conn.close()
            except Exception:
                pass

    return res


def _outbound_panel(
    workspace: Optional[Path] = None,
    runner: Optional[RunnerStatus] = None,
    narrow: bool = False,
    compact: bool = False,
) -> Panel:
    """A dedicated panel displaying summary metrics for outbound publication across GitHub and MISP."""
    ob = _collect_outbound_metrics(workspace, runner)

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=10, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    gh_pub = ob["github_published"]
    gh_pend = ob["github_pending"]
    gh_style = "bright_green" if gh_pub > 0 else "dim"
    gh_parts = [(f"{gh_pub} published", gh_style)]
    if gh_pend > 0:
        gh_parts.extend([(" · ", "dim"), (f"{gh_pend} PR pending", "bold bright_yellow")])
    elif ob["github_latest_hunt"]:
        gh_parts.extend([(" · ", "dim"), (f"last: {ob['github_latest_hunt']}", "bright_cyan")])
    else:
        gh_parts.extend([(" · ", "dim"), ("0 pending", "dim")])
    table.add_row("GITHUB", Text.assemble(*gh_parts))

    misp_conf = ob["misp_confirmed"]
    misp_pend = ob["misp_pending"]
    misp_style = "bright_green" if misp_conf > 0 else "dim"
    misp_parts = [(f"{misp_conf} confirmed", misp_style)]
    if misp_pend > 0:
        misp_parts.extend([(" · ", "dim"), (f"{misp_pend} pending", "bold bright_yellow")])
    elif ob["misp_latest_hunt"]:
        misp_parts.extend([(" · ", "dim"), (f"last: {ob['misp_latest_hunt']}", "bright_cyan")])
    else:
        misp_parts.extend([(" · ", "dim"), ("0 pending", "dim")])
    table.add_row("MISP", Text.assemble(*misp_parts))

    total_pend = gh_pend + misp_pend
    if total_pend > 0:
        sync_txt = f"{total_pend} outbound queued"
        sync_style = "bold bright_yellow"
    elif gh_pub > 0 or misp_conf > 0:
        sync_txt = "all destinations synced"
        sync_style = "bold bright_green"
    else:
        sync_txt = "standby · ready"
        sync_style = "dim"
    table.add_row("STATUS", Text(sync_txt, style=sync_style))

    if not compact:
        table.add_row(
            "CHANNELS",
            Text.assemble(
                ("GitHub Public", "bright_white"),
                (" · ", "dim"),
                ("MISP Events", "bright_cyan"),
                (" · ", "dim"),
                ("Signed CTI", "dim"),
            ),
        )

    return Panel(
        table,
        title="[bold bright_cyan]OUTBOUND[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _compact_progress(current: Optional[TrailEvent], active: bool, stale: bool, in_progress: Optional[int] = None) -> Panel:
    current_order = in_progress if in_progress is not None else (_stage_order(current.stage) if current else -1)
    labels = ("IN", "SRC", "RES", "HYP", "TEC", "SCOPE", "WRITE", "SIGMA", "REVIEW")
    parts: List[Text] = []
    for index, label in enumerate(labels):
        if current and current.stage == "done" or index < current_order:
            style, glyph = "bright_green", "✓"
        elif index == current_order:
            if stale:
                style, glyph = "bold bright_red", "!"
            else:
                style, glyph = ("bold bright_magenta", "▶") if active else ("bright_green", "✓")
        else:
            style, glyph = "dim", "·"
        parts.append(Text(glyph + label, style=style))
        if index < len(labels) - 1:
            parts.append(Text(" › ", style="dim"))
    return Panel(Text.assemble(*parts), title="[bold bright_cyan]PIPELINE[/]", border_style="bright_magenta", box=box.SIMPLE)


def _compact_resources(host: HostSample) -> Panel:
    gpu_memory = _percent(host.gpu_memory_used, host.gpu_memory_total)
    cells = (
        ("CPU", host.cpu_percent, "host"),
        ("RAM", _percent(host.memory_used, host.memory_total), f"{_bytes(host.memory_used)}/{_bytes(host.memory_total)}"),
        (
            "GPU",
            host.gpu_percent,
            f"{_bytes(host.gpu_memory_used)}/{_bytes(host.gpu_memory_total)}" if gpu_memory is not None else host.gpu_name,
        ),
    )
    table = Table(box=None, expand=True, show_header=False, padding=(0, 1))
    for _ in cells:
        table.add_column(ratio=1)
    values = []
    for name, value, detail in cells:
        percent = "n/a" if value is None else f"{value:.0f}%"
        style = "bright_magenta" if value is not None and value >= 85 else "bright_cyan"
        values.append(Text(f"{name} {percent} · {detail}", style=style))
    table.add_row(*values)
    body = Group(table, Text.assemble(("DRIVES ", "bold bright_cyan"), (_disk_summary(host, compact=True), "bright_cyan")))
    return Panel(body, border_style="bright_magenta", box=box.SIMPLE, padding=(0, 0))


def _disk_summary(host: HostSample, compact: bool = False) -> str:
    if not host.disks:
        return "no local mounted drives detected"
    entries = []
    for disk in host.disks:
        percent = 100 * disk.used / disk.total if disk.total else 0
        if compact:
            entries.append(f"{disk.mount} {percent:.0f}%")
        else:
            entries.append(f"{disk.mount} {percent:.0f}% ({_bytes(disk.used)}/{_bytes(disk.total)})")
    return "  ·  ".join(entries)


def _disk_panel(host: HostSample) -> Panel:
    table = Table(box=None, expand=True, show_header=True, header_style="dim", padding=(0, 1))
    table.add_column("MOUNT", style="bright_cyan")
    table.add_column("USED", justify="right")
    table.add_column("CAPACITY", justify="right")
    for disk in host.disks:
        percent = 100 * disk.used / disk.total if disk.total else 0
        table.add_row(disk.mount, f"{_bytes(disk.used)} ({percent:.0f}%)", _bytes(disk.total))
    if not host.disks:
        table.add_row("--", "no local drives detected", "--")
    return Panel(
        table,
        title="[bold bright_cyan]MOUNTED LOCAL DRIVES[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _backlog_observation(events: List[TrailEvent]) -> Optional[Tuple[int, str]]:
    for event in reversed(events):
        match = re.search(r"(\d+) high-signal waiting in its backlog", event.message)
        if match:
            return int(match.group(1)), event.timestamp[-8:]
    return None


def _quota_text(used: Optional[int], limit: Optional[int]) -> str:
    if used is None or limit is None:
        return "n/a"
    return f"{used}/{limit}" + (" FULL" if limit > 0 and used >= limit else "")


def _until_next_run(next_run: Optional[datetime]) -> str:
    if next_run is None:
        return "not scheduled"
    seconds = max(0, int((next_run - datetime.now().astimezone()).total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes = remainder // 60
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m"
    return f"{remainder}s"


def _runner_compact_summary(status: RunnerStatus, events: List[TrailEvent]) -> str:
    if not status.installed:
        return ""
    backlog = _backlog_observation(events)
    backlog_text = f"B{backlog[0]}@{backlog[1][:5]}" if backlog else "B?"
    parked_text = f"P{status.parked_items}" if status.parked_items is not None else "P?"
    service_state = (
        "running"
        if status.service_state in {"active", "activating"}
        else "idle"
        if status.service_state == "inactive"
        else status.service_state
    )
    if status.daemon_active:
        timer_text = "daemon (continuous)"
    elif status.timer_active:
        timer_text = f"+{_until_next_run(status.next_run)}"
    else:
        timer_text = "timer off"
    draft_quota = (
        f"{status.drafts_today}/{status.drafts_limit}"
        if status.drafts_today is not None and status.drafts_limit is not None
        else "?"
    )
    research_quota = (
        f"{status.research_today}/{status.research_limit}"
        if status.research_today is not None and status.research_limit is not None
        else "?"
    )
    prov_text = f" [{status.cti_provider.split()[0]}]" if status.cti_provider else ""
    query_text = f" Q{status.pending_queries}" if status.pending_queries else ""
    cost_text = f" ${status.cost_today:.2f}" if status.cost_today is not None and status.cost_today > 0 else ""
    return f"Runner{prov_text} {service_state} {timer_text} · D{draft_quota} R{research_quota}{cost_text} · {backlog_text} {parked_text}{query_text}"


def _get_cooldown_str(events: List[TrailEvent], now: datetime) -> Optional[str]:
    for event in reversed(events):
        msg = event.message or ""
        if "spacing_cooldown" in msg or "spacing cooldown" in msg:
            m = re.search(r"(\d+(?:\.\d+)?)h\s*/\s*(\d+(?:\.\d+)?)h", msg)
            if m:
                elapsed_h = float(m.group(1))
                target_h = float(m.group(2))
                rem_sec = max(0.0, (target_h - elapsed_h) * 3600.0)
                evt_time = _parse_time(event.timestamp)
                if evt_time:
                    passed = max(0.0, (now - evt_time).total_seconds())
                    rem_sec = max(0.0, rem_sec - passed)
                if rem_sec <= 0:
                    return "eligible now"
                m_rem = int(rem_sec // 60)
                s_rem = int(rem_sec % 60)
                h_rem = m_rem // 60
                m_rem = m_rem % 60
                target_dt = (now + timedelta(seconds=rem_sec)).strftime("%H:%M UTC")
                if h_rem > 0:
                    return f"{h_rem}h {m_rem:02d}m (at {target_dt})"
                return f"{m_rem:02d}m {s_rem:02d}s (at {target_dt})"
    return None


def _tab_nav_bar(active_tab: int = 1, errors_only: bool = False, paused: bool = False) -> Text:
    tabs = [
        (1, "1: Overview"),
        (2, "2: Hunts & Rules"),
        (3, "3: Feeds & Outbox"),
        (4, "4: BAS & Validation"),
    ]
    bar = Text()
    bar.append(" VIEWS: ", style="bold bright_white")
    for tab_id, label in tabs:
        if tab_id == active_tab:
            bar.append(f" ◀ {label} ▶ ", style="bold bright_black on bright_cyan")
        else:
            bar.append(f"  {label}  ", style="bright_white on grey23")
        bar.append(" ")
    bar.append("│  CONTROLS: ", style="dim")
    if errors_only:
        bar.append("[e] ERRORS ONLY", style="bold bright_white on red")
    else:
        bar.append("[e] Errors", style="dim")
    bar.append("  ")
    if paused:
        bar.append("[p] PAUSED", style="bold bright_white on bright_yellow")
    else:
        bar.append("[p] Pause", style="dim")
    bar.append("  [q] Quit", style="dim")
    return bar


def _hunts_table(workspace: Path, metrics: HuntsMetrics) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("HUNT ID", width=10, style="bright_cyan")
    table.add_column("STATUS", width=12)
    table.add_column("TITLE", ratio=1, overflow="ellipsis", no_wrap=True)
    table.add_column("TACTICS", width=18, style="dim")
    table.add_column("TECHNIQUES", width=16, style="dim")

    hunts_dir = workspace / "hunts"
    if not hunts_dir.exists():
        for candidate in [
            workspace.parent / "Hecate-Workspace" / "hunts",
            workspace.parent / "Hecate-Public" / "hunts",
            Path("/home/chemch/betas/Hecate-Public/hunts"),
        ]:
            if candidate.exists():
                hunts_dir = candidate
                break

    hunt_files = []
    if hunts_dir.exists():
        try:
            hunt_files = sorted(hunts_dir.rglob("H-*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            hunt_files = []

    status_styles = {
        "promoted": "bold bright_green",
        "published": "bold bright_green",
        "completed": "bright_green",
        "active": "bright_cyan",
        "in_progress": "bright_cyan",
        "in_review": "bold bright_yellow",
        "planning": "dim bright_yellow",
        "draft": "dim yellow",
    }

    count = 0
    for hf in hunt_files[:15]:
        try:
            content = hf.read_text(encoding="utf-8", errors="ignore")
            title = hf.stem
            status = "planning"
            tactics = []
            techniques = []
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    fm = yaml.safe_load(parts[1])
                    if isinstance(fm, dict):
                        title = str(fm.get("title") or title)
                        if title.startswith("DRAFT - "):
                            title = title[8:].strip()
                        status = str(fm.get("status") or "planning").lower()
                        tactics = [str(t).title() for t in (fm.get("tactics") or [])]
                        techniques = [str(t).upper() for t in (fm.get("techniques") or [])]
            style = status_styles.get(status, "bright_white")
            table.add_row(
                hf.stem,
                Text(status.upper(), style=style),
                title,
                ", ".join(tactics[:2]) if tactics else "--",
                ", ".join(techniques[:2]) if techniques else "--",
            )
            count += 1
        except Exception:
            continue

    if count == 0:
        table.add_row("--", "--", "No hunt drafts found in workspace", "--", "--")

    return Panel(
        table,
        title=f"[bold bright_cyan]ACTIVE & RECENT HUNTS ({metrics.total_hunts} total)[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _cti_feeds_panel(workspace: Path, events: List[TrailEvent]) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("FEED SOURCE", width=16, style="bright_cyan")
    table.add_column("CATEGORY", width=18, style="dim")
    table.add_column("LAST INTAKE", width=12, style="dim")
    table.add_column("ACTIVITY TODAY", ratio=1, overflow="ellipsis", no_wrap=True)
    table.add_column("STATUS", width=10)

    feeds = [
        ("cisa_kev", "CISA KEV", "Exploited Vulns"),
        ("otx", "Abuse.ch OTX", "Threat Pulses"),
        ("threatfox", "ThreatFox", "Threat Indicators"),
        ("malwarebazaar", "MalwareBazaar", "Malware Hashes"),
        ("shadowserver", "Shadowserver", "C2 Infrastructure"),
        ("misp", "MISP Inbound", "Community Events"),
        ("cisa_advisories", "CISA Advisories", "Alerts & ICS"),
        ("github_poc", "GitHub PoC", "Exploit Advisories"),
        ("rss", "Threat RSS", "Security Blogs"),
        ("certstream", "CertStream", "Live TLS Stream"),
    ]

    for key, name, category in feeds:
        last_time = "--"
        activity = "Standby"
        status = "STANDBY"
        status_style = "dim"

        for e in reversed(events):
            if key in e.message.lower() or (e.stage == "intake" and key in e.message.lower()):
                last_time = e.timestamp[-8:]
                status = "ACTIVE"
                status_style = "bold bright_green"
                activity = e.message[:55]
                break

        table.add_row(name, category, last_time, activity, Text(status, style=status_style))

    return Panel(
        table,
        title="[bold bright_cyan]INBOUND CTI FEEDS & POLLER STATUS[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _ingestion_funnel_panel(events: List[TrailEvent], runner: RunnerStatus) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("PIPELINE FUNNEL STAGE", width=24, style="bright_cyan")
    table.add_column("COUNT", width=8, justify="right", style="bold bright_white")
    table.add_column("PROGRESS / CONVERSION", ratio=1)

    intake_count = sum(1 for e in events if e.stage == "intake" or "intake:" in e.message)
    triage_count = sum(1 for e in events if e.stage == "triage" and "pass" in e.message)
    hypothesis_count = sum(1 for e in events if e.stage == "hypothesis" or "hypothesis:" in e.message)
    draft_count = runner.drafts_today or sum(1 for e in events if "draft_created" in e.message or "draft_written" in e.message)
    promoted_count = runner.github_confirmed_promotions

    base = max(intake_count, 1)
    stages = [
        ("1. Raw CTI Ingested", intake_count, 100.0 if intake_count else 0.0),
        ("2. Triage Validated", triage_count, (triage_count / base * 100.0)),
        ("3. Hypotheses Formed", hypothesis_count, (hypothesis_count / base * 100.0)),
        ("4. Drafts Created", draft_count, (draft_count / base * 100.0)),
        ("5. Hunts Published", promoted_count, (promoted_count / base * 100.0)),
    ]

    for label, cnt, pct in stages:
        bar = _bar(pct, width=16).plain
        table.add_row(label, str(cnt), f"[{bar}] {pct:.1f}%")

    if runner.parked_reasons:
        p_str = ", ".join(f"{cnt} {k}" for k, cnt in sorted(runner.parked_reasons.items())[:3])
        table.add_row("PARKED ITEMS QUEUE", str(runner.parked_items or 0), f"Reasons: {p_str}")

    return Panel(
        table,
        title="[bold bright_cyan]CTI INGESTION FUNNEL & CONVERSION (TODAY)[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _github_outbox_panel(workspace: Path) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("ID", width=4, style="dim")
    table.add_column("HUNT", width=8, style="bright_cyan")
    table.add_column("STATUS", width=11)
    table.add_column("PR / BRANCH", ratio=1, overflow="ellipsis", no_wrap=True)
    table.add_column("UPDATED", width=9, style="dim")

    db_path = workspace / ".hecate" / "publisher" / "promotion-outbox.sqlite3"
    if not db_path.exists():
        db_path = workspace / ".hecate" / "github" / "outbox.sqlite3"

    rows = []
    if db_path.exists():
        try:
            conn = sqlite3.connect(db_path, timeout=2.0)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute("SELECT * FROM promotions ORDER BY id DESC LIMIT 8").fetchall()
            finally:
                conn.close()
        except Exception:
            pass

    for r in rows:
        st = str(r["status"]).lower()
        if st in ("published", "merged"):
            st_style = "bold bright_green"
        elif st in ("queued", "publishing"):
            st_style = "bold bright_yellow"
        elif st == "retry":
            st_style = "bold red"
        else:
            st_style = "bright_white"

        pr = f"PR #{r['pr_number']}" if r["pr_number"] else str(r["branch"] or "--")
        upd = str(r["updated_at"] or "")[-14:-6] if r["updated_at"] else "--"
        table.add_row(str(r["id"]), str(r["hunt_id"]), Text(st.upper(), style=st_style), pr, upd)

    if not rows:
        table.add_row("--", "--", "EMPTY", "No promotions in GitHub outbox", "--")

    return Panel(
        table,
        title="[bold bright_cyan]GITHUB PROMOTION OUTBOX[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _misp_outbox_panel(workspace: Path) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("HUNT", width=8, style="bright_cyan")
    table.add_column("EVENT ID", width=10, style="dim")
    table.add_column("STATUS", width=11)
    table.add_column("TARGET", ratio=1, overflow="ellipsis", no_wrap=True)
    table.add_column("CONFIRMED", width=12, style="dim")

    db_path = workspace / ".hecate" / "misp" / "outbox.sqlite3"
    rows = []
    if db_path.exists():
        try:
            conn = sqlite3.connect(db_path, timeout=2.0)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute("SELECT * FROM exports ORDER BY next_attempt DESC LIMIT 8").fetchall()
            finally:
                conn.close()
        except Exception:
            pass

    for r in rows:
        st = str(r["status"]).lower()
        st_style = "bold bright_green" if st == "confirmed" else "bold bright_yellow" if st in ("queued", "publishing") else "bold red"
        conf = str(r["confirmed_at"] or "")[:10] if r["confirmed_at"] else "--"
        table.add_row(
            str(r["hunt_id"]),
            str(r["event_id"] or "--"),
            Text(st.upper(), style=st_style),
            str(r["target"]),
            conf,
        )

    if not rows:
        table.add_row("--", "--", "EMPTY", "No exports in MISP outbox", "--")

    return Panel(
        table,
        title="[bold bright_cyan]MISP EXPORT OUTBOX[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _bas_status_panel(workspace: Path, events: List[TrailEvent], metrics: Any) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=False, padding=(0, 1))
    table.add_column("KEY", width=20, style="dim")
    table.add_column("VALUE", style="bright_white")

    table.add_row("CONTROLLER ENGINE", Text("Caldera Controller (Non-Root)", style="bright_green"))
    table.add_row("TARGET SENSOR", Text("Ubuntu Local Process Sensor + Sigma", style="bright_cyan"))
    table.add_row("ATTACK AUTOMATION", Text(getattr(metrics, "bas_mode_label", "AUTO · approved Linux lab"), style="bright_white"))
    table.add_row("VALIDATION SCOPE", Text(getattr(metrics, "bas_scope_label", "Local process sensor + Sigma"), style="bright_white"))

    runs = getattr(metrics, "bas_runs", 0)
    live_runs = getattr(metrics, "bas_live_runs", 0)
    mock_runs = getattr(metrics, "bas_mock_runs", 0)
    table.add_row("SIMULATION RUNS", f"{runs} runs ({live_runs} live, {mock_runs} mock)")

    events_count = getattr(metrics, "bas_matched_events", 0)
    table.add_row("SENSOR TELEMETRY", f"{events_count} events captured & correlated")

    return Panel(
        table,
        title="[bold bright_cyan]BAS CONTROLLER & SENSOR STATUS[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _bas_events_panel(events: List[TrailEvent]) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("TIME", width=9, style="dim")
    table.add_column("STAGE", width=12)
    table.add_column("VALIDATION ACTIVITY", ratio=1, overflow="ellipsis", no_wrap=True)

    bas_events = [
        e
        for e in events
        if any(k in e.message.lower() or k in e.stage.lower() for k in ("bas", "sensor", "caldera", "stratus", "validation", "telemetry", "replay"))
    ]
    for e in bas_events[-8:]:
        table.add_row(e.timestamp[-8:], e.stage, e.message)

    if not bas_events:
        table.add_row("--:--:--", "standby", "No recent breach simulation events in log stream")

    return Panel(
        table,
        title="[bold bright_cyan]RECENT SENSOR & BREACH SIMULATION LOGS[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _runner_panel(status: RunnerStatus, events: List[TrailEvent]) -> Panel:
    service_state = status.service_state.upper()
    service_style = "bright_green" if service_state in {"ACTIVE", "ACTIVATING"} else "bright_cyan"
    if status.daemon_active:
        service_parts = [
            ("SERVICE  ", "dim"),
            ("DAEMON ACTIVE", "bright_green"),
        ]
    else:
        service_parts = [
            ("SERVICE  ", "dim"),
            (service_state, service_style),
            (" · timer " + ("active" if status.timer_active else "inactive"), "bright_cyan"),
        ]
        if status.cti_provider:
            service_parts.append((" · " + status.cti_provider, "dim"))
    schedule_label = "MODE     " if status.daemon_active else "NEXT RUN "
    schedule_text = "continuous event loop" if status.daemon_active else _until_next_run(status.next_run)
    schedule_style = "bright_green" if status.daemon_active else "bright_magenta"
    rows = [
        Text.assemble(*service_parts, no_wrap=True),
        Text.assemble((schedule_label, "dim"), (schedule_text, schedule_style), no_wrap=True),
    ]

    cooldown_str = _get_cooldown_str(events, datetime.now())
    if cooldown_str:
        rows.append(Text.assemble(("COOLDOWN ", "dim"), (f"next draft in {cooldown_str}", "bright_yellow"), no_wrap=True))

    quota_parts = [
        ("QUOTA    ", "dim"),
        ("drafts " + _quota_text(status.drafts_today, status.drafts_limit), "bright_white"),
        (" · research " + _quota_text(status.research_today, status.research_limit), "bright_white"),
    ]
    if status.cost_today is not None and status.cost_today > 0.0:
        cost_limit = status.cost_limit or 20.0
        pct = (status.cost_today / cost_limit * 100.0) if cost_limit > 0 else 0.0
        quota_parts.append((f" · ${status.cost_today:.2f} today (${cost_limit:.2f} cap · {pct:.0f}%)", "bright_green"))
    rows.append(Text.assemble(*quota_parts, no_wrap=True))
    backlog = _backlog_observation(events)
    if backlog:
        rows.append(
            Text.assemble(
                ("BACKLOG  ", "dim"),
                (f"{backlog[0]} waiting", "bright_cyan"),
                (f" · {backlog[1]}", "dim"),
                no_wrap=True,
            )
        )
    else:
        rows.append(Text.assemble(("BACKLOG  ", "dim"), ("none reported", "yellow"), no_wrap=True))
    if status.parked_items is not None or status.total_drafts is not None or status.pending_queries:
        details = []
        if status.parked_items is not None:
            if status.parked_reasons:
                p_summary = ", ".join(f"{cnt} {k}" for k, cnt in sorted(status.parked_reasons.items())[:2])
                details.append(f"{status.parked_items} parked ({p_summary})")
            else:
                details.append(f"{status.parked_items} parked")
        if status.total_drafts is not None:
            details.append(f"{status.total_drafts} drafts")
        if status.pending_queries:
            details.append(f"{status.pending_queries} pending")
        queue_style = "bold yellow" if status.pending_queries else "bright_white"
        rows.append(Text.assemble(("QUEUE    ", "dim"), (" · ".join(details), queue_style), no_wrap=True))

    outbox_parts = []
    if status.github_pending_prs or status.github_confirmed_promotions:
        if status.github_pending_prs:
            outbox_parts.append(f"{status.github_pending_prs} PR pending")
        if status.github_confirmed_promotions:
            outbox_parts.append(f"{status.github_confirmed_promotions} GitHub published")
    if status.misp_pending_exports or status.misp_confirmed_exports:
        if status.misp_pending_exports:
            outbox_parts.append(f"{status.misp_pending_exports} MISP pending")
        if status.misp_confirmed_exports:
            outbox_parts.append(f"{status.misp_confirmed_exports} MISP confirmed")
    if outbox_parts:
        rows.append(Text.assemble(("OUTBOX   ", "dim"), (" · ".join(outbox_parts), "bright_cyan"), no_wrap=True))

    return Panel(
        Group(*rows),
        title="[bold bright_cyan]RUNNER[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _get_inbox_counts(workspace: Path) -> Tuple[int, int, int]:
    try:
        import importlib

        hecate_graph = importlib.import_module("hecate_agent.orchestrator.graph").hecate_graph
        import sqlite3

        db_path = workspace / "hecate_checkpoints.sqlite"
        if not db_path.exists():
            return 0, 0, 0
        conn = sqlite3.connect(db_path)
        try:
            c = conn.cursor()
            c.execute("SELECT DISTINCT thread_id FROM checkpoints")
            threads = [row[0] for row in c.fetchall()]
        finally:
            conn.close()
        pending, completed, failed = 0, 0, 0
        for thread_id in threads:
            try:
                state = hecate_graph.get_state({"configurable": {"thread_id": thread_id}})
                if state.next:
                    pending += 1
                elif state.values.get("halt_reason"):
                    failed += 1
                else:
                    completed += 1
            except Exception:
                failed += 1
        return pending, completed, failed
    except Exception:
        return 0, 0, 0


def _format_cycle_outcome(msg: str) -> str:
    """Format a completed or parked cycle's outcome message cleanly for the header.

    Eliminates awkward mid-word slicing and formats reasons like
    'parked_after_hypothesis (reason) in 170s' into:
    'parked_after_hypothesis in 170s · reason'
    """
    clean = " ".join(msg.split())
    match = re.match(r"^(parked_after_\w+|parked\w*)\s*\((.*?)\)(?:\s*in\s*(\d+s))?$", clean)
    if match:
        outcome = match.group(1)
        reason = match.group(2).strip()
        dur = match.group(3)
        for prefix in (
            "hypothesis model judged this ",
            "model judged this ",
            "route model judged this ",
        ):
            if reason.lower().startswith(prefix):
                reason = reason[len(prefix) :].strip()
                break
        if dur:
            return f"{outcome} in {dur} · {reason}"
        return f"{outcome} · {reason}"
    return clean


def _render_dashboard(
    workspace: Path,
    events: List[TrailEvent],
    metrics: Dict[str, Any],
    host: HostSample,
    refreshed: datetime,
    runner: Optional[RunnerStatus] = None,
    recent_error: str = "",
    live: Optional[Dict[str, Any]] = None,
    active_tab: int = 1,
    errors_only: bool = False,
    paused: bool = False,
) -> Layout:
    runner = runner or RunnerStatus()
    if runner.cost_today is None:
        agg_cost = metrics.get("aggregate", {}).get("cost_today_usd")
        if agg_cost is not None and agg_cost > 0.0:
            runner.cost_today = agg_cost
    if runner.pending_queries is None:
        pending_dir = workspace / ".pending_queries"
        try:
            if pending_dir.exists():
                runner.pending_queries = len(list(pending_dir.glob("*.json")))
        except OSError:
            pass
    latest, active, elapsed = _pipeline_state(events, _service_running(runner, workspace), refreshed)
    stale = bool(latest and not active and latest.stage != "done")
    in_progress = _stage_in_progress(events)
    working_on = _STAGES[in_progress][1] if in_progress >= 0 else "starting"
    status = "RUNNING" if active else "STALLED" if stale else "IDLE"
    cycle = latest.cycle_id if latest else "------"
    title = Text(no_wrap=True, overflow="ellipsis")
    title.append(" HECATE ", style="bold black on bright_cyan")
    title.append(" MONITOR ", style="bold bright_white")
    pending, completed, failed = _get_inbox_counts(workspace)
    queue_str = (
        f" · Queue: {pending} pending, {completed} completed, {failed} failed" if (pending or completed or failed) else ""
    )

    if latest and active:
        subline = (
            f"[{status}] cycle {cycle} · now: {working_on} · elapsed {_duration(elapsed)}"
            f" · last: {latest.stage}: {' '.join(latest.message.split())}{queue_str}"
        )
    elif latest and stale:
        why = (
            "the Runner service is not running"
            if _service_running(runner, workspace) is False
            else f"no log activity for {_QUIET_SECONDS // 60}+ minutes"
        )
        time_str = latest.timestamp.split()[-1] if " " in latest.timestamp else latest.timestamp
        subline = f"[{status}] cycle {cycle} · stopped in {working_on} · seen {time_str} · {why}{queue_str}"
    elif latest:
        outcome_str = _format_cycle_outcome(latest.message)
        cooldown_str = _get_cooldown_str(events, refreshed)
        if cooldown_str and "spacing_cooldown" in latest.message:
            outcome_str = f"{outcome_str} (next in {cooldown_str})"
        subline = f"[{status}] last cycle {cycle} · {outcome_str}{queue_str}"
    else:
        subline = f"[{status}] monitoring {workspace} · waiting for a pipeline cycle{queue_str}"

    layout = Layout()
    title.append(" " + subline, style="dim")
    compact = console.size.height < 40
    header_height = 3 if compact else 4
    if compact:
        header_panel = Panel(title, border_style="bright_cyan", box=box.DOUBLE)
    else:
        header_panel = Panel(
            Group(title, _tab_nav_bar(active_tab, errors_only, paused)),
            border_style="bright_cyan",
            box=box.DOUBLE,
        )

    if compact:
        activity = Table(box=None, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
        activity.add_column("TIME", width=8, style="dim")
        activity.add_column("STAGE", width=9)
        activity.add_column("ACTIVITY", ratio=1, overflow="ellipsis")
        for event in events[-3:]:
            color = _get_stage_color(event.stage)
            activity.add_row(event.timestamp[-8:], f"[{color}]{event.stage[:9]}[/]", event.message)
        if not events:
            activity.add_row("--:--:--", "[dim white]idle[/]", "Waiting for Runner events")
        if recent_error and stale:
            action_panel = Panel(
                Text(recent_error, style="red"), title="[bold red]ERROR STREAM[/]", border_style="red", box=box.SIMPLE
            )
        else:
            action_panel = Panel(
                activity, title="[bold bright_cyan]ACTION STREAM[/]", border_style="bright_magenta", box=box.SIMPLE
            )
        search_count = _search_count(latest, events)
        layout.split_column(
            Layout(header_panel, name="header", size=3),
            Layout(_compact_resources(host), name="resources", size=4),
            Layout(_compact_progress(latest, active, stale, in_progress), name="progress", size=3),
            Layout(action_panel, name="activity", size=6),
            Layout(name="usage", size=_BOTTOM_ROW_HEIGHT),
            Layout(
                Text(
                    f"Updated {refreshed:%H:%M:%S} · Ctrl-C exits"
                    + (f" · {_runner_compact_summary(runner, events)}" if runner.installed else ""),
                    style="dim",
                    overflow="ellipsis",
                ),
                name="footer",
                size=1,
            ),
        )
        h_metrics = _collect_hunts_metrics(workspace)
        pt_metrics = _collect_purple_team_metrics(workspace, events)
        layout["usage"].split_row(
            Layout(
                _usage_panel(metrics, latest, active, events, compact=True, workspace=workspace, live=live, now=refreshed),
                ratio=1,
            ),
            Layout(Text(" "), size=1),
            Layout(_hunts_panel(workspace=workspace, compact=True, metrics=h_metrics), ratio=1),
            Layout(Text(" "), size=1),
            Layout(
                _detections_panel(
                    workspace=workspace,
                    compact=True,
                    metrics=h_metrics,
                    runner=runner,
                    events=events,
                    purple_metrics=pt_metrics,
                ),
                ratio=1,
            ),
            Layout(Text(" "), size=1),
            Layout(_mitre_metrics_panel(workspace=workspace, compact=True, narrow=False, metrics=h_metrics), ratio=1),
            Layout(Text(" "), size=1),
            Layout(_outbound_panel(workspace=workspace, runner=runner, compact=True), ratio=1),
            Layout(Text(" "), size=1),
            Layout(
                _integrations_panel(
                    workspace=workspace,
                    search_count=search_count,
                    compact=True,
                    narrow=False,
                    events=events,
                    metrics=metrics,
                    live=live,
                    current=latest,
                ),
                ratio=1,
            ),
        )
        return layout

    footer = Layout(
        Text(
            f"Updated {refreshed:%H:%M:%S}   ·   [1] Overview   [2] Hunts & Rules   [3] Feeds & Outbox   [4] BAS & Validation   ·   [e] Errors   [p] Pause   [q] Quit",
            style="dim",
            justify="center",
        ),
        name="footer",
        size=1,
    )

    h_metrics = _collect_hunts_metrics(workspace)
    pt_metrics = _collect_purple_team_metrics(workspace, events)

    # Tab 2: Hunts & Rules View
    if not compact and active_tab == 2:
        tab2_layout = Layout()
        tab2_layout.split_column(
            Layout(header_panel, name="header", size=header_height),
            Layout(_host_telemetry_ribbon(host), name="resources", size=3),
            Layout(name="middle", ratio=1),
            footer,
        )
        tab2_layout["middle"].split_row(
            Layout(name="hunts_left", ratio=1),
            Layout(Text(" "), size=1),
            Layout(name="hunts_right", ratio=1),
        )
        tab2_layout["hunts_left"].split_column(
            Layout(_hunts_table(workspace, h_metrics), ratio=2),
            Layout(_detections_panel(workspace, h_metrics, runner, events, pt_metrics), size=8),
        )
        tab2_layout["hunts_right"].split_column(
            Layout(_mitre_metrics_panel(workspace, metrics=h_metrics, detailed=True), ratio=2),
            Layout(_hunts_panel(workspace, metrics=h_metrics), size=8),
        )
        return tab2_layout

    # Tab 3: CTI Feeds & Outbox View
    if not compact and active_tab == 3:
        tab3_layout = Layout()
        tab3_layout.split_column(
            Layout(header_panel, name="header", size=header_height),
            Layout(_host_telemetry_ribbon(host), name="resources", size=3),
            Layout(name="middle", ratio=1),
            footer,
        )
        tab3_layout["middle"].split_row(
            Layout(name="feeds_left", ratio=1),
            Layout(Text(" "), size=1),
            Layout(name="feeds_right", ratio=1),
        )
        tab3_layout["feeds_left"].split_column(
            Layout(_cti_feeds_panel(workspace, events), ratio=1),
            Layout(_ingestion_funnel_panel(events, runner), ratio=1),
        )
        tab3_layout["feeds_right"].split_column(
            Layout(_outbound_panel(workspace, runner), size=6),
            Layout(_github_outbox_panel(workspace), ratio=1),
            Layout(_misp_outbox_panel(workspace), ratio=1),
        )
        return tab3_layout

    # Tab 4: BAS & Validation View
    if not compact and active_tab == 4:
        tab4_layout = Layout()
        tab4_layout.split_column(
            Layout(header_panel, name="header", size=header_height),
            Layout(_host_telemetry_ribbon(host), name="resources", size=3),
            Layout(name="middle", ratio=1),
            footer,
        )
        tab4_layout["middle"].split_column(
            Layout(name="val_top", ratio=1),
            Layout(name="val_bottom", ratio=1),
        )
        tab4_layout["val_top"].split_row(
            Layout(_bas_status_panel(workspace, events, pt_metrics), ratio=1),
            Layout(Text(" "), size=1),
            Layout(_purple_team_panel(workspace, events, narrow=False, metrics=pt_metrics), ratio=1),
        )
        tab4_layout["val_bottom"].split_row(
            Layout(_bas_events_panel(events), ratio=1),
            Layout(Text(" "), size=1),
            Layout(
                _integrations_panel(
                    workspace=workspace,
                    search_count="",
                    events=events,
                    metrics=metrics,
                    live=live,
                    current=latest,
                    grid=True,
                ),
                ratio=1,
            ),
        )
        return tab4_layout

    # Tab 1: Operations Overview (Default)
    resources_height = 3
    stages_height = len(_STAGES) + 3
    service_height = (8 if (runner.github_confirmed_promotions or runner.misp_confirmed_exports) else 7) if runner.installed else 0
    body_height = console.size.height - header_height - resources_height - 1
    llm_height = _NARROW_LLM_PANEL_HEIGHT
    hunts_height = _HUNTS_PANEL_HEIGHT
    mitre_height = _MITRE_PANEL_HEIGHT
    search_count = _search_count(latest, events)
    usage_on_left = body_height >= stages_height + service_height + llm_height + hunts_height + mitre_height + 4
    middle_height = body_height if usage_on_left else max(10, body_height - _BOTTOM_ROW_HEIGHT)
    service_on_left = runner.installed and middle_height >= stages_height + service_height
    left_width = min(52, max(46, console.size.width // 4)) if console.size.width >= 120 else None
    ops_width = (console.size.width - left_width - 2) if left_width else (console.size.width * 2 // 3)
    swap_detail_panels = usage_on_left and ops_width >= 85
    expanded_mitre = usage_on_left and ops_width >= 135
    llm_panel = _usage_panel(
        metrics, latest, active, events, workspace=workspace, live=live, now=refreshed, narrow=usage_on_left
    )
    integrations_panel = _integrations_panel(
        workspace=workspace, search_count=search_count, narrow=True, events=events, metrics=metrics, live=live, current=latest
    )
    integrations_grid_panel = _integrations_panel(
        workspace=workspace,
        search_count=search_count,
        events=events,
        metrics=metrics,
        live=live,
        current=latest,
        grid=True,
        grid_compact_names=ops_width < 160,
    )
    hunts_panel = _hunts_panel(workspace=workspace, narrow=usage_on_left, metrics=h_metrics)
    mitre_panel = _mitre_metrics_panel(workspace=workspace, narrow=usage_on_left, metrics=h_metrics, detailed=expanded_mitre)
    detections_panel = _detections_panel(
        workspace=workspace,
        metrics=h_metrics,
        runner=runner,
        events=events,
        purple_metrics=pt_metrics,
        narrow=usage_on_left,
    )
    outbound_panel = _outbound_panel(workspace=workspace, runner=runner, narrow=usage_on_left)
    purple_team_panel = _purple_team_panel(workspace=workspace, events=events, narrow=False, metrics=pt_metrics)

    if usage_on_left:
        layout.split_column(
            Layout(header_panel, name="header", size=header_height),
            Layout(_host_telemetry_ribbon(host), name="resources", size=resources_height),
            Layout(name="middle", ratio=2),
            footer,
        )
    else:
        layout.split_column(
            Layout(header_panel, name="header", size=header_height),
            Layout(_host_telemetry_ribbon(host), name="resources", size=resources_height),
            Layout(name="middle", ratio=2),
            Layout(name="usage", size=_BOTTOM_ROW_HEIGHT),
            footer,
        )
        layout["usage"].split_row(
            Layout(llm_panel, ratio=1),
            Layout(Text(" "), size=1),
            Layout(hunts_panel, ratio=1),
            Layout(Text(" "), size=1),
            Layout(detections_panel, ratio=1),
            Layout(Text(" "), size=1),
            Layout(mitre_panel, ratio=1),
            Layout(Text(" "), size=1),
            Layout(outbound_panel, ratio=1),
            Layout(Text(" "), size=1),
            Layout(integrations_panel, ratio=1),
        )

    step_elapsed = None
    if latest and active:
        last_ts = _parse_time(latest.timestamp)
        if last_ts:
            step_elapsed = max(0.0, (refreshed - last_ts).total_seconds())

    stages_panel = Panel(
        _stage_table(latest, active, stale, in_progress, step_elapsed=step_elapsed),
        title="[bold bright_cyan]SEQUENCE[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )
    if left_width:
        layout["middle"].split_row(
            Layout(name="stages", size=left_width),
            Layout(Text(" "), name="gutter", size=1),
            Layout(name="operations", ratio=1),
        )
    else:
        layout["middle"].split_row(
            Layout(name="stages", ratio=1),
            Layout(Text(" "), name="gutter", size=1),
            Layout(name="operations", ratio=2),
        )

    service_on_left = runner.installed and middle_height >= stages_height + service_height
    stream_height = middle_height if service_on_left or not runner.installed else middle_height - service_height
    if recent_error and stale:
        main_panel = Panel(
            Text(recent_error, style="red"), title="[bold red]ERROR STREAM[/]", border_style="red", box=box.ROUNDED
        )
    else:
        act_width = (console.size.width - left_width - 6) if left_width else (console.size.width * 2 // 3 - 30)
        stream_title = "[bold red]ACTION STREAM (ERRORS ONLY)[/]" if errors_only else "[bold bright_cyan]ACTION STREAM[/]"
        stream_border = "red" if errors_only else "bright_magenta"
        main_panel = Panel(
            _activity_table(events, rows=max(1, stream_height - 3), width=max(40, act_width), errors_only=errors_only),
            title=stream_title,
            border_style=stream_border,
            box=box.ROUNDED,
        )

    left = [Layout(stages_panel, size=stages_height)]
    if service_on_left:
        left.append(Layout(_runner_panel(runner, events), size=service_height))
    if usage_on_left:
        left.append(Layout(llm_panel, size=llm_height))
        left.append(Layout(hunts_panel, size=hunts_height))
        left.append(Layout(detections_panel, size=8))
        left.append(Layout(outbound_panel, ratio=1))
    else:
        left.append(Layout(detections_panel, ratio=1))
    if len(left) > 1:
        layout["stages"].split_column(*left)
    else:
        layout["stages"].update(stages_panel)
    if runner.installed and not service_on_left:
        layout["operations"].split_column(
            Layout(main_panel, ratio=2), Layout(_runner_panel(runner, events), size=service_height)
        )
    elif usage_on_left:
        if ops_width >= 135:
            bottom_ops = Layout(name="bottom_ops", size=_DETAILED_MITRE_PANEL_HEIGHT)
            bottom_ops.split_row(
                Layout(integrations_grid_panel, ratio=1),
                Layout(Text(" "), size=1),
                Layout(mitre_panel, ratio=1),
            )
            layout["operations"].split_column(Layout(main_panel, ratio=1), bottom_ops)
        elif ops_width >= 85:
            bottom_ops = Layout(name="bottom_ops", size=_BOTTOM_DETAIL_PANELS_HEIGHT)
            bottom_ops.split_row(
                Layout(integrations_grid_panel, ratio=1),
                Layout(Text(" "), size=1),
                Layout(mitre_panel, ratio=1),
            )
            layout["operations"].split_column(Layout(main_panel, ratio=1), bottom_ops)
        else:
            layout["operations"].split_column(
                Layout(main_panel, ratio=1), Layout(mitre_panel, size=_BOTTOM_ROW_HEIGHT)
            )
    else:
        layout["operations"].update(main_panel)
    return layout


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
                        elif key in ("1", "2", "3", "4"):
                            active_tab = int(key)
                            break
                        elif key in ("\t", "\x1b[C"):
                            active_tab = (active_tab % 4) + 1
                            break
                        elif key == "\x1b[D":
                            active_tab = 4 if active_tab == 1 else (active_tab - 1)
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
