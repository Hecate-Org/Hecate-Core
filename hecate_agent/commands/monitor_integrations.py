"""Integration panels and credential status for monitor UI."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich import box
from rich.console import Console, ConsoleOptions, RenderResult
from rich.measure import Measurement
from rich.panel import Panel
from rich.rule import Rule
from rich.segment import Segment
from rich.table import Table
from rich.text import Text

from hecate_agent.commands.monitor_samplers import TrailEvent
from hecate_agent.integration_registry import (
    BY_LABEL,
    INTEGRATIONS,
    SOURCE_INTEGRATIONS,
    STATUS_INTEGRATIONS,
    enrichment_label,
    label_for_host,
)

# Views of the registry. Other monitor modules import these names.
_INTEGRATION_IDS = {item.label: item.id for item in BY_LABEL.values()}
_SOURCE_INTEGRATIONS = {item.cti_name for item in INTEGRATIONS if item.follows_cti_provider}

def _backlog_observation(events: List[TrailEvent]) -> Optional[Tuple[int, str]]:
    for event in reversed(events):
        match = re.search(r"(\d+) high-signal waiting in its backlog", event.message)
        if match:
            return int(match.group(1)), event.timestamp[-8:]
    return None



def _credential_status(workspace: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    """Return lists of active (configured) and inactive service labels."""
    checks = tuple((item.label, item.env_keys) for item in STATUS_INTEGRATIONS if item.env_keys)
    env_files = [workspace / ".env"] if workspace else []
    if workspace:
        env_files.append(workspace.parent / "Hecate-Runner" / ".env")
    file_keys = set()
    for env_file in env_files:
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                key, sep, value = line.partition("=")
                if sep and value.strip().strip("\"'"):
                    file_keys.add(key.strip().removeprefix("export "))
        except OSError:
            continue
    on, off = [], []
    for label, names in checks:
        is_set = any(os.environ.get(name) for name in names) or any(name in file_keys for name in names)
        if is_set:
            on.append(label)
        else:
            off.append(label)
    return on, off


def _credential_summary(workspace: Optional[Path] = None) -> str:
    """Show configured status only; never read or render credential values."""
    on, off = _credential_status(workspace)
    return " · ".join([f"{item} ON" for item in on] + [f"{item} OFF" for item in off])


def _confirmed_integration(workspace: Optional[Path], name: str, enabled: bool) -> Tuple[bool, str]:
    """Only a recent successful check plus current enablement can produce green."""
    if workspace is None:
        return False, "unconfirmed" if enabled else "disabled"
    try:
        record = json.loads((workspace / ".hecate" / "integrations" / f"{name}.json").read_text())
        checked = datetime.fromisoformat(record["checked_at"])
        age = (datetime.now(timezone.utc) - checked).total_seconds()
        if not 0 <= age <= 7200:
            return False, "check stale" if enabled else "disabled"
        if not enabled and record.get("healthy") is True:
            return False, "reachable; disabled"
        if not enabled:
            return False, "disabled"
        healthy = enabled and record.get("healthy") is True and record.get("enabled") is True
        return healthy, "confirmed" if healthy else str(record.get("detail") or "failed")[:80]
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return False, "unconfirmed" if enabled else "disabled"


def _integration_style(healthy: bool, detail: str) -> str:
    if healthy:
        return "bold #ff69b4" if detail == "output only" else "bold bright_green"
    if detail == "reachable; disabled":
        return "bold bright_magenta"
    if detail == "disabled":
        return "bold grey62"
    return "bold bright_red"


def _color_group_rank(ok: bool, detail: str) -> int:
    """Group by color: 1=Green (healthy), 2=Pink (output-only), 3=Magenta (reachable; disabled), 4=Red (failed/error), 5=Grey (disabled)."""
    if ok and detail != "output only":
        return 1
    if ok and detail == "output only":
        return 2
    if detail == "reachable; disabled":
        return 3
    if detail == "disabled":
        return 5
    return 4


def _detect_active_integration(
    current: Optional[TrailEvent] = None,
    events: Optional[List[TrailEvent]] = None,
    live: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Identify which integration service is actively in use right now."""
    if live and (live.get("in_flight") or live.get("status") in ("CALLING", "STREAMING")):
        return "LLM"

    if not current:
        return None

    msg = current.message.lower()
    stage = current.stage.lower()

    if stage in ("hypothesis", "techniques", "scope", "write", "sigma", "review"):
        return "LLM"
    if stage == "research":
        if "search" in msg or "tavily" in msg:
            return "Tavily"
        return "LLM"
    if stage in ("intake", "source"):
        for token, label in (
            ("misp", "MISP"),
            ("otx", "OTX"),
            ("rss", "RSS"),
            ("github poc", "GitHub PoC"),
            ("vxug", "VXUG"),
            ("cisa", "CISA AA"),
            ("vulncheck", "VulnCheck"),
            ("triage", "Triage"),
            ("shadowserver", "Shadowsrv"),
            ("certstream", "CertStrm"),
        ):
            if token in msg:
                return label
        return None
    if stage == "enrichment":
        for token, label in (
            ("virustotal", "VT"),
            ("vt", "VT"),
            ("greynoise", "GreyNoise"),
            ("abuseipdb", "AbuseIPDB"),
            ("shodan", "Shodan"),
            ("censys", "Censys"),
            ("threatfox", "ThreatFox"),
            ("malwarebazaar", "MalBazaar"),
            ("malbazaar", "MalBazaar"),
            ("urlhaus", "URLhaus"),
            ("urlscan", "URLScan"),
            ("hybrid", "Hybrid"),
            ("rdap", "RDAP"),
            ("crt.sh", "crt.sh"),
            ("pdns", "PDNS"),
            ("spur", "Spur"),
        ):
            if token in msg:
                return label
    return None


def _compact_count(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}k"
    return str(int(value))


_API_CALLS_TAIL_BYTES = 512 * 1024
_RECENT_REQUEST_S = 8.0


def _api_label(host: str, env_values: Dict[str, str]) -> Optional[str]:
    """The panel label for a request host. Instance hosts come from the registry's env URLs."""
    return label_for_host(host, env_values)


def _read_jsonl_tail(path: Path) -> List[dict]:
    try:
        with path.open("rb") as fh:
            size = fh.seek(0, os.SEEK_END)
            fh.seek(max(0, size - _API_CALLS_TAIL_BYTES))
            raw = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    rows = []
    for line in raw.splitlines():
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _api_traffic(
    workspace: Optional[Path], since: float, env_values: Dict[str, str]
) -> Dict[str, Dict[str, float]]:
    """Per-label request counts since ``since``.

    Prefers ``logs/events.jsonl`` http events (the cycle event channel) and
    falls back to ``logs/api_calls.jsonl`` from before that channel existed.
    """
    if workspace is None:
        return {}
    logs = workspace / "logs"
    recorded = [row for row in _read_jsonl_tail(logs / "events.jsonl") if row.get("type") == "http"]
    calls = recorded or _read_jsonl_tail(logs / "api_calls.jsonl")
    traffic: Dict[str, Dict[str, float]] = {}
    for call in calls:
        try:
            ts, host, status = float(call["ts"]), str(call["host"]), int(call["status"])
        except (ValueError, TypeError, KeyError):
            continue
        if ts < since:
            continue
        label = _api_label(host, env_values)
        if label is None:
            continue
        row = traffic.setdefault(label, {"requests": 0, "ok": 0, "errors": 0, "limited": 0, "last_ts": 0.0})
        row["requests"] += 1
        if status == 429:
            row["limited"] += 1
        elif 200 <= status < 400:
            row["ok"] += 1
        else:
            row["errors"] += 1
        row["last_ts"] = max(row["last_ts"], ts)
    return traffic


def _cycle_start(events: List[TrailEvent]) -> Optional[float]:
    """Epoch seconds the latest cycle began, from its first trail line (local time)."""
    if not events:
        return None
    cycle = events[-1].cycle_id
    first = next((e for e in events if e.cycle_id == cycle), None)
    if first is None:
        return None
    try:
        return datetime.strptime(first.timestamp, "%Y-%m-%d %H:%M:%S").timestamp() - first.elapsed
    except ValueError:
        return None


def _enrichment_result(label: str, events: List[TrailEvent]) -> Optional[str]:
    """The Runner's per-service outcome line for ``label`` from the latest enrichment."""
    for event in reversed(events):
        data = event.data or {}
        if data.get("kind") == "enrichment" and enrichment_label(str(data.get("service") or "")) == label:
            summary = data.get("summary")
            if summary:
                return str(summary)
        if event.stage != "enrichment" or ": " not in event.message:
            continue
        service, outcome = event.message.split(": ", 1)
        if enrichment_label(service) == label:
            return outcome
    return None


def _traffic_line(row: Dict[str, float], now: float) -> Text:
    parts = [f"{int(row['requests'])} req", f"{int(row['ok'])} ok"]
    if row["errors"]:
        parts.append(f"{int(row['errors'])} err")
    if row["limited"]:
        parts.append(f"{int(row['limited'])} rate-limited")
    ago = max(0.0, now - row["last_ts"])
    parts.append(f"last {ago:.0f}s ago" if ago < 120 else f"last {ago / 60:.0f}m ago")
    style = "bright_red" if row["errors"] or row["limited"] else "bright_green"
    return Text(" · ".join(parts), style=style, overflow="ellipsis", no_wrap=True)


def _active_integration_lines(
    active: Optional[str],
    services: List[Tuple[str, bool, str, str]],
    current: Optional[TrailEvent],
    events: Optional[List[TrailEvent]],
    live: Optional[Dict[str, Any]],
    traffic: Optional[Dict[str, Dict[str, float]]] = None,
    now: Optional[float] = None,
) -> List[Text]:
    """Metrics for the integration in use, or the last one used, under the panel's grid.

    The monitor's layouts give this panel a fixed height and crop from the
    bottom, so these lines fill spare rows and are the first thing dropped
    when there are none.
    """
    events = events or []
    traffic = traffic or {}
    now = time.time() if now is None else now
    label, event, stage_events = active, current, []
    if label is None and traffic:
        recent, row = max(traffic.items(), key=lambda item: item[1]["last_ts"])
        if now - row["last_ts"] <= _RECENT_REQUEST_S:
            label = active = recent
    if label is None:
        for candidate in reversed(events):
            label = _detect_active_integration(candidate, events, None)
            if label:
                event = candidate
                break
    if label is None:
        return [Text("No integration in use this cycle", style="dim")]
    if event is not None:
        stage_events = [e for e in events if e.cycle_id == event.cycle_id and e.stage == event.stage]

    service = next((s for s in services if s[0] == label), None)
    detail, metric = (service[2], service[3]) if service else ("", "--")
    head = Text.assemble(
        ("NOW " if active else "LAST ", "bold black on bright_cyan" if active else "bold grey62"),
        (f" {label}", "bold bright_cyan" if active else "bold bright_white"),
        (f" · {detail}" if detail else "", "bright_white"),
        (f" · {metric}" if metric != "--" else "", "bright_cyan"),
    )
    head.no_wrap, head.overflow = True, "ellipsis"
    lines = [head]
    if label in traffic:
        lines.append(_traffic_line(traffic[label], now))
    outcome = _enrichment_result(label, events)
    if outcome:
        lines.append(Text(f"lookups: {outcome}", style="bright_cyan", overflow="ellipsis", no_wrap=True))

    facts: List[str] = []
    if event is not None:
        facts.append(f"stage {event.stage}")
        if stage_events:
            spent = max(0.0, event.elapsed - stage_events[0].elapsed)
            facts.append(f"{spent:.0f}s in stage")
            facts.append(f"{len(stage_events)} step(s)")
        if not active:
            facts.append(f"at {event.timestamp[-8:]}")
    if facts:
        lines.append(Text(" · ".join(facts), style="bright_white", overflow="ellipsis", no_wrap=True))
    if label == "LLM" and live:
        calls = int(live.get("llm_calls") or 0)
        usage = [f"{int(live.get('in_flight') or 0)} in flight", f"{calls} done"]
        if live.get("failed"):
            usage.append(f"{int(live['failed'])} failed")
        tokens_in, tokens_out = int(live.get("input_tokens") or 0), int(live.get("output_tokens") or 0)
        if tokens_in or tokens_out:
            usage.append(f"{_compact_count(tokens_in)} in / {_compact_count(tokens_out)} out tok")
        if calls and live.get("duration_ms"):
            usage.append(f"avg {int(live['duration_ms']) / calls / 1000:.1f}s/call")
        if live.get("cost_usd"):
            usage.append(f"${float(live['cost_usd']):.2f}")
        raw_tier = live.get("by_tier")
        by_tier: Dict[str, Any] = raw_tier if isinstance(raw_tier, dict) else {}
        tier_bits = []
        for name in ("simple", "complex"):
            raw_bucket = by_tier.get(name)
            bucket: Dict[str, Any] = raw_bucket if isinstance(raw_bucket, dict) else {}
            tier_calls = int(bucket.get("llm_calls") or 0)
            if tier_calls:
                tier_bits.append(f"{name} {tier_calls}")
        if tier_bits:
            usage.append(" / ".join(tier_bits))
        if live.get("escalated_calls"):
            usage.append(f"esc {int(live['escalated_calls'])}")
        models = live.get("models") or []
        if models:
            usage.append(", ".join(str(m) for m in sorted(models))[:40])
        lines.append(Text(" · ".join(usage), style="bright_cyan", overflow="ellipsis", no_wrap=True))
    if event is not None and event.message:
        lines.append(Text(event.message, style="dim", overflow="ellipsis", no_wrap=True))
    return lines


def _integrations_panel(
    workspace: Optional[Path] = None,
    search_count: str = "pending",
    narrow: bool = True,
    compact: bool = False,
    events: Optional[List[TrailEvent]] = None,
    metrics: Optional[Dict[str, Any]] = None,
    live: Optional[Dict[str, Any]] = None,
    current: Optional[TrailEvent] = None,
    grid: bool = False,
    grid_compact_names: bool = False,
) -> Panel:
    """A dedicated panel displaying external API and service integration statuses and activity metrics."""
    env_files = [workspace / ".env"] if workspace else []
    if workspace:
        env_files.append(workspace.parent / "Hecate-Runner" / ".env")
    file_keys = set()
    file_values: Dict[str, str] = {}
    for env_file in env_files:
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                key, sep, value = line.partition("=")
                if sep and value.strip().strip("\"'"):
                    env_key = key.strip().removeprefix("export ")
                    file_keys.add(env_key)
                    file_values[env_key] = value.strip().strip("\"'")
        except OSError:
            continue
    cycle_events: List[TrailEvent] = []
    if current and events:
        cycle_events = [e for e in events if e.cycle_id == current.cycle_id]
    elif events:
        last_cid = events[-1].cycle_id if events else None
        if last_cid:
            cycle_events = [e for e in events if e.cycle_id == last_cid]

    # For enrichment services, preserve metrics from the latest active cycle that performed
    # enrichment across idle polling cycles (similar to _latest_metrics for LLM calls).
    active_enrichment_events: List[TrailEvent] = cycle_events
    if not any(e.stage == "enrichment" for e in cycle_events) and events:
        for e in reversed(events):
            if e.stage == "enrichment":
                last_enrich_cid = e.cycle_id
                active_enrichment_events = [ev for ev in events if ev.cycle_id == last_enrich_cid]
                break

    services_data = []
    for item in STATUS_INTEGRATIONS:
        label, names = item.label, item.env_keys
        is_set = (
            any(os.environ.get(name) for name in names)
            or any(name in file_keys for name in names)
            or item.always_configured
        )
        if label == "LLM":
            if is_set:
                provider_name = os.environ.get("HECATE_LLM_PROVIDER")
                if not provider_name:
                    if any(os.environ.get(k) or k in file_keys for k in ("ANTHROPIC_API_KEY",)):
                        provider_name = "anthropic"
                    elif any(os.environ.get(k) or k in file_keys for k in ("OPENAI_API_KEY",)):
                        provider_name = "openai"
                    elif any(os.environ.get(k) or k in file_keys for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY")):
                        provider_name = "gemini"
                    elif any(os.environ.get(k) or k in file_keys for k in ("AWS_PROFILE",)):
                        provider_name = "bedrock"
                    else:
                        provider_name = "ollama"
                else:
                    provider_name = provider_name.lower().split()[0]
                detail = str(provider_name)
                calls = 0
                if live and live.get("llm_calls") is not None:
                    calls = int(live.get("llm_calls") or 0)
                elif metrics:
                    llm_stages = [
                        s for s in (metrics.get("stages") or []) if isinstance(s, dict) and s.get("llm_calls") is not None
                    ]
                    calls = sum(int(s.get("llm_calls") or 0) for s in llm_stages)
                metric = f"{calls} calls"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "Tavily":
            if is_set:
                detail = "web search"
                searches = None
                in_prog = False
                for e in reversed(cycle_events):
                    m = re.search(r"(\d+)\s+web\s+search(?:es|\(es\))?", e.message)
                    if m:
                        searches = int(m.group(1))
                        break
                    if e.stage == "research" and "web search on" in e.message:
                        in_prog = True
                if searches is None and not in_prog and active_enrichment_events != cycle_events:
                    for e in reversed(active_enrichment_events):
                        m = re.search(r"(\d+)\s+web\s+search(?:es|\(es\))?", e.message)
                        if m:
                            searches = int(m.group(1))
                            break
                if searches is not None:
                    metric = f"{searches} searches"
                elif in_prog:
                    metric = "searching..."
                elif search_count.isdigit():
                    metric = f"{search_count} searches"
                elif search_count in ("in progress...", "searching..."):
                    metric = "searching..."
                else:
                    metric = "0 searches"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "OTX":
            if is_set:
                detail = "feed/ioc" if narrow else "pulses"
                otx_found = any(
                    e.stage in ("intake", "route", "research")
                    and ("otx:" in e.message.lower() or "otx pulse:" in e.message.lower())
                    for e in cycle_events
                )
                if not otx_found and active_enrichment_events != cycle_events:
                    otx_found = any(
                        e.stage in ("intake", "route", "research")
                        and ("otx:" in e.message.lower() or "otx pulse:" in e.message.lower())
                        for e in active_enrichment_events
                    )
                if otx_found:
                    metric = "1 pulse"
                else:
                    obs_count = 0
                    for e in active_enrichment_events:
                        if e.stage == "enrichment":
                            m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                            if m_obs:
                                obs_count = int(m_obs.group(1))
                                break
                    if obs_count > 0:
                        metric = f"{obs_count} queries"
                    else:
                        backlog = _backlog_observation(events or [])
                        if backlog and backlog[0] > 0:
                            metric = f"{backlog[0]} queued"
                        else:
                            metric = "0 queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "MISP":
            if is_set:
                detail = "threat sharing" if narrow else "threat share"
                misp_found = any(e.stage == "intake" and "misp:" in e.message.lower() for e in cycle_events)
                if not misp_found and active_enrichment_events != cycle_events:
                    misp_found = any(e.stage == "intake" and "misp:" in e.message.lower() for e in active_enrichment_events)
                metric = "1 event" if misp_found else "0 events"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "VT":
            if is_set:
                detail = "enrichment"
                ioc_count = 0
                for e in active_enrichment_events:
                    m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                    if m_obs:
                        ioc_count = max(ioc_count, int(m_obs.group(1)))
                    m = re.search(r"(\d+)\s+indicator\(s\)", e.message)
                    if m:
                        ioc_count = max(ioc_count, int(m.group(1)))
                    m_typed = re.search(r"(\d+)/\d+\s+indicator\(s\)\s+typed", e.message)
                    if m_typed:
                        ioc_count = max(ioc_count, int(m_typed.group(1)))
                    m_intake = re.search(r"indicators:\s*([^\);]+)", e.message)
                    if m_intake and "none" not in m_intake.group(1).lower():
                        nums = [int(n) for n in re.findall(r"\b(\d+)\b", m_intake.group(1))]
                        if nums:
                            ioc_count = max(ioc_count, sum(nums))
                metric = f"{ioc_count} checked"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "GreyNoise":
            if is_set:
                detail = "noise" if narrow else "noise filter"
                ip_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                    if m:
                        ip_count = max(ip_count, int(m.group(1)))
                metric = f"{ip_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "AbuseIPDB":
            if is_set:
                detail = "ip abuse"
                ip_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                    if m:
                        ip_count = max(ip_count, int(m.group(1)))
                metric = f"{ip_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "Shodan":
            if is_set:
                detail = "recon"
                ip_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                    if m:
                        ip_count = max(ip_count, int(m.group(1)))
                metric = f"{ip_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "Censys":
            if is_set:
                detail = "surface" if narrow else "attack surface"
                ip_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                    if m:
                        ip_count = max(ip_count, int(m.group(1)))
                metric = f"{ip_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "ThreatFox":
            if is_set:
                detail = "abuse.ch"
                tf_count = 0
                for e in active_enrichment_events:
                    if e.stage == "enrichment":
                        m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                        if m_obs:
                            tf_count = int(m_obs.group(1))
                            break
                    m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                    if m_obs:
                        tf_count = max(tf_count, int(m_obs.group(1)))
                    elif tf_count == 0:
                        m_ind = re.search(r"(\d+)\s+indicator\(s\)", e.message, re.IGNORECASE)
                        if m_ind:
                            tf_count = max(tf_count, int(m_ind.group(1)))
                metric = f"{tf_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "MalBazaar":
            if is_set:
                detail = "malware"
                hash_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+hash", e.message, re.IGNORECASE)
                    if m:
                        hash_count = max(hash_count, int(m.group(1)))
                metric = f"{hash_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label in ("Feodo C2", "Feodo"):
            detail = "botnet c2" if narrow else "botnet"
            ip_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                if m:
                    ip_count = max(ip_count, int(m.group(1)))
            metric = f"{ip_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "SSLBL":
            detail = "ssl/ja3"
            hash_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+hash", e.message, re.IGNORECASE)
                if m:
                    hash_count = max(hash_count, int(m.group(1)))
            metric = f"{hash_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "URLhaus":
            if is_set:
                detail = "urls" if narrow else "malware urls"
                url_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+url", e.message, re.IGNORECASE)
                    if m:
                        url_count = max(url_count, int(m.group(1)))
                metric = f"{url_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "URLScan":
            has_key = any(os.environ.get(name) for name in names) or any(name in file_keys for name in names)
            detail = "web lures" if has_key else "lures"
            url_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+url", e.message, re.IGNORECASE)
                if m:
                    url_count = max(url_count, int(m.group(1)))
            metric = f"{url_count} scans"
            services_data.append((label, True, detail, metric))
        elif label == "Hybrid":
            if is_set:
                detail = "sandbox"
                hash_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+hash", e.message, re.IGNORECASE)
                    if m:
                        hash_count = max(hash_count, int(m.group(1)))
                metric = f"{hash_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "RDAP":
            detail = "whois/age"
            dom_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+domain", e.message, re.IGNORECASE)
                if m:
                    dom_count = max(dom_count, int(m.group(1)))
            metric = f"{dom_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "crt.sh":
            detail = "ct logs"
            dom_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+domain", e.message, re.IGNORECASE)
                if m:
                    dom_count = max(dom_count, int(m.group(1)))
            metric = f"{dom_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "PDNS":
            detail = "passive dns"
            obs_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                if m:
                    obs_count = max(obs_count, int(m.group(1)))
            metric = f"{obs_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "Spur":
            if is_set:
                detail = "proxy/vpn"
                ip_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                    if m:
                        ip_count = max(ip_count, int(m.group(1)))
                metric = f"{ip_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "Tor/Proxy":
            detail = "tor/vpn"
            ip_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                if m:
                    ip_count = max(ip_count, int(m.group(1)))
            metric = f"{ip_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "EPSS":
            detail = "cve score" if narrow else "exploit prediction"
            cve_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+cve", e.message, re.IGNORECASE)
                if m:
                    cve_count = max(cve_count, int(m.group(1)))
            metric = f"{cve_count} CVEs"
            services_data.append((label, True, detail, metric))
        elif label in ("OSV.dev", "OSV"):
            detail = "supply chain" if narrow else "osv/pkg"
            cve_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+cve", e.message, re.IGNORECASE)
                if m:
                    cve_count = max(cve_count, int(m.group(1)))
            metric = f"{cve_count} CVEs"
            services_data.append((label, True, detail, metric))
        elif label == "Slack":
            if is_set:
                detail = "alerts"
                draft_created = any("draft_created" in e.message for e in cycle_events)
                if not draft_created and active_enrichment_events != cycle_events:
                    draft_created = any("draft_created" in e.message for e in active_enrichment_events)
                metric = "1 sent" if draft_created else "0 sent"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "VulnCheck":
            if is_set:
                detail = "kev/cve" if narrow else "kev exploit"
                cve_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+cve", e.message, re.IGNORECASE)
                    if m:
                        cve_count = max(cve_count, int(m.group(1)))
                metric = f"{cve_count} KEVs" if cve_count > 0 else "active"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "Triage":
            if is_set:
                detail = "sandbox"
                metric = "active"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "Shadowsrv":
            if is_set:
                detail = "c2/botnet"
                metric = "active"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "MSRC":
            detail = "cvrf/cve"
            cve_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+cve", e.message, re.IGNORECASE)
                if m:
                    cve_count = max(cve_count, int(m.group(1)))
            metric = f"{cve_count} CVEs" if cve_count > 0 else "advisories"
            services_data.append((label, True, detail, metric))
        elif label == "CloudThrt":
            detail = "iam/cloud"
            metric = "3 feeds"
            services_data.append((label, True, detail, metric))
        elif label == "DFIR Rept":
            detail = "reports"
            metric = "feed"
            services_data.append((label, True, detail, metric))
        elif label == "FIRST.org":
            detail = "epss spike"
            metric = "active"
            services_data.append((label, True, detail, metric))
        elif label == "ANY.RUN":
            detail = "sandbox"
            metric = "active"
            services_data.append((label, True, detail, metric))
        elif label == "OpenCTI":
            detail = "stix/intel"
            metric = "active"
            services_data.append((label, True, detail, metric))

    env_values = {**file_values, **os.environ}
    provider = env_values.get("HECATE_RUNNER_CTI_PROVIDER", "file")
    active_sources = set(env_values.get("HECATE_RUNNER_CTI_MULTI_PROVIDERS", "rss,otx,misp").replace(" ", "").split(",")) if provider == "multi" else {provider}
    for item in SOURCE_INTEGRATIONS:
        services_data.append((item.label, True, "source", "--"))
    confirmed_data = []
    for label, configured, detail, metric in services_data:
        item = BY_LABEL[label]
        name = item.id
        source_name = item.cti_name
        enabled = source_name in active_sources if item.follows_cti_provider else configured
        if name == "misp" and str(env_values.get("HECATE_RUNNER_MISP_PUBLISHING_ENABLED", "false")).lower() in {"true", "1", "yes", "on"}:
            name, enabled = "misp_output", True
            detail = "output only" if source_name not in active_sources else "input/output"
        if name == "slack" and str(env_values.get("HECATE_RUNNER_SLACK_INTERACTIVE_ENABLED", "false")).lower() not in {"true", "1", "yes", "on"}:
            detail = "output only"
        ok, reason = _confirmed_integration(workspace, name, enabled)
        confirmed_data.append((label, ok, detail if ok else reason, metric))
    active_integration = _detect_active_integration(current, events, live)
    confirmed_data.sort(key=lambda item: (_color_group_rank(item[1], item[2]), item[0].lower()))
    services_data = confirmed_data

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    if grid:
        # The wide dashboard places this panel beside other detail panels.
        # Use a compact grid so every configured integration remains visible.
        for column in ("one", "two", "three", "four"):
            table.add_column(column, ratio=1, overflow="ellipsis", no_wrap=True)
        aliases = {
            "GreyNoise": "GreyN",
            "AbuseIPDB": "Abuse",
            "ThreatFox": "ThrtFx",
            "MalBazaar": "MalBzr",
            "Feodo C2": "Feodo",
            "Tor/Proxy": "TorPrx",
            "VulnCheck": "VulnCh",
            "DFIR Rept": "DFIR",
            "FIRST.org": "FIRST",
            "URLhaus": "URLhs",
            "URLScan": "URLScn",
            "OSV.dev": "OSVdev",
        }
        display_items = [
            (
                aliases.get(label, label) if grid_compact_names else label,
                is_set,
                detail,
                label == active_integration,
            )
            for label, is_set, detail, _ in services_data
        ]
        for start in range(0, len(display_items), 4):
            row = [
                Text(
                    f" {label} " if is_active else label,
                    style="bold black on bright_cyan"
                    if is_active
                    else _integration_style(ok, detail),
                )
                for label, ok, detail, is_active in display_items[start : start + 4]
            ]
            row.extend(Text("") for _ in range(4 - len(row)))
            table.add_row(*row)
    elif narrow:
        table.add_column("label", style="dim", width=11, no_wrap=True)
        table.add_column("status", ratio=1, overflow="ellipsis", no_wrap=True)
        table.add_column("metric", justify="right", width=11, no_wrap=True)
        for label, is_set, detail, metric in services_data:
            is_active = (label == active_integration)
            if is_active:
                lbl_style = "bold black on bright_cyan"
                st = Text.assemble(("ACTIVE", "bold black on bright_cyan"), (" · ", "dim"), (detail, "bright_white"))
                m_style = "bold bright_cyan"
            elif is_set:
                lbl_style = "dim"
                st = Text.assemble(("ON", _integration_style(True, detail)), (" · ", "dim"), (detail, "bright_white"))
                m_style = "bright_cyan" if metric != "--" else "dim"
            else:
                lbl_style = "dim"
                st = Text.assemble(("OFF", _integration_style(False, detail)), (" · ", "dim"), (detail, "dim"))
                m_style = "dim"
            table.add_row(Text(label, style=lbl_style), st, Text(metric, style=m_style))
    else:

        def format_item(lbl: str, is_on: bool, det: str, met: str) -> Text:
            is_active = (lbl == active_integration)
            if is_active:
                lbl_style = "bold black on bright_cyan"
                st = "ACTIVE"
                col = "bold black on bright_cyan"
                m_col = "bold bright_cyan"
            else:
                lbl_style = "dim"
                st = "ON" if is_on else "OFF"
                col = _integration_style(is_on, det)
                m_col = "bright_cyan" if is_on and met != "--" else "dim"
            return Text.assemble(
                (f"{lbl:<9}", lbl_style),
                (" ", "default"),
                (st, col),
                (" · ", "dim"),
                (f"{det[:7]:<7}", "bright_white" if is_on else "dim"),
                (" ", "default"),
                (f"{met:>9}", m_col),
            )

        table = Table(box=None, show_header=False, expand=True, padding=(0, 0))
        table.add_column("col1", ratio=1, no_wrap=True)
        table.add_column("col2", ratio=1, no_wrap=True)
        pairs = [
            (services_data[i], services_data[i + 1] if i + 1 < len(services_data) else None)
            for i in range(0, len(services_data), 2)
        ]
        for d1, d2 in pairs:
            if d2:
                table.add_row(format_item(*d1), format_item(*d2))
            else:
                table.add_row(format_item(*d1), Text(""))

    body: Any = table
    if not compact:
        traffic = _api_traffic(workspace, _cycle_start(events or []) or time.time() - 3600, env_values)
        body = _SpareRows(
            table,
            _active_integration_lines(active_integration, services_data, current, events, live, traffic),
        )
    return Panel(body, title="[bold bright_cyan]INTEGRATIONS[/]", border_style="bright_magenta", box=box.ROUNDED)


class _SpareRows:
    """``main``, then as many of ``extra`` as fit below it in a height-bounded region.

    With no height bound (printed, not in a layout) only ``main`` renders, so the
    panel is never taller than its integrations.
    """

    def __init__(self, main: Any, extra: List[Text]) -> None:
        self.main, self.extra = main, extra

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        lines = console.render_lines(self.main, options.update(height=None), pad=False)
        yield from _as_lines(lines)
        spare = (options.height or 0) - len(lines)
        if spare < 2 or not self.extra:
            return
        yield from _as_lines(console.render_lines(Rule(style="grey35"), options.update(height=None)))
        for line in self.extra[: spare - 1]:
            yield line

    def __rich_measure__(self, console: Console, options: ConsoleOptions) -> Measurement:
        return Measurement.get(console, options, self.main)


def _as_lines(lines: List[List[Segment]]) -> RenderResult:
    for line in lines:
        yield from line
        yield Segment.line()
