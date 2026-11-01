"""Integration panels and credential status for monitor UI."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hecate_agent.commands.monitor_samplers import TrailEvent

def _backlog_observation(events: List[TrailEvent]) -> Optional[Tuple[int, str]]:
    for event in reversed(events):
        match = re.search(r"(\d+) high-signal waiting in its backlog", event.message)
        if match:
            return int(match.group(1)), event.timestamp[-8:]
    return None



def _credential_status(workspace: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    """Return lists of active (configured) and inactive service labels."""
    checks = (
        (
            "LLM",
            (
                "HECATE_LLM_PROVIDER",
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "GEMINI_API_KEY",
                "GOOGLE_API_KEY",
                "AWS_PROFILE",
                "OLLAMA_HOST",
            ),
        ),
        ("Tavily", ("TAVILY_API_KEY",)),
        ("OTX", ("OTX_API_KEY",)),
        ("MISP", ("MISP_API_KEY",)),
        ("VT", ("HECATE_RUNNER_VT_API_KEY", "VT_API_KEY")),
        ("GreyNoise", ("GREYNOISE_API_KEY",)),
        ("AbuseIPDB", ("ABUSEIPDB_API_KEY",)),
        ("Shodan", ("SHODAN_API_KEY",)),
        ("Censys", ("CENSYS_API_TOKEN",)),
        ("ThreatFox", ("ABUSECH_API_KEY",)),
        ("MalBazaar", ("ABUSECH_API_KEY",)),
        ("VulnCheck", ("VULNCHECK_API_KEY",)),
        ("Triage", ("TRIAGE_API_KEY", "HATCHING_TRIAGE_API_KEY")),
        ("Shadowserver", ("SHADOWSERVER_API_KEY",)),
        ("ANY.RUN", ("ANYRUN_API_KEY",)),
        ("OpenCTI", ("OPENCTI_TOKEN", "OPENCTI_URL")),
        ("Slack", ("SLACK_BOT_TOKEN", "HECATE_RUNNER_SLACK_WEBHOOK_URL", "SLACK_WEBHOOK_URL")),
    )
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


_INTEGRATION_IDS = {
    "LLM": "llm", "Tavily": "tavily", "OTX": "otx", "MISP": "misp", "VT": "vt",
    "GreyNoise": "greynoise", "AbuseIPDB": "abuseipdb", "Shodan": "shodan", "Censys": "censys",
    "ThreatFox": "threatfox", "MalBazaar": "malwarebazaar", "Feodo C2": "feodo", "SSLBL": "sslbl",
    "URLhaus": "urlhaus", "URLScan": "urlscan", "Hybrid": "hybrid", "RDAP": "rdap", "crt.sh": "crtsh",
    "PDNS": "pdns", "Spur": "spur", "Tor/Proxy": "tor_proxy", "EPSS": "epss", "OSV.dev": "osv",
    "Slack": "slack", "VulnCheck": "vulncheck", "Triage": "triage", "Shadowsrv": "shadowserver",
    "MSRC": "msrc", "CloudThrt": "cloud_threat", "DFIR Rept": "dfir_report", "FIRST.org": "first_org",
    "ANY.RUN": "anyrun", "OpenCTI": "opencti", "LOLBAS": "lolbas", "LOLDrivers": "loldrivers",
    "GTFOBins": "gtfobins", "Nuclei": "nuclei", "CISA AA": "cisa_narrative", "CISA CSAF": "cisa_advisories",
    "CISA ICS": "cisa_ics", "ATT&CK": "attack_deltas", "CISA KEV": "cisa_kev",
    "RSS": "rss", "GitHub PoC": "github_poc", "VXUG": "vxunderground", "CertStrm": "certstream",
}
_SOURCE_INTEGRATIONS = {
    "otx", "misp", "vulncheck", "triage", "shadowserver", "msrc", "cloud_threat", "dfir_report",
    "first_org", "anyrun", "opencti", "lolbas", "loldrivers", "gtfobins", "nuclei",
    "cisa_advisories", "cisa_ics", "attack_deltas", "cisa_kev", "rss", "github_poc", "vxunderground", "certstream",
}


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
    checks = (
        (
            "LLM",
            (
                "HECATE_LLM_PROVIDER",
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "GEMINI_API_KEY",
                "GOOGLE_API_KEY",
                "AWS_PROFILE",
                "OLLAMA_HOST",
            ),
        ),
        ("Tavily", ("TAVILY_API_KEY",)),
        ("OTX", ("OTX_API_KEY",)),
        ("MISP", ("MISP_API_KEY",)),
        ("VT", ("HECATE_RUNNER_VT_API_KEY", "VT_API_KEY")),
        ("GreyNoise", ("GREYNOISE_API_KEY",)),
        ("AbuseIPDB", ("ABUSEIPDB_API_KEY",)),
        ("Shodan", ("SHODAN_API_KEY",)),
        ("Censys", ("CENSYS_API_TOKEN",)),
        ("ThreatFox", ("ABUSECH_API_KEY",)),
        ("MalBazaar", ("ABUSECH_API_KEY",)),
        ("Feodo C2", ()),
        ("SSLBL", ()),
        ("URLhaus", ("ABUSECH_API_KEY",)),
        ("URLScan", ("URLSCAN_API_KEY",)),
        ("Hybrid", ("HYBRID_ANALYSIS_API_KEY", "HA_API_KEY", "FALCON_SANDBOX_API_KEY")),
        ("RDAP", ()),
        ("crt.sh", ()),
        ("PDNS", ("VT_API_KEY", "MNEMONIC_API_KEY", "OTX_API_KEY")),
        ("Spur", ("SPUR_API_KEY",)),
        ("Tor/Proxy", ("IPINFO_TOKEN", "IPINFO_API_KEY")),
        ("EPSS", ()),
        ("OSV.dev", ()),
        ("Slack", ("SLACK_BOT_TOKEN", "HECATE_RUNNER_SLACK_WEBHOOK_URL", "SLACK_WEBHOOK_URL")),
        ("VulnCheck", ("VULNCHECK_API_KEY",)),
        ("Triage", ("TRIAGE_API_KEY", "HATCHING_TRIAGE_API_KEY")),
        ("Shadowsrv", ("SHADOWSERVER_API_KEY",)),
        ("MSRC", ()),
        ("CloudThrt", ()),
        ("DFIR Rept", ()),
        ("FIRST.org", ()),
        ("ANY.RUN", ("ANYRUN_API_KEY",)),
        ("OpenCTI", ("OPENCTI_TOKEN", "OPENCTI_URL")),
    )
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
    for label, names in checks:
        is_set = (
            any(os.environ.get(name) for name in names)
            or any(name in file_keys for name in names)
            or (
                label
                in (
                    "RDAP",
                    "EPSS",
                    "OSV.dev",
                    "Feodo C2",
                    "SSLBL",
                    "Feodo/SSLBL",
                    "URLScan",
                    "crt.sh",
                    "PDNS",
                    "Tor/Proxy",
                    "MSRC",
                    "CloudThrt",
                    "DFIR Rept",
                    "FIRST.org",
                    "ANY.RUN",
                    "OpenCTI",
                )
            )
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
    for label in ("LOLBAS", "LOLDrivers", "GTFOBins", "Nuclei", "CISA AA", "CISA CSAF", "CISA ICS", "ATT&CK", "CISA KEV", "RSS", "GitHub PoC", "VXUG", "CertStrm"):
        services_data.append((label, True, "source", "--"))
    confirmed_data = []
    for label, configured, detail, metric in services_data:
        name = _INTEGRATION_IDS[label]
        source_name = "cisa_advisories" if name == "cisa_narrative" else name
        enabled = source_name in active_sources if source_name in _SOURCE_INTEGRATIONS else configured
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

    return Panel(table, title="[bold bright_cyan]INTEGRATIONS[/]", border_style="bright_magenta", box=box.ROUNDED)
