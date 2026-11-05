"""Metrics collection and aggregation for Hecate pipeline monitor."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from hecate_agent.commands.monitor_samplers import TrailEvent

logger = logging.getLogger(__name__)


@dataclass
class HuntsMetrics:
    total_hunts: int = 0
    drafts_count: int = 0
    active_count: int = 0
    completed_count: int = 0
    threats_count: int = 0
    actors_count: int = 0
    campaigns_count: int = 0
    malware_count: int = 0
    ttps_count: int = 0
    sigma_rules_count: int = 0
    network_total: int = 0
    network_ips: int = 0
    network_domains: int = 0
    network_urls: int = 0
    host_total: int = 0
    host_hashes: int = 0
    host_paths: int = 0
    enterprise_ttps: Dict[str, int] = field(default_factory=dict)
    cloud_ttps: Dict[str, int] = field(default_factory=dict)
    containers_ttps: Dict[str, int] = field(default_factory=dict)
    mobile_ttps: Dict[str, int] = field(default_factory=dict)
    ics_ttps: Dict[str, int] = field(default_factory=dict)
    tactic_hunts: Dict[str, Dict[str, int]] = field(default_factory=dict)
    tactic_rules: Dict[str, Dict[str, int]] = field(default_factory=dict)
    tactic_iocs: Dict[str, Dict[str, int]] = field(default_factory=dict)
    matrix_hunts: Dict[str, int] = field(default_factory=dict)
    matrix_rules: Dict[str, int] = field(default_factory=dict)
    matrix_iocs: Dict[str, int] = field(default_factory=dict)
    enterprise_total: int = 0
    cloud_total: int = 0
    containers_total: int = 0
    mobile_total: int = 0
    ics_total: int = 0
    grounding_asserted: int = 0
    grounding_corroborated: int = 0
    grounding_derived: int = 0
    grounding_unsupported: int = 0
    fingerprints_count: int = 0
    cloud_ops_count: int = 0


_EXCLUDED_HUNT_DOCS = {"README.md", "FORMAT_GUIDELINES.md", "INDEX.md", "AGENTS.md", "WEEKLY_SUMMARY_TEMPLATE.md"}
_RE_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_HEX = re.compile(r"^[a-fA-F0-9]{32,64}$")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|ru|cn|io|top|biz|info|cc|co|kg|lv|dev|online|store|site|club|app|vip|pro|mobi|tech)\b",
    re.IGNORECASE,
)
_RE_ACTOR_ROW = re.compile(r"\|\s*\*\*Actor\*\*\s*\|\s*([^|\n]+)\|")
_RE_THREAT_CONTEXT = re.compile(r"\*\*Threat(?:\s+Actor)?:\*\*\s*([^\n]+)")
_RE_GROUNDING_ENTITY = re.compile(r"\|\s*`([^`]+)`\s*\|\s*entity\s*\|\s*asserted by CTI")
_RE_GROUNDING_SUMMARY = re.compile(
    r"\*(\d+)\s+asserted(?: by CTI)?\s*·\s*(\d+)\s+(?:research-only|corroborated)\s*·\s*(\d+)\s+(?:inferred|derived)\s*·\s*(\d+)\s+unsupported\*",
    re.IGNORECASE,
)
_RE_ROLE_INDICATOR = re.compile(r"\|\s*`([^`]+)`\s*\|\s*([\w_]+)\s*\|")
_RE_MALWARE_TERMS = re.compile(
    r"\b(trojan|ransomware|stealer|loader|backdoor|rat|botnet|wiper|rootkit|infostealer|dropper|implant|spyware|worm|malware|keylogger|miner|vshell)\b",
    re.I,
)
_RE_CAMEL_MALWARE = re.compile(r"\b[A-Z][a-z0-9]+(?:RAT|Bot|Loader|Stealer|Locker)\b")
_RE_ACTOR_TERMS = re.compile(
    r"\b(apt\d+|fin\d+|unc\d+|ta\d+|storm-\d+|group|team|crew|cartel|operators?|syndicate|threat cluster)\b",
    re.I,
)
_RE_CAMPAIGN_TERMS = re.compile(
    r"\b(campaign|operation|op\s+[a-z0-9_-]+)\b",
    re.I,
)
_GENERIC_THREAT_NAMES = {
    "unknown",
    "none",
    "n/a",
    "various",
    "threat actor",
    "adversary",
    "unspecified",
    "tbd",
    "actor",
    "attacker",
    "malware",
    "not specified",
    "hkcu",
    "hklm",
}

_HUNTS_METRICS_CACHE: Dict[Path, Tuple[float, int, float, HuntsMetrics]] = {}


def _collect_hunts_metrics(workspace: Optional[Path] = None) -> HuntsMetrics:
    """Collect summary metrics across all hunt drafts in the workspace."""
    if not workspace:
        return HuntsMetrics()

    hunts_dir = workspace / "hunts"
    is_eval_or_special = (
        "/tmp/eval_runs" in str(workspace.resolve())
        or "eval" in workspace.name.lower()
        or workspace == Path("/home/chemch/betas")
    )
    if not (hunts_dir.exists() and hunts_dir.is_dir()) and is_eval_or_special:
        alt_candidates = [
            Path("/home/chemch/betas/Hecate-Workspace/hunts"),
            Path.home() / "betas" / "Hecate-Workspace" / "hunts",
            workspace.parent / "Hecate-Workspace" / "hunts",
        ]
        for alt in alt_candidates:
            if alt.exists() and alt.is_dir():
                hunts_dir = alt
                break

    if not hunts_dir or not hunts_dir.exists() or not hunts_dir.is_dir():
        return HuntsMetrics()

    resolved_path = hunts_dir.resolve()
    now = time.monotonic()
    cached = _HUNTS_METRICS_CACHE.get(resolved_path)

    if cached is not None and (now - cached[0] < 10.0):
        return cached[3]

    try:
        hunt_files = sorted(f for f in hunts_dir.rglob("*.md") if f.name not in _EXCLUDED_HUNT_DOCS)
    except OSError:
        hunt_files = []

    if not hunt_files:
        return HuntsMetrics()

    file_count = len(hunt_files)
    queries_dir = workspace / "queries"
    if not queries_dir.is_dir():
        queries_dir = hunts_dir.parent / "queries"
    try:
        sigma_files = sorted(p for p in queries_dir.rglob("*") if p.suffix.lower() in {".yml", ".yaml"} and p.is_file())
    except OSError:
        sigma_files = []
    fingerprint_count = file_count + len(sigma_files)

    try:
        max_mtime = max((f.stat().st_mtime for f in [*hunt_files, *sigma_files]), default=0.0)
    except OSError:
        max_mtime = 0.0

    if cached is not None and cached[1] == fingerprint_count and cached[2] == max_mtime:
        _HUNTS_METRICS_CACHE[resolved_path] = (now, fingerprint_count, max_mtime, cached[3])
        return cached[3]

    drafts_count = 0
    active_count = 0
    completed_count = 0
    actors: Set[str] = set()
    campaigns: Set[str] = set()
    malware: Set[str] = set()
    techniques: Set[str] = set()
    network_ips: Set[str] = set()
    network_domains: Set[str] = set()
    network_urls: Set[str] = set()
    host_hashes: Set[str] = set()
    host_paths: Set[str] = set()
    fingerprints: Set[str] = set()
    cloud_ops: Set[str] = set()
    grounding_asserted = 0
    grounding_corroborated = 0
    grounding_derived = 0
    grounding_unsupported = 0
    tactic_hunts: Dict[str, Dict[str, int]] = {}
    tactic_rules: Dict[str, Dict[str, int]] = {}
    tactic_iocs: Dict[str, Dict[str, int]] = {}
    matrix_hunts: Dict[str, int] = {}
    matrix_rules: Dict[str, int] = {}
    matrix_iocs: Dict[str, int] = {}

    from hecate_agent.core.attack_matrix import canonical_tactic, categorize_techniques_by_matrix

    classifications: Dict[frozenset[str], Dict[str, Any]] = {}

    def record_tactic_document(
        ids: Set[str],
        counts: Dict[str, Dict[str, int]],
        totals: Dict[str, int],
        declared: Optional[Set[str]] = None,
        weight: int = 1,
    ) -> None:
        key = frozenset(ids)
        if key not in classifications:
            classifications[key] = categorize_techniques_by_matrix(ids)
        classified = classifications[key]
        active = {
            domain: {tactic for tactic, count in classified.get(domain, {}).items() if count}
            for domain in ("enterprise", "cloud", "containers", "mobile", "ics")
        }
        if declared and not any(active.values()):
            active["enterprise"].update(
                canonical_tactic(tactic) for tactic in declared
                if canonical_tactic(tactic) in classified.get("enterprise", {})
            )
        for domain, tactics in active.items():
            if tactics:
                totals[domain] = totals.get(domain, 0) + weight
            for tactic in tactics:
                domain_counts = counts.setdefault(domain, {})
                domain_counts[tactic] = domain_counts.get(tactic, 0) + weight

    from hecate_agent.core.grounding import _ACRONYM_STOPWORDS

    def _is_valid_threat(val: str) -> bool:
        if not val or len(val) < 2:
            return False
        lowered = val.lower()
        if lowered in _GENERIC_THREAT_NAMES or lowered in _ACRONYM_STOPWORDS:
            return False
        if lowered.startswith("[review") or lowered.startswith("review cti"):
            return False
        if "/" in val or "\\" in val:
            return False
        if _RE_HEX.match(val) or _RE_IP.match(val):
            return False
        return True

    def _record_threat(name: str, hint: str = "") -> None:
        clean = name.strip().strip("*_`# ")
        if not _is_valid_threat(clean):
            return
        if _RE_ACTOR_TERMS.search(clean) or hint == "actor":
            actors.add(clean)
        elif _RE_CAMPAIGN_TERMS.search(clean) or hint == "campaign":
            campaigns.add(clean)
        elif _RE_MALWARE_TERMS.search(clean) or _RE_CAMEL_MALWARE.search(clean) or hint == "malware":
            malware.add(clean)
        elif hint == "attribution":
            actors.add(clean)
        else:
            malware.add(clean)

    for hunt_file in hunt_files:
        try:
            text = hunt_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        hunt_techniques: Set[str] = set()
        hunt_iocs: Set[str] = set()
        m_fm = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
        if m_fm:
            try:
                fm = yaml.safe_load(m_fm.group(1)) or {}
                st = str(fm.get("status", "")).lower()
                if st in {"active", "in_progress", "in-progress"}:
                    active_count += 1
                elif st in {"completed", "done", "closed"}:
                    completed_count += 1
                else:
                    drafts_count += 1

                for t in fm.get("techniques", []):
                    t_str = str(t).strip()
                    if _RE_TECHNIQUE.match(t_str):
                        techniques.add(t_str)
                        hunt_techniques.add(t_str)

                for k in ("threat", "threat_actor", "actor"):
                    val = fm.get(k)
                    if val and isinstance(val, str):
                        for p in re.split(r",\s*|\s*;\s*|\s+and\s+", val):
                            _record_threat(p, hint="attribution")
            except Exception:
                drafts_count += 1
        else:
            drafts_count += 1

        m_act = _RE_ACTOR_ROW.search(text)
        if m_act:
            for p in re.split(r",\s*|\s*;\s*|\s+and\s+", m_act.group(1)):
                _record_threat(p, hint="actor")

        m_ta = _RE_THREAT_CONTEXT.search(text)
        if m_ta:
            for p in re.split(r",\s*|\s*;\s*|\s+and\s+", m_ta.group(1)):
                _record_threat(p, hint="attribution")

        m_tags = re.search(r"Tags:\s*([^\n]+)", text)
        if m_tags:
            for tag in m_tags.group(1).split(","):
                clean_tag = tag.strip().strip("*_`# ")
                if _is_valid_threat(clean_tag):
                    if _RE_CAMPAIGN_TERMS.search(clean_tag):
                        campaigns.add(clean_tag)
                    elif _RE_MALWARE_TERMS.search(clean_tag) or _RE_CAMEL_MALWARE.search(clean_tag):
                        malware.add(clean_tag)

        for m_ge in _RE_GROUNDING_ENTITY.finditer(text):
            _record_threat(m_ge.group(1).strip())

        for m_ir in _RE_ROLE_INDICATOR.finditer(text):
            val, itype = m_ir.group(1).strip(), m_ir.group(2).lower()
            if itype in {"malware_family", "malware"}:
                _record_threat(val, hint="malware")
            elif itype in {"threat_actor", "actor"}:
                _record_threat(val, hint="actor")
            elif itype == "campaign":
                _record_threat(val, hint="campaign")
            elif itype in {"ip", "ipv4", "ipv6"}:
                clean_ip = val.replace("[", "").replace("]", "")
                if _RE_IP.match(clean_ip):
                    network_ips.add(clean_ip)
                    hunt_iocs.add(clean_ip)
            elif itype in {"domain", "hostname"}:
                clean_dom = val.replace("[", "").replace("]", "").lower()
                network_domains.add(clean_dom)
                hunt_iocs.add(clean_dom)
            elif itype == "url":
                clean_url = val.replace("[", "").replace("]", "")
                network_urls.add(clean_url)
                hunt_iocs.add(clean_url)
            elif itype in {"hash", "file_hash", "sha256", "md5", "sha1"}:
                clean_hsh = val.lower()
                host_hashes.add(clean_hsh)
                hunt_iocs.add(clean_hsh)
            elif itype in {"file_path", "path", "file", "registry", "process"}:
                host_paths.add(val)
                hunt_iocs.add(val)
            elif itype in {"ja4", "jarm", "ssl_fingerprint", "tls_hash", "fingerprint"}:
                fingerprints.add(val.lower())
                hunt_iocs.add(val.lower())
            elif itype in {"iam_operation", "cloud_role", "k8s_action", "cloud_action"}:
                cloud_ops.add(val)
                hunt_iocs.add(val)

        m_ioc = re.search(r"###\s+Indicators of Compromise.*?(?=\n###\s+[A-Z]|\n## |\Z)", text, re.DOTALL | re.IGNORECASE)
        if m_ioc:
            ioc_txt = m_ioc.group(0)
            for ip in _RE_IP.findall(ioc_txt):
                network_ips.add(ip)
                hunt_iocs.add(ip)
            for d in _RE_DOMAIN.findall(ioc_txt):
                clean_d = d.lower()
                network_domains.add(clean_d)
                hunt_iocs.add(clean_d)
            for hsh in _RE_SHA256.findall(ioc_txt):
                clean_h = hsh.lower()
                host_hashes.add(clean_h)
                hunt_iocs.add(clean_h)
            for hsh in _RE_MD5.findall(ioc_txt):
                clean_h = hsh.lower()
                host_hashes.add(clean_h)
                hunt_iocs.add(clean_h)
            for hsh in _RE_SHA1.findall(ioc_txt):
                clean_h = hsh.lower()
                host_hashes.add(clean_h)
                hunt_iocs.add(clean_h)
            m_fp = re.search(r"####\s+File Paths.*?(?=####|\Z)", ioc_txt, re.DOTALL | re.IGNORECASE)
            if m_fp:
                for p in re.findall(r"`([^`]+)`", m_fp.group(0)):
                    host_paths.add(p)
                    hunt_iocs.add(p)

        record_tactic_document(hunt_techniques, tactic_hunts, matrix_hunts, weight=1)
        record_tactic_document(hunt_techniques, tactic_iocs, matrix_iocs, weight=len(hunt_iocs))

        m_gs = _RE_GROUNDING_SUMMARY.search(text)
        if m_gs:
            grounding_asserted += int(m_gs.group(1))
            grounding_corroborated += int(m_gs.group(2))
            grounding_derived += int(m_gs.group(3))
            grounding_unsupported += int(m_gs.group(4))
        else:
            m_gsec = re.search(r"###\s+Grounding.*?(?=\n###\s+[A-Z]|\n## |\Z)", text, re.DOTALL | re.IGNORECASE)
            if m_gsec:
                for line in m_gsec.group(0).splitlines():
                    if not line.startswith("|") or "---" in line or "Claim" in line:
                        continue
                    l_lower = line.lower()
                    if "unsupported" in l_lower:
                        grounding_unsupported += 1
                    elif "asserted" in l_lower:
                        grounding_asserted += 1
                    elif "inferred" in l_lower or "derived" in l_lower:
                        grounding_derived += 1
                    elif "research" in l_lower or "corroborated" in l_lower:
                        grounding_corroborated += 1

    actors.difference_update(malware | campaigns)
    all_threats = actors | campaigns | malware

    sigma_rules_count = len(sigma_files)
    for rule_file in sigma_files:
        try:
            rule = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
            if not isinstance(rule, dict) or not isinstance(rule.get("tags"), list):
                continue
            tags = [str(tag) for tag in rule["tags"] if str(tag).lower().startswith("attack.")]
            rule_techniques = {technique for tag in tags for technique in _RE_TECHNIQUE.findall(tag.upper())}
            declared_tactics = {tag.split(".", 1)[1].lower().replace("_", "-") for tag in tags}
            record_tactic_document(rule_techniques, tactic_rules, matrix_rules, declared_tactics)
        except (OSError, UnicodeError, yaml.YAMLError):
            continue

    cat_metrics = categorize_techniques_by_matrix(techniques)

    metrics = HuntsMetrics(
        total_hunts=file_count,
        drafts_count=drafts_count,
        active_count=active_count,
        completed_count=completed_count,
        threats_count=len(all_threats),
        actors_count=len(actors),
        campaigns_count=len(campaigns),
        malware_count=len(malware),
        ttps_count=len(techniques),
        sigma_rules_count=sigma_rules_count,
        network_total=len(network_ips | network_domains | network_urls),
        network_ips=len(network_ips),
        network_domains=len(network_domains),
        network_urls=len(network_urls),
        host_total=len(host_hashes | host_paths),
        host_hashes=len(host_hashes),
        host_paths=len(host_paths),
        enterprise_ttps=cat_metrics.get("enterprise", {}),
        cloud_ttps=cat_metrics.get("cloud", {}),
        containers_ttps=cat_metrics.get("containers", {}),
        mobile_ttps=cat_metrics.get("mobile", {}),
        ics_ttps=cat_metrics.get("ics", {}),
        tactic_hunts=tactic_hunts,
        tactic_rules=tactic_rules,
        tactic_iocs=tactic_iocs,
        matrix_hunts=matrix_hunts,
        matrix_rules=matrix_rules,
        matrix_iocs=matrix_iocs,
        enterprise_total=cat_metrics.get("enterprise_total", 0),
        cloud_total=cat_metrics.get("cloud_total", 0),
        containers_total=cat_metrics.get("containers_total", 0),
        mobile_total=cat_metrics.get("mobile_total", 0),
        ics_total=cat_metrics.get("ics_total", 0),
        grounding_asserted=grounding_asserted,
        grounding_corroborated=grounding_corroborated,
        grounding_derived=grounding_derived,
        grounding_unsupported=grounding_unsupported,
        fingerprints_count=len(fingerprints),
        cloud_ops_count=len(cloud_ops),
    )
    _HUNTS_METRICS_CACHE[resolved_path] = (now, fingerprint_count, max_mtime, metrics)
    return metrics


@dataclass
class PurpleTeamMetrics:
    validated_rules: int = 0
    tuned_rules: int = 0
    total_telemetry_events: int = 0
    precision_rate: float = 1.0
    false_positive_count: int = 0
    hunts_validated: int = 0
    last_status: str = "IDLE"
    last_validated_count: int = 0
    last_tuned_count: int = 0
    last_duration_sec: float = 0.0
    bas_runs: int = 0
    bas_live_runs: int = 0
    bas_mock_runs: int = 0
    bas_verified: int = 0
    bas_detection_misses: int = 0
    bas_telemetry_missing: int = 0
    bas_failures: int = 0
    bas_detections: int = 0
    bas_matched_events: int = 0
    bas_telemetry_runs: int = 0
    bas_techniques: int = 0
    bas_providers: Dict[str, int] = field(default_factory=dict)
    bas_last_status: str = ""
    bas_last_duration_sec: float = 0.0
    bas_mode_label: str = ""
    bas_scope_label: str = ""
    bas_skipped: int = 0
    bas_last_skip_reason: str = ""
    bas_control_runs: int = 0
    bas_siem_verified: int = 0
    bas_last_detection_latency_sec: float = 0.0
    bas_avg_detection_latency_sec: float = 0.0
    bas_last_siem_backend: str = ""
    bas_last_job_id: str = ""


_PURPLE_METRICS_CACHE: Dict[str, Tuple[float, int, float, PurpleTeamMetrics]] = {}


def _collect_purple_team_metrics(
    workspace: Optional[Path] = None,
    events: Optional[List[TrailEvent]] = None,
) -> PurpleTeamMetrics:
    """Collect purple-team validation metrics from workspace artifacts and trail events."""
    metrics = PurpleTeamMetrics()
    now = time.time()

    if events:
        for ev in reversed(events):
            if ev.stage == "purple_team":
                m = re.search(
                    r"validated\s+(\d+)\s+rule\(s\)\s+in\s+([\d\.]+)s:\s+(\d+)\s+tuned,\s+(\d+)\s+FP",
                    ev.message,
                )
                if m:
                    metrics.last_validated_count = int(m.group(1))
                    metrics.last_duration_sec = float(m.group(2))
                    metrics.last_tuned_count = int(m.group(3))
                    metrics.false_positive_count = int(m.group(4))
                    metrics.last_status = "COMPLETED"
                    break
            elif "purple" in ev.message.lower() and "validat" in ev.message.lower():
                metrics.last_status = "ACTIVE"

    if not workspace or not workspace.exists():
        candidates = [
            Path("/home/chemch/betas/Hecate-Public"),
            Path("/home/chemch/betas/Hecate-Workspace"),
            Path.cwd(),
        ]
        for c in candidates:
            if c.is_dir() and ((c / ".hecate" / "bas").is_dir() or (c / "hunts").is_dir()):
                workspace = c
                break
        if not workspace or not workspace.exists():
            return metrics

    resolved_path = str(workspace.resolve())
    hunts_dir = workspace / "hunts"
    queries_dir = workspace / "queries"
    bas_root = workspace / ".hecate" / "bas"
    bas_runs_dir = bas_root / "runs"
    state_file = bas_root / "state.json"

    bas_files: List[Path] = list(bas_runs_dir.glob("*.json")) if bas_runs_dir.is_dir() else []
    bas_mtime = max((f.stat().st_mtime for f in bas_files), default=0.0)
    state_mtime = state_file.stat().st_mtime if state_file.exists() else 0.0
    hunts_mtime = hunts_dir.stat().st_mtime if hunts_dir.exists() else 0.0
    bas_fingerprint = (len(bas_files), bas_mtime, state_mtime, hunts_mtime)

    cached = _PURPLE_METRICS_CACHE.get(resolved_path)
    if cached and (now - cached[0] < 5.0) and cached[1] == bas_fingerprint[0] and cached[2] == bas_fingerprint[1]:
        cached_m = cached[3]
        if metrics.last_validated_count > 0:
            cached_m.last_validated_count = metrics.last_validated_count
            cached_m.last_tuned_count = metrics.last_tuned_count
            cached_m.last_duration_sec = metrics.last_duration_sec
            cached_m.last_status = metrics.last_status
        return cached_m

    hunt_files: List[Path] = []
    if hunts_dir.exists():
        hunt_files = [f for f in hunts_dir.glob("**/*.md") if f.name not in _EXCLUDED_HUNT_DOCS]

    val_rules = 0
    tuned_rules = 0
    hunts_val = 0
    telemetry = 0
    bas_techniques: Set[str] = set()
    last_bas_mtime = 0.0
    seen_bas_ids: Set[str] = set()
    latencies: List[float] = []

    def include_bas(record: Dict[str, Any], mtime: float) -> None:
        nonlocal last_bas_mtime
        status = str(record.get("status") or "")
        if status == "skipped":
            metrics.bas_skipped += 1
            metrics.bas_last_skip_reason = str(record.get("reason") or "No approved procedure")
            return
        if status not in {"verified_true_positive", "detection_miss", "telemetry_missing", "detonation_failed", "error"}:
            return
        metrics.bas_runs += 1
        metrics.bas_control_runs += int(record.get("purpose") == "sensor_control" or record.get("hunt_id") == "LAB-CHECK")
        provider = str(record.get("provider") or "unknown").lower()
        metrics.bas_providers[provider] = metrics.bas_providers.get(provider, 0) + 1
        metrics.bas_mock_runs += int(provider == "mock")
        metrics.bas_live_runs += int(provider in {"caldera", "stratus", "local_sandbox", "live_lab"})
        metrics.bas_verified += int(status == "verified_true_positive")
        metrics.bas_detection_misses += int(status == "detection_miss")
        metrics.bas_telemetry_missing += int(status == "telemetry_missing")
        metrics.bas_failures += int(status in {"detonation_failed", "error"})
        metrics.bas_detections += int(record.get("rule_triggered") is True)
        metrics.bas_telemetry_runs += int(record.get("telemetry_arrived") is True)
        metrics.bas_matched_events += int(record.get("sensor_events_count", record.get("matched_events_count", 0)))
        technique = str(record.get("technique_id") or "")
        if _RE_TECHNIQUE.fullmatch(technique):
            bas_techniques.add(technique)
        lat_val = record.get("detection_latency_sec")
        if lat_val is not None:
            try:
                lat_float = float(lat_val)
                if lat_float > 0.0:
                    latencies.append(lat_float)
            except (ValueError, TypeError):
                pass
        siem_bk = str(record.get("siem_backend") or "")
        if record.get("siem_verified") or (siem_bk and status == "verified_true_positive"):
            metrics.bas_siem_verified += 1
        if mtime >= last_bas_mtime:
            last_bas_mtime = mtime
            metrics.bas_last_status = status
            metrics.bas_last_duration_sec = float(record.get("duration_seconds", 0.0))
            if lat_val is not None:
                try:
                    metrics.bas_last_detection_latency_sec = float(lat_val)
                except (ValueError, TypeError):
                    pass
            if siem_bk:
                metrics.bas_last_siem_backend = siem_bk
            if record.get("search_job_id"):
                metrics.bas_last_job_id = str(record.get("search_job_id"))

    for bas_file in sorted(bas_files, key=lambda f: f.stat().st_mtime):
        try:
            record = json.loads(bas_file.read_text(encoding="utf-8"))
            if not isinstance(record, dict):
                continue
            run_id = str(record.get("run_id") or "")
            if not run_id or run_id in seen_bas_ids:
                continue
            include_bas(record, bas_file.stat().st_mtime)
            seen_bas_ids.add(run_id)
        except (OSError, ValueError, TypeError):
            continue
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
        metrics.bas_mode_label = (
            "DISABLED" if not state.get("enabled") else
            "AUTO · approved Linux lab" if state.get("auto_execute_live") else "MANUAL ONLY"
        )
        if state.get("telemetry") == "lab_process":
            metrics.bas_scope_label = "Local process sensor + Sigma"
        if "last_detection_latency_sec" in state and not metrics.bas_last_detection_latency_sec:
            try:
                metrics.bas_last_detection_latency_sec = float(state.get("last_detection_latency_sec") or 0.0)
            except (ValueError, TypeError):
                pass
        if "last_siem_backend" in state and not metrics.bas_last_siem_backend:
            metrics.bas_last_siem_backend = str(state.get("last_siem_backend") or "")
        if "last_search_job_id" in state and not metrics.bas_last_job_id:
            metrics.bas_last_job_id = str(state.get("last_search_job_id") or "")
    except (OSError, ValueError, AttributeError):
        pass

    for hf in hunt_files:
        try:
            content = hf.read_text(encoding="utf-8", errors="ignore")
            flagged = "purple_team_validated: true" in content or "Purple-Team Validated" in content
            m_va = re.search(r"purple_team_rules_validated:\s*(\d+)", content)
            if flagged:
                hunts_val += 1
            if flagged or m_va:
                if m_va:
                    val_rules += int(m_va.group(1))
                else:
                    # Older hunts record only how many rules were evaluated.
                    m_ev = re.search(r"purple_team_rules_evaluated:\s*(\d+)", content)
                    if m_ev:
                        val_rules += int(m_ev.group(1))
                m_tu = re.search(r"purple_team_rules_tuned:\s*(\d+)", content)
                if m_tu:
                    tuned_rules += int(m_tu.group(1))
                m_te = re.search(r"purple_team_telemetry_events:\s*(\d+)", content)
                if m_te:
                    telemetry += int(m_te.group(1))
            match = re.match(r"^---\s*\n(.*?)\n---(?:\s*\n|$)", content, re.DOTALL)
            metadata = yaml.safe_load(match.group(1)) if match else {}
            if not isinstance(metadata, dict):
                metadata = {}
            bas_status = str(metadata.get("bas_status") or "")
            if bas_status and metadata.get("bas_run_id") not in seen_bas_ids:
                observed = (
                    bas_status in {"verified_true_positive", "detection_miss"}
                    or bool(re.search(r"\*\*Telemetry Observed:\*\* Yes", content))
                )
                target = re.search(r"\*\*Target Technique:\*\* `([^`]+)`", content)
                hits = re.search(r"\*\*Detection Triggered:\*\* .*?\((\d+) hit\(s\)\)", content)
                duration = re.search(r"\*\*Duration:\*\* ([\d.]+)s", content)
                include_bas({
                    "status": bas_status,
                    "provider": metadata.get("bas_provider"),
                    "rule_triggered": metadata.get("bas_detection_triggered"),
                    "telemetry_arrived": observed,
                    "technique_id": target.group(1) if target else (metadata.get("techniques", [""])[0] if metadata.get("techniques") else ""),
                    "matched_events_count": int(hits.group(1)) if hits else 0,
                    "duration_seconds": float(duration.group(1)) if duration else 0.0,
                    "detection_latency_sec": metadata.get("bas_detection_latency_sec"),
                    "siem_backend": metadata.get("bas_backend"),
                    "search_job_id": metadata.get("bas_search_job_id"),
                    "siem_verified": metadata.get("bas_siem_alert_fired") or metadata.get("bas_verified"),
                }, hf.stat().st_mtime)
        except (OSError, ValueError, yaml.YAMLError):
            continue

    if val_rules == 0 and queries_dir.exists():
        for qf in queries_dir.glob("**/*.yml"):
            try:
                qc = qf.read_text(encoding="utf-8", errors="ignore")
                if "x_hecate_purple_team_validated: true" in qc:
                    val_rules += 1
                    if "x_hecate_tuned: true" in qc:
                        tuned_rules += 1
            except OSError:
                continue

    if latencies:
        metrics.bas_avg_detection_latency_sec = round(sum(latencies) / len(latencies), 3)

    if metrics.last_validated_count > val_rules:
        val_rules = max(val_rules, metrics.last_validated_count)
    if metrics.last_tuned_count > tuned_rules:
        tuned_rules = max(tuned_rules, metrics.last_tuned_count)

    metrics.validated_rules = val_rules
    metrics.tuned_rules = tuned_rules
    metrics.hunts_validated = hunts_val
    metrics.total_telemetry_events = telemetry
    metrics.bas_techniques = len(bas_techniques)
    _PURPLE_METRICS_CACHE[resolved_path] = (now, bas_fingerprint[0], bas_fingerprint[1], metrics)
    return metrics


@dataclass
class SiemDriftMetrics:
    total_queries: int = 0
    in_sync_count: int = 0
    decommissioned_count: int = 0
    pending_decommission_count: int = 0
    drifted_count: int = 0
    missing_count: int = 0
    error_count: int = 0
    sync_pct: float = 100.0
    last_audited: str = ""
    sweeps_conducted: int = 0
    tracked_versions: int = 0
    reconciled_count: int = 0
    target_breakdown: Dict[str, Dict[str, int]] = field(default_factory=dict)
    recent_events: List[Dict[str, Any]] = field(default_factory=list)
    recent_versions: List[Dict[str, Any]] = field(default_factory=list)
    active_targets: List[str] = field(default_factory=list)
    status_summary: str = "STANDBY"
    raw_state: Dict[str, Any] = field(default_factory=dict)
    bas_verified_alerts_count: int = 0
    last_detection_latency_sec: float = 0.0
    avg_detection_latency_sec: float = 0.0
    last_verified_hunt: str = ""
    last_verified_technique: str = ""


_SIEM_METRICS_CACHE: Dict[str, Tuple[float, float, float, SiemDriftMetrics]] = {}


def _find_siem_dir(workspace: Optional[Path] = None) -> Optional[Path]:
    """Locate the .hecate/siem directory containing drift state and history."""
    candidates: List[Path] = []
    if workspace:
        resolved = workspace.resolve()
        candidates.extend([
            resolved / ".hecate" / "siem",
            resolved / "Hecate-Public" / ".hecate" / "siem",
            resolved / "Hecate-Workspace" / ".hecate" / "siem",
            resolved.parent / "Hecate-Public" / ".hecate" / "siem",
            resolved.parent / "Hecate-Workspace" / ".hecate" / "siem",
            resolved.parent / "Hecate-Runner" / ".hecate" / "siem",
        ])
    cwd = Path.cwd().resolve()
    candidates.extend([
        cwd / ".hecate" / "siem",
        cwd / "Hecate-Public" / ".hecate" / "siem",
        cwd.parent / "Hecate-Public" / ".hecate" / "siem",
        Path("/home/chemch/betas/Hecate-Public/.hecate/siem"),
        Path("/home/chemch/betas/Hecate-Workspace/.hecate/siem"),
    ])
    for candidate in candidates:
        if candidate.is_dir() and ((candidate / "drift_state.json").exists() or (candidate / "drift_history.db").exists()):
            return candidate
    return None


def _collect_siem_drift_metrics(workspace: Optional[Path] = None) -> SiemDriftMetrics:
    """Collect SIEM sync health, drift metrics, and query version history."""
    metrics = SiemDriftMetrics()
    siem_dir = _find_siem_dir(workspace)
    if not siem_dir or not siem_dir.exists():
        return metrics

    state_file = siem_dir / "drift_state.json"
    db_file = siem_dir / "drift_history.db"

    state_mtime = state_file.stat().st_mtime if state_file.exists() else 0.0
    db_mtime = db_file.stat().st_mtime if db_file.exists() else 0.0

    now = time.time()
    cache_key = str(siem_dir.resolve())
    cached = _SIEM_METRICS_CACHE.get(cache_key)
    if cached and (now - cached[0] < 3.0) and cached[1] == state_mtime and cached[2] == db_mtime:
        return cached[3]

    if state_file.exists():
        try:
            raw = json.loads(state_file.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                metrics.total_queries = int(raw.get("total_queries", 0))
                metrics.in_sync_count = int(raw.get("in_sync_count", 0))
                metrics.decommissioned_count = int(raw.get("decommissioned_count", 0))
                metrics.pending_decommission_count = int(raw.get("pending_decommission_count", 0))
                metrics.drifted_count = int(raw.get("drifted_count", 0))
                metrics.missing_count = int(raw.get("missing_count", 0))
                metrics.error_count = int(raw.get("error_count", 0))
                metrics.raw_state = raw

                target_counts: Dict[str, Dict[str, int]] = {}
                active_targets: Set[str] = set()
                hunts_dict = raw.get("hunts", {})
                if isinstance(hunts_dict, dict):
                    for hunt_id, queries in hunts_dict.items():
                        if isinstance(queries, list):
                            for q in queries:
                                if isinstance(q, dict):
                                    tgt = str(q.get("target") or "unknown")
                                    active_targets.add(tgt)
                                    st = str(q.get("status") or "unknown")
                                    if tgt not in target_counts:
                                        target_counts[tgt] = {
                                            "total": 0,
                                            "in_sync": 0,
                                            "decommissioned": 0,
                                            "drifted": 0,
                                            "missing": 0,
                                            "error": 0,
                                        }
                                    target_counts[tgt]["total"] += 1
                                    if st == "in_sync":
                                        target_counts[tgt]["in_sync"] += 1
                                    elif st == "decommissioned":
                                        target_counts[tgt]["decommissioned"] += 1
                                    elif st in ("drift_detected", "drifted"):
                                        target_counts[tgt]["drifted"] += 1
                                    elif st in ("missing_remote", "missing"):
                                        target_counts[tgt]["missing"] += 1
                                    elif st == "error":
                                        target_counts[tgt]["error"] += 1
                metrics.target_breakdown = target_counts
                metrics.active_targets = sorted(active_targets)
        except (OSError, ValueError, TypeError) as exc:
            logger.debug("Failed reading SIEM drift state: %s", exc)

    if db_file.exists():
        conn = None
        try:
            conn = sqlite3.connect(f"file:{db_file.resolve()}?mode=ro", uri=True, timeout=2.0)
            conn.row_factory = sqlite3.Row

            row = conn.execute("SELECT COUNT(*), MAX(timestamp) FROM audit_sweeps").fetchone()
            if row and row[0] is not None:
                metrics.sweeps_conducted = int(row[0])
                if row[1]:
                    metrics.last_audited = str(row[1])

            v_row = conn.execute("SELECT COUNT(*) FROM query_versions").fetchone()
            if v_row and v_row[0] is not None:
                metrics.tracked_versions = int(v_row[0])

            r_row = conn.execute("SELECT COUNT(*) FROM drift_events WHERE event_type = 'reconciled'").fetchone()
            if r_row and r_row[0] is not None:
                metrics.reconciled_count = int(r_row[0])

            cur = conn.execute(
                "SELECT id, timestamp, hunt_id, target, file_name, remote_id, event_type, previous_status, new_status, drift_diff, detail, actor "
                "FROM drift_events ORDER BY id DESC LIMIT 15"
            )
            metrics.recent_events = [dict(r) for r in cur.fetchall()]

            cur_v = conn.execute(
                "SELECT id, hunt_id, target, file_name, remote_id, version, query_hash, deployed_at, deployed_by, status "
                "FROM query_versions ORDER BY id DESC LIMIT 15"
            )
            metrics.recent_versions = [dict(r) for r in cur_v.fetchall()]

            try:
                val_row = conn.execute(
                    "SELECT COUNT(*), AVG(detection_latency_sec) FROM detection_validations WHERE status = 'verified_true_positive'"
                ).fetchone()
                if val_row and val_row[0] is not None:
                    metrics.bas_verified_alerts_count = int(val_row[0])
                    if val_row[1] is not None:
                        metrics.avg_detection_latency_sec = round(float(val_row[1]), 3)

                last_val = conn.execute(
                    "SELECT hunt_id, technique_id, detection_latency_sec FROM detection_validations ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if last_val:
                    metrics.last_verified_hunt = str(last_val[0])
                    metrics.last_verified_technique = str(last_val[1])
                    if last_val[2] is not None:
                        metrics.last_detection_latency_sec = round(float(last_val[2]), 3)
            except sqlite3.OperationalError:
                pass
        except (sqlite3.Error, OSError) as exc:
            logger.debug("Failed reading SIEM drift history DB: %s", exc)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    if metrics.last_detection_latency_sec == 0.0 and siem_dir:
        bas_state_file = siem_dir.parent / "bas" / "state.json"
        if bas_state_file.exists():
            try:
                b_state = json.loads(bas_state_file.read_text(encoding="utf-8"))
                if "last_detection_latency_sec" in b_state and b_state["last_detection_latency_sec"]:
                    metrics.last_detection_latency_sec = float(b_state["last_detection_latency_sec"])
                    metrics.bas_verified_alerts_count = max(metrics.bas_verified_alerts_count, 1)
                if "last_verified_hunt" in b_state:
                    metrics.last_verified_hunt = str(b_state["last_verified_hunt"])
                if "last_verified_technique" in b_state:
                    metrics.last_verified_technique = str(b_state["last_verified_technique"])
            except Exception:
                pass

    if metrics.total_queries > 0:
        active_q = max(1, metrics.total_queries - metrics.decommissioned_count)
        metrics.sync_pct = round((metrics.in_sync_count / active_q) * 100, 1)
        if metrics.sync_pct > 100.0:
            metrics.sync_pct = 100.0
    else:
        metrics.sync_pct = 100.0

    if metrics.drifted_count > 0:
        metrics.status_summary = "DRIFT DETECTED"
    elif metrics.pending_decommission_count > 0:
        metrics.status_summary = "DECOMMISSION PENDING"
    elif metrics.missing_count > 0 or metrics.error_count > 0:
        metrics.status_summary = "ATTENTION REQUIRED"
    elif metrics.total_queries > 0:
        metrics.status_summary = "IN SYNC"
    else:
        metrics.status_summary = "STANDBY"

    _SIEM_METRICS_CACHE[cache_key] = (now, state_mtime, db_mtime, metrics)
    return metrics

