"""The one list of integrations the monitor, health checks, and request log share.

A host, an environment variable, or a trail name maps back here. Adding an
integration means adding one entry, not another copy of its label in the panel,
the health probe, and the request counter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Integration:
    id: str
    label: str
    kind: str  # llm, search, enrichment, source, output
    env_keys: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    host_prefixes: tuple[str, ...] = ()
    host_contains: tuple[str, ...] = ()
    host_env: str = ""
    host_regex: str = ""
    # Name the enrichment trail uses when it is not the panel label.
    trail_name: str = ""
    panel: str = "status"  # status (credential row), source (feed row), none (health only)
    # Shown as configured even when no credential is set. Keyless public APIs.
    always_configured: bool = False
    # On only when this id (or provider_name) is an active CTI provider.
    follows_cti_provider: bool = False
    provider_name: str = ""

    @property
    def cti_name(self) -> str:
        return self.provider_name or self.id


def _i(id: str, label: str, kind: str, **kwargs: object) -> Integration:
    return Integration(id, label, kind, **kwargs)  # type: ignore[arg-type]


INTEGRATIONS: tuple[Integration, ...] = (
    _i(
        "llm", "LLM", "llm",
        env_keys=("HECATE_LLM_PROVIDER", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "AWS_PROFILE", "OLLAMA_HOST"),
        hosts=("api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com", "localhost:11434", "127.0.0.1:11434"),
        host_env="OLLAMA_HOST",
        host_regex=r"^bedrock-runtime\..+\.amazonaws\.com$",
    ),
    _i("tavily", "Tavily", "search", env_keys=("TAVILY_API_KEY",), hosts=("api.tavily.com",)),
    _i("otx", "OTX", "enrichment", env_keys=("OTX_API_KEY",), hosts=("otx.alienvault.com",), trail_name="OTX", follows_cti_provider=True),
    _i("misp", "MISP", "enrichment", env_keys=("MISP_API_KEY",), host_env="MISP_URL", trail_name="MISP", follows_cti_provider=True),
    _i("vt", "VT", "enrichment", env_keys=("HECATE_RUNNER_VT_API_KEY", "VT_API_KEY"), hosts=("www.virustotal.com",), trail_name="VirusTotal"),
    _i("greynoise", "GreyNoise", "enrichment", env_keys=("GREYNOISE_API_KEY",), hosts=("api.greynoise.io",), trail_name="GreyNoise"),
    _i("abuseipdb", "AbuseIPDB", "enrichment", env_keys=("ABUSEIPDB_API_KEY",), hosts=("api.abuseipdb.com",), trail_name="AbuseIPDB"),
    _i("shodan", "Shodan", "enrichment", env_keys=("SHODAN_API_KEY",), hosts=("api.shodan.io", "internetdb.shodan.io"), trail_name="Shodan"),
    _i("censys", "Censys", "enrichment", env_keys=("CENSYS_API_TOKEN",), hosts=("api.platform.censys.io", "search.censys.io"), trail_name="Censys"),
    _i("threatfox", "ThreatFox", "enrichment", env_keys=("ABUSECH_API_KEY",), hosts=("threatfox-api.abuse.ch",), trail_name="ThreatFox"),
    _i("malwarebazaar", "MalBazaar", "enrichment", env_keys=("ABUSECH_API_KEY",), hosts=("mb-api.abuse.ch",), trail_name="MalwareBazaar"),
    _i("feodo", "Feodo C2", "enrichment", hosts=("feodotracker.abuse.ch",), trail_name="Feodo", always_configured=True),
    _i("sslbl", "SSLBL", "enrichment", hosts=("sslbl.abuse.ch",), trail_name="SSLBL", always_configured=True),
    _i("urlhaus", "URLhaus", "enrichment", env_keys=("ABUSECH_API_KEY",), hosts=("urlhaus-api.abuse.ch", "urlhaus.abuse.ch"), trail_name="URLhaus"),
    _i("urlscan", "URLScan", "enrichment", env_keys=("URLSCAN_API_KEY",), hosts=("urlscan.io",), trail_name="URLScan", always_configured=True),
    _i("hybrid", "Hybrid", "enrichment", env_keys=("HYBRID_ANALYSIS_API_KEY", "HA_API_KEY", "FALCON_SANDBOX_API_KEY"), hosts=("hybrid-analysis.com", "www.hybrid-analysis.com"), trail_name="Hybrid Analysis"),
    _i("rdap", "RDAP", "enrichment", host_prefixes=("rdap.",), host_contains=(".rdap.",), trail_name="RDAP", always_configured=True),
    _i("crtsh", "crt.sh", "enrichment", hosts=("crt.sh",), trail_name="crt.sh", always_configured=True),
    _i("pdns", "PDNS", "enrichment", env_keys=("VT_API_KEY", "MNEMONIC_API_KEY", "OTX_API_KEY"), hosts=("api.mnemonic.no",), trail_name="Passive DNS", always_configured=True),
    _i("spur", "Spur", "enrichment", env_keys=("SPUR_API_KEY",), hosts=("api.spur.us",), trail_name="Spur"),
    _i("tor_proxy", "Tor/Proxy", "enrichment", env_keys=("IPINFO_TOKEN", "IPINFO_API_KEY"), hosts=("onionoo.torproject.org", "check.torproject.org", "ipinfo.io"), trail_name="Tor/Proxy", always_configured=True),
    _i("epss", "EPSS", "enrichment", hosts=("api.first.org",), trail_name="EPSS", always_configured=True),
    _i("osv", "OSV.dev", "enrichment", hosts=("api.osv.dev",), trail_name="OSV.dev", always_configured=True),
    _i("slack", "Slack", "output", env_keys=("SLACK_BOT_TOKEN", "HECATE_RUNNER_SLACK_WEBHOOK_URL", "SLACK_WEBHOOK_URL"), hosts=("slack.com", "hooks.slack.com")),
    _i("vulncheck", "VulnCheck", "enrichment", env_keys=("VULNCHECK_API_KEY",), hosts=("api.vulncheck.com",), trail_name="VulnCheck", follows_cti_provider=True),
    _i("triage", "Triage", "enrichment", env_keys=("TRIAGE_API_KEY", "HATCHING_TRIAGE_API_KEY"), hosts=("tria.ge", "api.tria.ge"), trail_name="Triage", follows_cti_provider=True),
    _i("shadowserver", "Shadowsrv", "enrichment", env_keys=("SHADOWSERVER_API_KEY",), hosts=("api.shadowserver.org", "transform.shadowserver.org"), trail_name="Shadowserver", follows_cti_provider=True),
    _i("msrc", "MSRC", "enrichment", hosts=("api.msrc.microsoft.com",), trail_name="MSRC", always_configured=True, follows_cti_provider=True),
    _i("cloud_threat", "CloudThrt", "source", always_configured=True, follows_cti_provider=True, panel="status"),
    _i("dfir_report", "DFIR Rept", "source", always_configured=True, follows_cti_provider=True, panel="status"),
    _i("first_org", "FIRST.org", "source", always_configured=True, follows_cti_provider=True, panel="status"),
    _i("anyrun", "ANY.RUN", "source", env_keys=("ANYRUN_API_KEY",), always_configured=True, follows_cti_provider=True, panel="status"),
    _i("opencti", "OpenCTI", "source", env_keys=("OPENCTI_TOKEN", "OPENCTI_URL"), always_configured=True, follows_cti_provider=True, panel="status"),
    _i("lolbas", "LOLBAS", "source", panel="source", follows_cti_provider=True),
    _i("loldrivers", "LOLDrivers", "source", panel="source", follows_cti_provider=True),
    _i("gtfobins", "GTFOBins", "source", panel="source", follows_cti_provider=True),
    _i("nuclei", "Nuclei", "source", panel="source", follows_cti_provider=True),
    _i("cisa_narrative", "CISA AA", "source", panel="source", follows_cti_provider=True, provider_name="cisa_advisories"),
    _i("cisa_advisories", "CISA CSAF", "source", panel="source", follows_cti_provider=True),
    _i("cisa_ics", "CISA ICS", "source", panel="source", follows_cti_provider=True),
    _i("attack_deltas", "ATT&CK", "source", panel="source", follows_cti_provider=True),
    _i("cisa_kev", "CISA KEV", "source", panel="source", follows_cti_provider=True),
    _i("rss", "RSS", "source", panel="source", follows_cti_provider=True),
    _i("github_poc", "GitHub PoC", "source", hosts=("api.github.com",), panel="source", follows_cti_provider=True),
    _i("vxunderground", "VXUG", "source", panel="source", follows_cti_provider=True),
    _i("certstream", "CertStrm", "source", panel="source", follows_cti_provider=True),
    # Health-check id for MISP publishing. The panel row stays "MISP".
    _i("misp_output", "", "output", panel="none"),
)

BY_ID: dict[str, Integration] = {item.id: item for item in INTEGRATIONS}
BY_LABEL: dict[str, Integration] = {item.label: item for item in INTEGRATIONS if item.panel != "none" and item.label}
STATUS_INTEGRATIONS: tuple[Integration, ...] = tuple(item for item in INTEGRATIONS if item.panel == "status")
SOURCE_INTEGRATIONS: tuple[Integration, ...] = tuple(item for item in INTEGRATIONS if item.panel == "source")
_TRAIL_LABELS: dict[str, str] = {
    (item.trail_name or item.label): item.label
    for item in INTEGRATIONS
    if item.label and (item.trail_name or item.kind == "enrichment")
}
_HOST_LABELS: dict[str, str] = {}
for _item in INTEGRATIONS:
    for _host in _item.hosts:
        if _host in _HOST_LABELS and _HOST_LABELS[_host] != _item.label:
            raise RuntimeError(f"{_host} is claimed by {_HOST_LABELS[_host]} and {_item.label}")
        _HOST_LABELS[_host] = _item.label
_HOST_REGEXES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(item.host_regex), item.label) for item in INTEGRATIONS if item.host_regex and item.label
)


def enrichment_label(service: str) -> str:
    """Panel label for a name the enrichment trail uses."""
    return _TRAIL_LABELS.get(service, service)


def label_for_host(host: str, env: Mapping[str, str] | None = None) -> str | None:
    """Panel label for a request host. Instance hosts (MISP, Ollama) come from ``env``."""
    host = (host or "").lower()
    if not host:
        return None
    values = env or {}
    for item in INTEGRATIONS:
        configured = str(values.get(item.host_env) or "") if item.host_env else ""
        if not configured:
            continue
        parts = urlsplit(configured if "://" in configured else f"http://{configured}")
        netloc = (parts.hostname or "").lower()
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        if netloc and host == netloc:
            return item.label or None
    if host in _HOST_LABELS:
        return _HOST_LABELS[host]
    for item in INTEGRATIONS:
        if any(host.startswith(prefix) for prefix in item.host_prefixes) or any(
            piece in host for piece in item.host_contains
        ):
            return item.label or None
    for pattern, label in _HOST_REGEXES:
        if pattern.search(host):
            return label
    return None


def require_integration(name: str) -> Integration:
    """The registry entry for a health-check id, or KeyError if it was never registered."""
    try:
        return BY_ID[name]
    except KeyError:
        raise KeyError(f"{name} is not a registered integration") from None
