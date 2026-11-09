from __future__ import annotations

import logging
import os
import re
import time
from typing import Dict, List, Set

import httpx

from hecate_agent.enrichment.constants import _KNOWN_PUBLISHER_DOMAINS
from hecate_agent.enrichment.result import OUTCOMES as ENRICHMENT_OUTCOMES
from hecate_agent.enrichment.result import classify_enrichment_result
from hecate_agent.core.provenance import is_valid_ipv4, trim_shell_tail
from hecate_agent.core.workspace import load_workspace_env

from hecate_agent.enrichment.providers.virustotal import (
    extract_vt_behavior_graph,
    query_vt_hash,
    query_vt_ip,
    query_vt_domain,
    query_vt_pdns_domain,
    query_vt_pdns_ip,
)
from hecate_agent.enrichment.providers.rdap import (
    _format_rdap_date,
    query_rdap_domain,
)
from hecate_agent.enrichment.providers.greynoise import (
    extract_greynoise_context,
    query_greynoise_ip,
)
from hecate_agent.enrichment.providers.shodan_censys import (
    query_shodan_ip,
    query_censys_ip,
)
from hecate_agent.enrichment.providers.misp import (
    query_misp_indicator,
    expand_ttps,
)
from hecate_agent.enrichment.providers.shadowserver import (
    query_shadowserver_ip,
    query_shadowserver_hash,
)
from hecate_agent.enrichment.providers.abuseipdb import (
    query_abuseipdb_ip,
)
from hecate_agent.enrichment.providers.spur import (
    _SPUR_CACHE,
    _SPUR_CACHE_TTL,
    extract_spur_context,
    query_spur_ip,
)
from hecate_agent.enrichment.providers.threat_intel_feeds import (
    _FEODO_CACHE,
    _SSLBL_CACHE,
    query_threatfox,
    query_malwarebazaar,
    _get_feodo_ip_map,
    _get_sslbl_fingerprint_map,
    query_feodotracker_ip,
    query_sslbl_fingerprint,
)
from hecate_agent.enrichment.providers.anonymity import (
    _TOR_EXIT_CACHE,
    _TOR_EXIT_TTL,
    _get_tor_exit_nodes,
    is_tor_exit_node,
    query_tor_exit,
    _IPINFO_CACHE,
    _IPINFO_CACHE_TTL,
    extract_ipinfo_context,
    query_ipinfo_ip,
    query_anonymity_proxy_ip,
)
from hecate_agent.enrichment.providers.urlhaus import (
    query_urlhaus_url,
    query_urlhaus_host,
    query_urlhaus_payload,
)
from hecate_agent.enrichment.providers.urlscan import (
    _URLSCAN_CACHE,
    _URLSCAN_CACHE_TTL,
    extract_web_lure_payloads,
    query_urlscan_url,
    query_urlscan_domain,
    submit_urlscan_detonation,
    poll_urlscan_result,
    extract_http_transactions,
    generate_transaction_sigma_rules,
)
from hecate_agent.enrichment.providers.crtsh import (
    _CRTSH_CACHE,
    _CRTSH_CACHE_TTL,
    _SHARED_HOSTING_SUFFIXES,
    extract_sibling_domains_from_crtsh,
    query_crtsh_domain,
)
from hecate_agent.enrichment.providers.vulnerabilities import (
    query_epss,
    query_epss_batch,
    query_osv_vuln,
    query_vulncheck_cve,
    _fetch_msrc_document,
    query_msrc_cve,
)
from hecate_agent.enrichment.providers.otx import (
    query_otx_indicator,
    query_otx_ip,
    query_otx_domain,
    query_otx_hash,
    query_otx_cve,
    query_otx_pdns,
)
from hecate_agent.enrichment.providers.passive_dns import (
    _PDNS_CACHE,
    _PDNS_CACHE_TTL,
    _normalize_pdns_timestamp,
    _format_pdns_date,
    query_mnemonic_pdns,
    query_passive_dns,
    query_passive_dns_ip,
    query_passive_dns_domain,
)
from hecate_agent.enrichment.providers.sandboxes import (
    query_hybrid_analysis,
    query_triage_hash,
)

load_workspace_env()

logger = logging.getLogger(__name__)

__all__ = [
    "extract_indicators",
    "generate_enrichment_summary",
    "refang",
    "_get_apex_domain",
    "_setting",
    "_misp_verify_tls",
    "_KNOWN_PUBLISHER_DOMAINS",
    "httpx",
    "time",
    "logger",
    "extract_vt_behavior_graph",
    "query_vt_hash",
    "query_vt_ip",
    "query_vt_domain",
    "query_vt_pdns_domain",
    "query_vt_pdns_ip",
    "_format_rdap_date",
    "query_rdap_domain",
    "extract_greynoise_context",
    "query_greynoise_ip",
    "query_shodan_ip",
    "query_censys_ip",
    "query_misp_indicator",
    "expand_ttps",
    "query_shadowserver_ip",
    "query_shadowserver_hash",
    "query_abuseipdb_ip",
    "_SPUR_CACHE",
    "_SPUR_CACHE_TTL",
    "extract_spur_context",
    "query_spur_ip",
    "_FEODO_CACHE",
    "_SSLBL_CACHE",
    "query_threatfox",
    "query_malwarebazaar",
    "_get_feodo_ip_map",
    "_get_sslbl_fingerprint_map",
    "query_feodotracker_ip",
    "query_sslbl_fingerprint",
    "_TOR_EXIT_CACHE",
    "_TOR_EXIT_TTL",
    "_get_tor_exit_nodes",
    "is_tor_exit_node",
    "query_tor_exit",
    "_IPINFO_CACHE",
    "_IPINFO_CACHE_TTL",
    "extract_ipinfo_context",
    "query_ipinfo_ip",
    "query_anonymity_proxy_ip",
    "query_urlhaus_url",
    "query_urlhaus_host",
    "query_urlhaus_payload",
    "_URLSCAN_CACHE",
    "_URLSCAN_CACHE_TTL",
    "extract_web_lure_payloads",
    "query_urlscan_url",
    "query_urlscan_domain",
    "submit_urlscan_detonation",
    "poll_urlscan_result",
    "extract_http_transactions",
    "generate_transaction_sigma_rules",
    "_CRTSH_CACHE",
    "_CRTSH_CACHE_TTL",
    "_SHARED_HOSTING_SUFFIXES",
    "extract_sibling_domains_from_crtsh",
    "query_crtsh_domain",
    "query_epss",
    "query_epss_batch",
    "query_osv_vuln",
    "query_vulncheck_cve",
    "_fetch_msrc_document",
    "query_msrc_cve",
    "query_otx_indicator",
    "query_otx_ip",
    "query_otx_domain",
    "query_otx_hash",
    "query_otx_cve",
    "query_otx_pdns",
    "_PDNS_CACHE",
    "_PDNS_CACHE_TTL",
    "_normalize_pdns_timestamp",
    "_format_pdns_date",
    "query_mnemonic_pdns",
    "query_passive_dns",
    "query_passive_dns_ip",
    "query_passive_dns_domain",
    "query_hybrid_analysis",
    "query_triage_hash",
]

def _setting(name: str, default: str = "") -> str:
    """Read a credential or endpoint from the environment (loaded from .env by the CLI).

    Never hardcode these: the values below were once committed and pushed.
    """
    return os.environ.get(name, default)


def _misp_verify_tls() -> bool:
    """Verify MISP's certificate unless MISP_VERIFY_SSL=false (e.g. a local self-signed instance)."""
    return _setting("MISP_VERIFY_SSL", "true").lower() != "false"


logger = logging.getLogger(__name__)


def refang(value: str) -> str:
    """Undo report defanging ("hxxp", "[.]", "(.)", "[:]", "(:)", etc.) so values match real telemetry."""
    if not value or not isinstance(value, str):
        return ""
    v = value.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("(dot)", ".")
    v = v.replace("[:]", ":").replace("(:)", ":")
    return re.sub(r"\bhxxp", "http", v, flags=re.IGNORECASE)


def _get_apex_domain(domain: str) -> str:
    """Extract registrable apex domain (e.g. c2.evil.com -> evil.com)."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return domain
    two_part_tlds = {
        "co.uk",
        "gov.uk",
        "ac.uk",
        "org.uk",
        "com.au",
        "net.au",
        "co.nz",
        "co.jp",
        "com.kg",
        "org.kg",
        "net.kg",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "com.br",
        "co.in",
        "com.tr",
        "co.za",
        "com.mx",
        "com.ar",
    }
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in two_part_tlds and len(parts) > 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])





def extract_indicators(text: str) -> Dict[str, List[str]]:
    """Extract IPs, Domains, Hashes, and CVEs from text using regex, refanging first."""
    if not text:
        return {"ips": [], "hashes": [], "domains": [], "cves": []}
    clean_text = refang(text)
    tlds_list = [
        r"co\.uk",
        r"gov\.uk",
        r"ac\.uk",
        r"org\.uk",
        r"com\.au",
        r"net\.au",
        r"co\.nz",
        r"co\.jp",
        r"com\.kg",
        r"org\.kg",
        r"net\.kg",
        r"com\.cn",
        r"net\.cn",
        r"org\.cn",
        r"gov\.cn",
        r"com\.br",
        r"co\.in",
        r"com\.tr",
        r"co\.za",
        r"com\.mx",
        r"com\.ar",
        r"com",
        r"org",
        r"net",
        r"edu",
        r"gov",
        r"mil",
        r"info",
        r"biz",
        r"shop",
        r"top",
        r"xyz",
        r"site",
        r"online",
        r"club",
        r"vip",
        r"live",
        r"app",
        r"dev",
        r"pro",
        r"win",
        r"work",
        r"cloud",
        r"space",
        r"link",
        r"one",
        r"click",
        r"tech",
        r"store",
        r"news",
        r"blog",
        r"icu",
        r"fun",
        r"digital",
        r"security",
        r"agency",
        r"center",
        r"io",
        r"ai",
        r"me",
        r"cc",
        r"tv",
        r"to",
        r"is",
        r"pw",
        r"ws",
        r"uk",
        r"de",
        r"cn",
        r"ru",
        r"jp",
        r"kr",
        r"in",
        r"br",
        r"ca",
        r"au",
        r"fr",
        r"nl",
        r"se",
        r"no",
        r"fi",
        r"es",
        r"it",
        r"pl",
        r"ch",
        r"at",
        r"be",
        r"cz",
        r"ro",
        r"ua",
        r"za",
        r"mx",
        r"ar",
        r"cl",
        r"co",
        r"id",
        r"my",
        r"th",
        r"vn",
        r"ph",
        r"sg",
        r"nz",
        r"kg",
    ]
    tlds = "|".join(tlds_list)
    domain_re = rf"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?\.)+(?:{tlds})\b(?!\.[a-zA-Z0-9])"
    indicators = {
        "ips": list(set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", clean_text))),
        "hashes": list(set(re.findall(r"\b[a-fA-F0-9]{32,64}\b", clean_text))),
        "domains": [
            d
            for d in set(re.findall(domain_re, clean_text, re.IGNORECASE))
            if not re.match(
                r"^(?:[A-Za-z0-9_-]+)\.(?:(?:Read|ReadWrite|Write|Manage|Send|Access)(?:\.[A-Za-z0-9_-]+)?|All|Directory|Selected)$",
                d,
                re.IGNORECASE,
            )
        ],
        "cves": list(
            dict.fromkeys(
                cve.upper()
                for cve in re.findall(
                    r"\b(?:CVE-\d{4}-\d{4,7}|GHSA-[2-9a-kmnp-z]{4}-[2-9a-kmnp-z]{4}-[2-9a-kmnp-z]{4})\b",
                    clean_text,
                    re.IGNORECASE,
                )
            )
        ),
    }
    # Filter out common false positives and private IPs. A dotted version
    # number has an address's shape: H-0830's NetScaler build "13.1.37.283".
    indicators["ips"] = [
        ip
        for ip in indicators["ips"]
        if is_valid_ipv4(ip)
        and not ip.startswith(
            (
                "127.",
                "10.",
                "192.168.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.20.",
                "172.21.",
                "172.22.",
                "172.23.",
                "172.24.",
                "172.25.",
                "172.26.",
                "172.27.",
                "172.28.",
                "172.29.",
                "172.30.",
                "172.31.",
                "0.0.0.0",
                "255.255.255.255",
            )
        )
    ]

    # Dynamically extract domains cited in reference/source/citation URLs
    dynamic_publishers: Set[str] = set()
    for ref_url in re.findall(
        r"(?:references?|sources?|see\s+also|read\s+more|link|url|via|courtesy|author|published\s+by|credit|report|research):\s*(https?://[^\s\)\],]+)",
        clean_text,
        re.IGNORECASE,
    ):
        m_host = re.match(r"https?://(?:www\.)?([^/:\s\)\],]+)", ref_url, re.IGNORECASE)
        if m_host:
            host = m_host.group(1).lower()
            dynamic_publishers.add(host)
            dynamic_publishers.add(_get_apex_domain(host))

    for m_host_match in re.finditer(
        r"https?://(?:www\.)?([^/:\s\)\],]+)(?:/[^\s\)\],]*(?:blog|research|threat-intel|advisory|advisories|security-center|posts?|articles?|news|publications?|topics/threat-intelligence)[^\s\)\],]*)",
        clean_text,
        re.IGNORECASE,
    ):
        host = m_host_match.group(1).lower()
        dynamic_publishers.add(host)
        dynamic_publishers.add(_get_apex_domain(host))

    for md_link in re.findall(
        r"\[(?:source|reference|report|link|article|read\s+more|blog)\]\((https?://[^\s\)]+)\)",
        clean_text,
        re.IGNORECASE,
    ):
        m_host = re.match(r"https?://(?:www\.)?([^/:\s\)]+)", md_link, re.IGNORECASE)
        if m_host:
            host = m_host.group(1).lower()
            dynamic_publishers.add(host)
            dynamic_publishers.add(_get_apex_domain(host))

    # A host the text only ever mentions as a markdown link target is a
    # citation, not infrastructure: reports hyperlink the advisories and
    # databases they cite and defang the indicators they publish. H-0830's
    # source linked nvd.nist.gov, www.cve.org and helpx.adobe.com, and all
    # three became IOC rules.
    link_targets = list(re.finditer(r"\]\((https?://[^\s)]+)\)", clean_text))
    unlinked_text = clean_text
    for link in reversed(link_targets):
        unlinked_text = unlinked_text[: link.start(1)] + unlinked_text[link.end(1) :]
    for link in link_targets:
        m_host = re.match(r"https?://([^/:\s)]+)", link.group(1), re.IGNORECASE)
        if m_host and m_host.group(1).lower() not in unlinked_text.lower():
            dynamic_publishers.add(m_host.group(1).lower())

    def _is_benign_or_publisher(d: str) -> bool:
        low = d.lower()
        if low.endswith(".local"):
            return True
        if low in _KNOWN_PUBLISHER_DOMAINS or low in dynamic_publishers:
            return True
        apex = _get_apex_domain(low)
        if apex in _KNOWN_PUBLISHER_DOMAINS or apex in dynamic_publishers:
            return True
        return False

    indicators["domains"] = [d.lower() for d in indicators["domains"] if not _is_benign_or_publisher(d)]

    raw_urls = re.findall(r'https?://[^\s<>"\'\)\]`]+', clean_text)
    filtered_urls = []
    for u in raw_urls:
        clean_u = trim_shell_tail(u.rstrip(".,;:)"))
        m_u_host = re.match(r"https?://(?:www\.)?([^/:\s\)\],]+)", clean_u, re.IGNORECASE)
        if m_u_host:
            u_host = m_u_host.group(1).lower()
            if _is_benign_or_publisher(u_host):
                continue
            if any(u_host.startswith(p) for p in ("127.", "10.", "192.168.", "172.", "0.0.0.0", "localhost")):
                continue
            filtered_urls.append(clean_u)

    indicators["urls"] = list(dict.fromkeys(filtered_urls))
    return indicators






class _EnrichmentTally:
    def __init__(
        self,
        sink: Dict[str, Dict[str, int]] | None,
        citations: List[Dict[str, str]] | None = None,
    ) -> None:
        import threading

        self._sink = sink
        self._citations = citations
        self._lock = threading.Lock()

    def __call__(self, service: str, result: str, observable: str = "", kind: str = "") -> str:
        outcome = classify_enrichment_result(result)  # reads EnrichmentResult.outcome when set
        with self._lock:
            if self._sink is not None:
                row = self._sink.setdefault(service, {"checked": 0, **{k: 0 for k in ENRICHMENT_OUTCOMES}})
                row["checked"] += 1
                row[outcome] += 1
                if outcome == "flagged":
                    row["found"] += 1
            if self._citations is not None and observable:
                self._citations.append(
                    {
                        "observable": observable,
                        "kind": kind or "observable",
                        "service": service,
                        "outcome": outcome,
                        "verdict": str(getattr(result, "verdict", "") or ""),
                    }
                )
        return result


def generate_enrichment_summary(
    threat_intel: str,
    stats: Dict[str, Dict[str, int]] | None = None,
    citations: List[Dict[str, str]] | None = None,
) -> str:
    """Extracts indicators and queries OSINT platforms, returning a markdown summary.

    ``stats``, when given, is filled per service with how many lookups ran and
    how they came out. ``citations``, when given, receives one record per
    lookup so the hunt can label each observable corroborated or not.
    """
    indicators = extract_indicators(threat_intel)
    if not any(indicators.values()):
        return ""
    rec = _EnrichmentTally(stats, citations)

    summary = [
        "\n\n### 🛡️ Automated Threat Enrichment (VT, AlienVault OTX, URLScan.io, crt.sh, Passive DNS, Tor Project, IPinfo, Hybrid Analysis, Hatching Triage, Abuse.ch [ThreatFox, MalwareBazaar, Feodo, SSLBL, URLhaus], GreyNoise, AbuseIPDB, Shodan, Censys [JARM/JA4], Shadowserver Foundation, RDAP, EPSS, VulnCheck KEV, OSV.dev & MISP)"
    ]

    from concurrent.futures import ThreadPoolExecutor

    def process_hash(h: str) -> str:
        res = rec("VirusTotal", query_vt_hash(h), h, "hash")
        otx_res = rec("OTX", query_otx_hash(h), h, "hash")
        ha_res = rec("Hybrid Analysis", query_hybrid_analysis(h), h, "hash")
        triage_res = rec("Triage", query_triage_hash(h), h, "hash")
        mb_res = rec("MalwareBazaar", query_malwarebazaar(h), h, "hash")
        ss_hash_res = rec("Shadowserver", query_shadowserver_hash(h), h, "hash")
        sslbl_res = rec("SSLBL", query_sslbl_fingerprint(h), h, "hash")
        urlhaus_res = rec("URLhaus", query_urlhaus_payload(h), h, "hash")
        threatfox_res = rec("ThreatFox", query_threatfox(h), h, "hash")
        misp_res = rec("MISP", query_misp_indicator(h), h, "hash")
        lines = [
            f"- **Hash {h}**:\n"
            f"  - *VirusTotal:* {res}\n"
            f"  - *AlienVault OTX:* {otx_res}\n"
            f"  - *Hybrid Analysis (Falcon Sandbox):* {ha_res}\n"
            f"  - *Hatching Triage (tria.ge Sandbox):* {triage_res}\n"
            f"  - *Abuse.ch (MalwareBazaar):* {mb_res}"
        ]
        if not ss_hash_res.startswith("No record on Shadowserver") and not ss_hash_res.startswith("Invalid hash"):
            lines.append(f"  - *Shadowserver Foundation (Malware Analysis):* {ss_hash_res}")
        if len(h) in (32, 40):
            lines.append(f"  - *Abuse.ch (SSLBL Fingerprint):* {sslbl_res}")
        if not urlhaus_res.startswith("No payload on URLhaus"):
            lines.append(f"  - *Abuse.ch (URLhaus Payload):* {urlhaus_res}")
        lines.append(f"  - *Abuse.ch (ThreatFox):* {threatfox_res}")
        lines.append(f"  - *Internal MISP:* {misp_res}")
        return "\n".join(lines)

    def process_ip(ip: str) -> str:
        vt_res = rec("VirusTotal", query_vt_ip(ip), ip, "ip")
        otx_res = rec("OTX", query_otx_ip(ip), ip, "ip")
        feodo_res = rec("Feodo", query_feodotracker_ip(ip), ip, "ip")
        abuseipdb_res = rec("AbuseIPDB", query_abuseipdb_ip(ip), ip, "ip")
        anon_res = rec("Tor/Proxy", query_anonymity_proxy_ip(ip), ip, "ip")
        spur_res = rec("Spur", query_spur_ip(ip), ip, "ip")
        pdns_res = rec("Passive DNS", query_passive_dns(ip), ip, "ip")
        gn_res = rec("GreyNoise", query_greynoise_ip(ip), ip, "ip")
        shodan_res = rec("Shodan", query_shodan_ip(ip), ip, "ip")
        censys_res = rec("Censys", query_censys_ip(ip), ip, "ip")
        ss_ip_res = rec("Shadowserver", query_shadowserver_ip(ip), ip, "ip")
        threatfox_res = rec("ThreatFox", query_threatfox(ip), ip, "ip")
        misp_res = rec("MISP", query_misp_indicator(ip), ip, "ip")
        lines = [
            f"- **IP {ip}**:\n"
            f"  - *VirusTotal:* {vt_res}\n"
            f"  - *AlienVault OTX:* {otx_res}\n"
            f"  - *Abuse.ch (Feodo Tracker C2):* {feodo_res}\n"
            f"  - *AbuseIPDB:* {abuseipdb_res}"
        ]
        if anon_res and not anon_res.startswith("Private") and not anon_res.startswith("Invalid"):
            lines.append(f"  - *Anonymity & Proxy (Tor / Hosting / VPN):* {anon_res}")
        if not spur_res.startswith("SPUR_API_KEY not configured"):
            lines.append(f"  - *Spur.us (Proxy & Infrastructure):* {spur_res}")
        if not pdns_res.startswith("No passive DNS records found"):
            lines.append(f"  - *Passive DNS (Historical Correlated Hostnames):* {pdns_res}")
        if (
            not ss_ip_res.startswith("No ASN record")
            and not ss_ip_res.startswith("Private")
            and not ss_ip_res.startswith("Invalid")
        ):
            lines.append(f"  - *Shadowserver Foundation (Network Origin):* {ss_ip_res}")
        lines.extend(
            [
                f"  - *GreyNoise:* {gn_res}",
                f"  - *Shodan:* {shodan_res}",
                f"  - *Censys:* {censys_res}",
                f"  - *Abuse.ch (ThreatFox):* {threatfox_res}",
                f"  - *Internal MISP:* {misp_res}",
            ]
        )
        return "\n".join(lines)

    def process_domain(d: str) -> str:
        vt_res = rec("VirusTotal", query_vt_domain(d), d, "domain")
        otx_res = rec("OTX", query_otx_domain(d), d, "domain")
        rdap_res = rec("RDAP", query_rdap_domain(d), d, "domain")
        urlscan_res = rec("URLScan", query_urlscan_domain(d), d, "domain")
        crtsh_res = rec("crt.sh", query_crtsh_domain(d), d, "domain")
        pdns_res = rec("Passive DNS", query_passive_dns(d), d, "domain")
        urlhaus_res = rec("URLhaus", query_urlhaus_host(d), d, "domain")
        threatfox_res = rec("ThreatFox", query_threatfox(d), d, "domain")
        misp_res = rec("MISP", query_misp_indicator(d), d, "domain")
        lines = [
            f"- **Domain {d}**:\n"
            f"  - *VirusTotal:* {vt_res}\n"
            f"  - *AlienVault OTX:* {otx_res}\n"
            f"  - *RDAP (Domain Age & Registrar):* {rdap_res}"
        ]
        if not urlscan_res.startswith("Not indexed on URLScan"):
            lines.append(f"  - *URLScan.io (Web Lures & Staging):* {urlscan_res}")
        if not crtsh_res.startswith("No certificates found on crt.sh"):
            lines.append(f"  - *crt.sh (Certificate Transparency & Sibling Domains):* {crtsh_res}")
        if not pdns_res.startswith("No passive DNS records found"):
            lines.append(f"  - *Passive DNS (Historical IP Resolutions):* {pdns_res}")
        if not urlhaus_res.startswith("Not listed on URLhaus"):
            lines.append(f"  - *Abuse.ch (URLhaus Host):* {urlhaus_res}")
        lines.append(f"  - *Abuse.ch (ThreatFox):* {threatfox_res}")
        lines.append(f"  - *Internal MISP:* {misp_res}")
        return "\n".join(lines)

    def process_url(u: str) -> str:
        urlscan_res = rec("URLScan", query_urlscan_url(u), u, "url")
        urlhaus_res = rec("URLhaus", query_urlhaus_url(u), u, "url")
        threatfox_res = rec("ThreatFox", query_threatfox(u), u, "url")
        misp_res = rec("MISP", query_misp_indicator(u), u, "url")
        return (
            f"- **URL {u}**:\n"
            f"  - *URLScan.io (DOM & Web Lure Analysis):* {urlscan_res}\n"
            f"  - *Abuse.ch (URLhaus):* {urlhaus_res}\n"
            f"  - *Abuse.ch (ThreatFox):* {threatfox_res}\n"
            f"  - *Internal MISP:* {misp_res}"
        )

    with ThreadPoolExecutor(max_workers=10) as executor:
        hash_futures = {executor.submit(process_hash, h): h for h in indicators["hashes"][:5]}
        ip_futures = {executor.submit(process_ip, ip): ip for ip in indicators["ips"][:5]}
        domain_futures = {executor.submit(process_domain, d): d for d in indicators["domains"][:5]}
        url_futures = {executor.submit(process_url, u): u for u in indicators.get("urls", [])[:5]}

        # To maintain order
        hash_results = {future: future.result() for future in hash_futures}
        for h in indicators["hashes"][:5]:
            for future, result in hash_results.items():
                if hash_futures[future] == h:
                    summary.append(result)
                    break

        ip_results = {future: future.result() for future in ip_futures}
        for ip in indicators["ips"][:5]:
            for future, result in ip_results.items():
                if ip_futures[future] == ip:
                    summary.append(result)
                    break

        domain_results = {future: future.result() for future in domain_futures}
        for d in indicators["domains"][:5]:
            for future, result in domain_results.items():
                if domain_futures[future] == d:
                    summary.append(result)
                    break

        url_results = {future: future.result() for future in url_futures}
        for u in indicators.get("urls", [])[:5]:
            for future, result in url_results.items():
                if url_futures[future] == u:
                    summary.append(result)
                    break

    cve_list = indicators.get("cves", [])[:5]
    if cve_list:
        epss_batch = query_epss_batch(cve_list)
        for cve in cve_list:
            epss_res = rec("EPSS", epss_batch.get(cve, "No EPSS score published."), cve, "cve")
            otx_res = rec("OTX", query_otx_cve(cve), cve, "cve")
            misp_res = rec("MISP", query_misp_indicator(cve), cve, "cve")
            osv_res = rec("OSV.dev", query_osv_vuln(cve), cve, "cve")
            vulncheck_res = rec("VulnCheck", query_vulncheck_cve(cve), cve, "cve")
            msrc_res = rec("MSRC", query_msrc_cve(cve), cve, "cve")
            summary.append(
                f"- **Vulnerability {cve}**:\n"
                f"  - *FIRST EPSS (Exploit Prediction):* {epss_res}\n"
                f"  - *VulnCheck KEV (Active Exploitation):* {vulncheck_res}\n"
                f"  - *Microsoft MSRC (Security Guidance):* {msrc_res}\n"
                f"  - *OSV.dev (Open Source Supply Chain):* {osv_res}\n"
                f"  - *AlienVault OTX:* {otx_res}\n"
                f"  - *Internal MISP:* {misp_res}"
            )

    final_output = ""
    if len(summary) > 1:
        final_output += "\n".join(summary)

    if citations:
        from hecate_agent.enrichment.result import render_enrichment_citations

        rendered = render_enrichment_citations(citations)
        if rendered:
            final_output = rendered + "\n\n" + final_output

    ttp_summary = expand_ttps(threat_intel)
    if ttp_summary:
        final_output += "\n" + ttp_summary

    return final_output
