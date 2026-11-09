"""Tor Project and IPinfo anonymity, VPN, and egress node provider."""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any, Dict, Set, Tuple, cast

import httpx


logger = logging.getLogger(__name__)


def _setting(name: str, default: str = "") -> str:
    from hecate_agent.orchestrator import enrichment
    return enrichment._setting(name, default)


def _misp_verify_tls() -> bool:
    from hecate_agent.orchestrator import enrichment
    return enrichment._misp_verify_tls()


def refang(value: str) -> str:
    from hecate_agent.orchestrator import enrichment
    return enrichment.refang(value)


def _get_apex_domain(domain: str) -> str:
    from hecate_agent.orchestrator import enrichment
    return enrichment._get_apex_domain(domain)


def _get_known_publishers() -> Set[str]:
    from hecate_agent.orchestrator import enrichment
    return getattr(enrichment, "_KNOWN_PUBLISHER_DOMAINS", set())


_TOR_EXIT_CACHE: Dict[str, Any] = {"data": set(), "ts": 0.0}


_TOR_EXIT_TTL: float = 3600.0  # 1-hour cache TTL (matches Tor consensus cycle)


def _get_tor_exit_nodes() -> Set[str]:
    """Fetch and cache the official Tor Project bulk exit node list (1-hour TTL)."""
    now = time.time()
    cached_set = _TOR_EXIT_CACHE.get("data")
    if cached_set and (now - float(_TOR_EXIT_CACHE.get("ts", 0.0)) < _TOR_EXIT_TTL):
        return cast(Set[str], cached_set)
    try:
        url = "https://check.torproject.org/torbulkexitlist"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            exit_ips: Set[str] = {line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")}
            if exit_ips:
                _TOR_EXIT_CACHE["data"] = exit_ips
                _TOR_EXIT_CACHE["ts"] = now
                return exit_ips
    except Exception as e:
        logger.debug(f"Failed to fetch Tor bulk exit list: {e}")
    return cast(Set[str], cached_set) if cached_set else set()


def is_tor_exit_node(ip: str) -> bool:
    """Return True if the IP address is an active Tor Project exit node."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return False
    return clean_ip in _get_tor_exit_nodes()


def query_tor_exit(ip: str) -> str:
    """Query whether an IP is an active Tor exit node."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return "Invalid IP address."
    if is_tor_exit_node(clean_ip):
        return "Tor Exit Node: Confirmed Active Exit Node [Tor Project consensus]"
    return "Not a Tor exit node."


_IPINFO_CACHE: Dict[str, Tuple[float, str, Dict[str, Any]]] = {}


_IPINFO_CACHE_TTL: float = 86400.0  # 24-hour cache TTL


def extract_ipinfo_context(ip: str) -> Dict[str, Any]:
    """Query IPinfo.io for IP geolocation, organization, hosting/datacenter classification, and privacy."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return {"configured": False, "error": "Empty IP address"}

    try:
        addr = ipaddress.ip_address(clean_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return {"configured": True, "found": False, "bogon": True, "message": "Private/internal IP address."}
    except ValueError:
        return {"configured": False, "error": f"Invalid IP address: {clean_ip}"}

    now = time.time()
    cached = _IPINFO_CACHE.get(clean_ip)
    if cached and (now - cached[0] < _IPINFO_CACHE_TTL):
        return cached[2]

    token = _setting("IPINFO_TOKEN") or _setting("IPINFO_API_KEY")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"https://ipinfo.io/{clean_ip}/json"
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            data = cast(Dict[str, Any], resp.json())
            data["configured"] = True
            data["found"] = True
            return data
        elif resp.status_code == 404:
            return {"configured": True, "found": False, "message": "Not found on IPinfo"}
        elif resp.status_code == 429:
            return {"configured": True, "error": "IPinfo rate limit exceeded"}
        return {"configured": True, "error": f"IPinfo HTTP {resp.status_code}"}
    except Exception as e:
        return {"configured": True, "error": f"Error querying IPinfo: {e}"}


def query_ipinfo_ip(ip: str) -> str:
    """Query IPinfo for ASN, organization, hosting type, and privacy flags."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return "Invalid IP address."

    data = extract_ipinfo_context(clean_ip)
    if not data.get("configured", True):
        return str(data.get("error") or "IPinfo error.")
    if data.get("error"):
        return str(data["error"])
    if not data.get("found", True):
        return str(data.get("message") or "Not found on IPinfo.")

    now = time.time()
    cached = _IPINFO_CACHE.get(clean_ip)
    if cached and (now - cached[0] < _IPINFO_CACHE_TTL):
        return cached[1]

    org = data.get("org") or ""
    hostname = data.get("hostname") or ""
    city = data.get("city")
    region = data.get("region")
    country = data.get("country")
    anycast = data.get("anycast", False)
    privacy = data.get("privacy") or {}
    company = data.get("company") or {}

    is_vpn = privacy.get("vpn", False)
    is_proxy = privacy.get("proxy", False)
    is_tor = privacy.get("tor", False)
    is_hosting = privacy.get("hosting", False) or company.get("type") == "hosting"
    service = privacy.get("service")

    tags = []
    if is_tor:
        tags.append("Tor")
    if is_vpn:
        tags.append(f"VPN ({service})" if service else "VPN")
    if is_proxy:
        tags.append("Proxy")
    if is_hosting:
        tags.append("Hosting/Datacenter")
    if anycast:
        tags.append("Anycast")

    parts = []
    if tags:
        parts.append(f"Classification: {', '.join(tags)}")
    elif is_hosting:
        parts.append("Classification: Hosting/Datacenter")

    if org:
        parts.append(f"Org: {org}")
    if hostname and not hostname.endswith(".in-addr.arpa"):
        parts.append(f"Host: {hostname}")

    loc_parts = [p for p in (city, region, country) if p]
    if loc_parts:
        parts.append(f"Loc: {', '.join(loc_parts)}")

    summary = " | ".join(parts) if parts else "Benign ISP / Non-proxy."
    _IPINFO_CACHE[clean_ip] = (now, summary, data)
    return summary


def query_anonymity_proxy_ip(ip: str) -> str:
    """Unified anonymity & proxy intelligence combining Tor Project consensus + IPinfo context."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return "Invalid IP address."

    try:
        addr = ipaddress.ip_address(clean_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "Private/internal IP address."
    except ValueError:
        return f"Invalid IP address: {clean_ip}"

    tor_active = is_tor_exit_node(clean_ip)
    ipinfo_str = query_ipinfo_ip(clean_ip)

    items = []
    sources = set()
    if tor_active:
        items.append("Tor Exit Node (Active)")
        sources.add("Tor Project")

    if (
        ipinfo_str
        and not ipinfo_str.startswith("Error")
        and not ipinfo_str.startswith("IPinfo HTTP")
        and not ipinfo_str.startswith("Private")
    ):
        items.append(ipinfo_str)
        sources.add("IPinfo")

    if not items:
        if tor_active:
            return "Tor Exit Node: Active [Tor Project]"
        return "Benign ISP / Non-proxy."

    src_tag = f" [{', '.join(sorted(sources))}]" if sources else ""
    return f"{' | '.join(items)}{src_tag}"


