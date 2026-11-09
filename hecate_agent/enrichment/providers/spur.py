"""SPUR IP anonymous infrastructure and proxy intelligence provider."""

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


_SPUR_CACHE: Dict[str, Tuple[float, str, Dict[str, Any]]] = {}


_SPUR_CACHE_TTL: float = 86400.0  # 24-hour cache TTL


def extract_spur_context(ip: str) -> Dict[str, Any]:
    """Query Spur.us Context API for structured IP intelligence, proxy detection, and tunnels."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return {"configured": False, "error": "Empty IP address"}

    try:
        addr = ipaddress.ip_address(clean_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return {"configured": True, "found": False, "message": "Private/internal IP address"}
    except ValueError:
        return {"configured": False, "error": f"Invalid IP address: {clean_ip}"}

    key = _setting("SPUR_API_KEY")
    if not key:
        return {"configured": False, "error": "SPUR_API_KEY not configured"}

    now = time.time()
    cached = _SPUR_CACHE.get(clean_ip)
    if cached and (now - cached[0] < _SPUR_CACHE_TTL):
        return cached[2]

    url = f"https://api.spur.us/v2/context/{clean_ip}"
    headers = {"Token": key, "Accept": "application/json"}
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            data = cast(Dict[str, Any], resp.json())
            data["configured"] = True
            data["found"] = True
            return data
        elif resp.status_code == 404:
            return {"configured": True, "found": False, "message": "Not observed on Spur"}
        elif resp.status_code in (401, 403):
            return {"configured": True, "error": "Spur Auth Error (check SPUR_API_KEY)"}
        elif resp.status_code == 429:
            return {"configured": True, "error": "Spur rate limit exceeded"}
        return {"configured": True, "error": f"Spur API error: HTTP {resp.status_code}"}
    except httpx.TimeoutException:
        return {"configured": True, "error": "Spur query timed out"}
    except Exception as e:
        return {"configured": True, "error": f"Error querying Spur: {e}"}


def query_spur_ip(ip: str) -> str:
    """Query Spur.us Context API for residential proxies, VPN tunnels, and bulletproof infrastructure."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return "Invalid IP address."

    try:
        addr = ipaddress.ip_address(clean_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return "Private/internal IP address."
    except ValueError:
        return f"Invalid IP address: {clean_ip}"

    key = _setting("SPUR_API_KEY")
    if not key:
        return "SPUR_API_KEY not configured."

    now = time.time()
    cached = _SPUR_CACHE.get(clean_ip)
    if cached and (now - cached[0] < _SPUR_CACHE_TTL):
        return cached[1]

    data = extract_spur_context(clean_ip)
    if not data.get("configured", True):
        return str(data.get("error") or "SPUR_API_KEY not configured.")
    if data.get("error"):
        return str(data["error"])
    if not data.get("found", True):
        res = "Not observed on Spur."
        _SPUR_CACHE[clean_ip] = (now, res, data)
        return res

    infra = data.get("infrastructure") or ""
    as_info = data.get("as") or {}
    as_num = as_info.get("number")
    as_org = as_info.get("organization") or ""

    tunnels = data.get("tunnels") or []
    tunnel_strs = []
    for t in tunnels:
        if isinstance(t, dict):
            op = t.get("operator") or "Unknown"
            anon = " (Anonymous)" if t.get("anonymous") else ""
            tunnel_strs.append(f"{op}{anon}")
        elif isinstance(t, str):
            tunnel_strs.append(t)

    client = data.get("client") or {}
    proxies = client.get("proxies") or []
    risks = data.get("risks") or []
    location = data.get("location") or {}
    city = location.get("city")
    country = location.get("country")

    parts = []
    if infra:
        parts.append(f"Infra: {infra}")
    if as_num:
        parts.append(f"AS: AS{as_num} ({as_org})" if as_org else f"AS: AS{as_num}")
    elif as_org:
        parts.append(f"Org: {as_org}")
    if tunnel_strs:
        parts.append(f"Tunnels: {', '.join(tunnel_strs[:3])}")
    if proxies:
        parts.append(f"Proxies: {', '.join(str(p) for p in proxies[:3])}")
    if risks:
        parts.append(f"Risks: {', '.join(str(r) for r in risks[:4])}")
    loc_parts = [p for p in (city, country) if p]
    if loc_parts:
        parts.append(f"Loc: {', '.join(loc_parts)}")

    summary = " | ".join(parts) if parts else "No threat or proxy signals reported."
    _SPUR_CACHE[clean_ip] = (now, summary, data)
    return summary


