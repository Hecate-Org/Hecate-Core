"""crt.sh Certificate Transparency log analysis and sibling domain provider."""

from __future__ import annotations

import logging
import re
import time
from typing import Dict, List, Set, Tuple

import httpx
from hecate_agent.enrichment.constants import _KNOWN_PUBLISHER_DOMAINS


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


_CRTSH_CACHE: Dict[str, Tuple[float, str, List[str]]] = {}


_CRTSH_CACHE_TTL: float = 86400.0  # 24-hour cache TTL


_SHARED_HOSTING_SUFFIXES: Set[str] = {
    "pages.dev",
    "github.io",
    "gitlab.io",
    "workers.dev",
    "herokuapp.com",
    "azurewebsites.net",
    "s3.amazonaws.com",
    "cloudfront.net",
    "ngrok-free.app",
    "trycloudflare.com",
    "duckdns.org",
    "no-ip.com",
    "ddns.net",
    "firebaseapp.com",
}


def extract_sibling_domains_from_crtsh(domain: str) -> List[str]:
    """Query crt.sh Certificate Transparency logs to discover co-issued sibling subdomains and staging infrastructure."""
    clean = domain.strip().lower()
    now = time.monotonic()
    cached = _CRTSH_CACHE.get(clean)
    if cached and (now - cached[0] < _CRTSH_CACHE_TTL):
        return cached[2]

    apex = _get_apex_domain(clean)
    if any(clean.endswith(f".{suffix}") or clean == suffix for suffix in _SHARED_HOSTING_SUFFIXES):
        query_param = clean
    elif any(apex.endswith(f".{suffix}") or apex == suffix for suffix in _SHARED_HOSTING_SUFFIXES):
        query_param = clean
    else:
        query_param = f"%.{apex}" if apex else clean

    url = "https://crt.sh/"
    headers = {"Accept": "application/json", "User-Agent": "Hecate-Agent/2.0 (Threat-Hunting)"}
    params = {"q": query_param, "output": "json"}

    siblings: Set[str] = set()
    issuers: Set[str] = set()
    latest_date: str = ""
    cert_count = 0

    try:
        resp = httpx.get(url, headers=headers, params=params, timeout=10.0)
        if resp.status_code == 200:
            content_type = resp.headers.get("content-type", "")
            if "json" in content_type:
                data = resp.json()
            else:
                try:
                    data = resp.json()
                except Exception:
                    data = []

            if isinstance(data, list):
                cert_count = len(data)
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    raw_issuer = str(item.get("issuer_name", ""))
                    m_iss = re.search(r"O=([^,]+)", raw_issuer)
                    if m_iss:
                        issuers.add(m_iss.group(1).strip().strip("'\""))
                    elif raw_issuer:
                        issuers.add(raw_issuer.split(",")[-1].strip().strip("'\""))

                    dt = str(item.get("not_before") or item.get("entry_timestamp") or "")
                    if dt and (not latest_date or dt > latest_date):
                        latest_date = dt[:10]

                    names = str(item.get("name_value", "")).splitlines()
                    cn = item.get("common_name")
                    if cn:
                        names.append(str(cn))

                    for n in names:
                        sub = n.strip().lower().lstrip("*.").strip(".")
                        if (
                            sub
                            and len(sub) >= 3
                            and sub != clean
                            and "." in sub
                            and not any(sub == pub or sub.endswith(f".{pub}") for pub in _KNOWN_PUBLISHER_DOMAINS)
                        ):
                            siblings.add(sub)
    except Exception:
        pass

    sorted_sibs = sorted(siblings)
    sorted_iss = sorted(issuers)
    parts = [f"Certificates: {cert_count} logged"]
    if sorted_iss:
        parts.append(f"CAs: {', '.join(sorted_iss[:2])}")
    if latest_date:
        parts.append(f"Latest: {latest_date}")
    if sorted_sibs:
        sample = ", ".join(sorted_sibs[:5])
        if len(sorted_sibs) > 5:
            sample += f" (+{len(sorted_sibs) - 5} more)"
        parts.append(f"Sibling Domains ({len(sorted_sibs)}): {sample}")
    else:
        parts.append("No sibling subdomains found")

    summary_str = " | ".join(parts)
    _CRTSH_CACHE[clean] = (now, summary_str, sorted_sibs)
    return sorted_sibs


def query_crtsh_domain(domain: str) -> str:
    """Query crt.sh Certificate Transparency logs for co-issued sibling subdomains and staging infrastructure."""
    clean = domain.strip().lower()
    now = time.monotonic()
    cached = _CRTSH_CACHE.get(clean)
    if cached and (now - cached[0] < _CRTSH_CACHE_TTL):
        return cached[1]

    apex = _get_apex_domain(clean)
    if any(clean.endswith(f".{suffix}") or clean == suffix for suffix in _SHARED_HOSTING_SUFFIXES):
        query_param = clean
    elif any(apex.endswith(f".{suffix}") or apex == suffix for suffix in _SHARED_HOSTING_SUFFIXES):
        query_param = clean
    else:
        query_param = f"%.{apex}" if apex else clean

    url = "https://crt.sh/"
    headers = {"Accept": "application/json", "User-Agent": "Hecate-Agent/2.0 (Threat-Hunting)"}
    params = {"q": query_param, "output": "json"}

    try:
        resp = httpx.get(url, headers=headers, params=params, timeout=10.0)
        if resp.status_code == 200:
            content_type = resp.headers.get("content-type", "")
            if "json" in content_type:
                data = resp.json()
            else:
                try:
                    data = resp.json()
                except Exception:
                    data = []

            if not isinstance(data, list) or not data:
                res = "No certificates found on crt.sh."
                _CRTSH_CACHE[clean] = (now, res, [])
                return res

            siblings: Set[str] = set()
            issuers: Set[str] = set()
            latest_date: str = ""

            for item in data:
                if not isinstance(item, dict):
                    continue
                raw_issuer = str(item.get("issuer_name", ""))
                m_iss = re.search(r"O=([^,]+)", raw_issuer)
                if m_iss:
                    issuers.add(m_iss.group(1).strip().strip("'\""))
                elif raw_issuer:
                    issuers.add(raw_issuer.split(",")[-1].strip().strip("'\""))

                dt = str(item.get("not_before") or item.get("entry_timestamp") or "")
                if dt and (not latest_date or dt > latest_date):
                    latest_date = dt[:10]

                names = str(item.get("name_value", "")).splitlines()
                cn = item.get("common_name")
                if cn:
                    names.append(str(cn))

                for n in names:
                    sub = n.strip().lower().lstrip("*.").strip(".")
                    if (
                        sub
                        and len(sub) >= 3
                        and sub != clean
                        and "." in sub
                        and not any(sub == pub or sub.endswith(f".{pub}") for pub in _KNOWN_PUBLISHER_DOMAINS)
                    ):
                        siblings.add(sub)

            sorted_sibs = sorted(siblings)
            sorted_iss = sorted(issuers)
            parts = [f"Certificates: {len(data)} logged"]
            if sorted_iss:
                parts.append(f"CAs: {', '.join(sorted_iss[:2])}")
            if latest_date:
                parts.append(f"Latest: {latest_date}")
            if sorted_sibs:
                sample = ", ".join(sorted_sibs[:5])
                if len(sorted_sibs) > 5:
                    sample += f" (+{len(sorted_sibs) - 5} more)"
                parts.append(f"Sibling Domains ({len(sorted_sibs)}): {sample}")
            else:
                parts.append("No sibling subdomains found")

            res = " | ".join(parts)
            _CRTSH_CACHE[clean] = (now, res, sorted_sibs)
            return res
        elif resp.status_code == 429:
            return "crt.sh rate limit exceeded."
        return f"crt.sh error: HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying crt.sh: {e}"


