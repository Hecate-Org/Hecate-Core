"""AbuseIPDB IP reputation and abusive activity reporting provider."""

from __future__ import annotations

from hecate_agent.enrichment.result import report

import logging
from typing import Set

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


def query_abuseipdb_ip(ip: str) -> str:
    """Query AbuseIPDB for IP abuse confidence score, reports, ISP, and usage type."""
    key = _setting("ABUSEIPDB_API_KEY")
    if not key:
        return report("ABUSEIPDB_API_KEY not configured.", 'unconfigured')
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
    }
    try:
        resp = httpx.get(url, headers=headers, params=params, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            isp = data.get("isp") or "Unknown"
            usage = data.get("usageType") or "Unknown"
            country = data.get("countryCode")

            parts = [f"Score: {score}% (Reports: {reports})", f"ISP: {isp}", f"Usage: {usage}"]
            if country:
                parts.append(f"Country: {country}")
            return report(" | ".join(parts))
        elif resp.status_code in (401, 403):
            return report("AbuseIPDB Auth Error (check ABUSEIPDB_API_KEY).", 'errors')
        elif resp.status_code == 429:
            return report("AbuseIPDB rate limit exceeded.", 'errors')
        elif resp.status_code in (404, 422):
            return report("No data on AbuseIPDB.", 'missing')
        return report(f"AbuseIPDB error: HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying AbuseIPDB: {e}")


