"""URLhaus malware distribution and malicious link intelligence provider."""

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


def query_urlhaus_url(url: str) -> str:
    """Query abuse.ch URLhaus API for malicious URL status, threat classification, and payload info."""
    key = _setting("ABUSECH_API_KEY")
    if not key:
        return report("ABUSECH_API_KEY not configured.", 'unconfigured')
    clean_url = url.strip()
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {"Auth-Key": key}
    data = {"url": clean_url}
    try:
        resp = httpx.post(api_url, headers=headers, data=data, timeout=8.0)
        if resp.status_code == 200:
            res_json = resp.json()
            q_status = res_json.get("query_status")
            if q_status == "ok":
                url_status = res_json.get("url_status") or "unknown"
                threat = res_json.get("threat") or "malware_download"
                tags = res_json.get("tags") or []
                payloads = res_json.get("payloads") or []
                sig = ""
                if payloads and isinstance(payloads, list):
                    p0 = payloads[0]
                    if isinstance(p0, dict):
                        sig = p0.get("signature") or p0.get("file_type") or ""
                parts = [f"Status: {url_status}", f"Threat: {threat}"]
                if sig:
                    parts.append(f"Payload: {sig}")
                if tags:
                    parts.append(f"Tags: {', '.join(str(t) for t in tags[:3])}")
                return report(" | ".join(parts))
            elif q_status == "no_results":
                return report("Not listed on URLhaus.", 'missing')
            return report(f"URLhaus: {q_status}")
        elif resp.status_code in (401, 403):
            return report("URLhaus Auth Error (check ABUSECH_API_KEY).", 'errors')
        return report(f"HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying URLhaus: {e}")


def query_urlhaus_host(host: str) -> str:
    """Query abuse.ch URLhaus API for host (domain or IP) malware distribution history."""
    key = _setting("ABUSECH_API_KEY")
    if not key:
        return report("ABUSECH_API_KEY not configured.", 'unconfigured')
    clean_host = host.strip().lower()
    api_url = "https://urlhaus-api.abuse.ch/v1/host/"
    headers = {"Auth-Key": key}
    data = {"host": clean_host}
    try:
        resp = httpx.post(api_url, headers=headers, data=data, timeout=8.0)
        if resp.status_code == 200:
            res_json = resp.json()
            q_status = res_json.get("query_status")
            if q_status == "ok":
                cnt = res_json.get("url_count")
                if cnt is None:
                    cnt = len(res_json.get("urls") or [])
                firstseen = str(res_json.get("firstseen") or "")[:10]
                parts = [f"Malware host ({cnt} URL(s))"]
                if firstseen:
                    parts.append(f"First seen: {firstseen}")
                return report(" | ".join(parts))
            elif q_status == "no_results":
                return report("Not listed on URLhaus.", 'missing')
            return report(f"URLhaus: {q_status}")
        elif resp.status_code in (401, 403):
            return report("URLhaus Auth Error (check ABUSECH_API_KEY).", 'errors')
        return report(f"HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying URLhaus: {e}")


def query_urlhaus_payload(file_hash: str) -> str:
    """Query abuse.ch URLhaus API for payload hash (MD5 or SHA256) distribution info."""
    key = _setting("ABUSECH_API_KEY")
    if not key:
        return report("ABUSECH_API_KEY not configured.", 'unconfigured')
    clean_hash = file_hash.strip().lower()
    api_url = "https://urlhaus-api.abuse.ch/v1/payload/"
    headers = {"Auth-Key": key}
    field = "sha256_hash" if len(clean_hash) == 64 else "md5_hash"
    data = {field: clean_hash}
    try:
        resp = httpx.post(api_url, headers=headers, data=data, timeout=8.0)
        if resp.status_code == 200:
            res_json = resp.json()
            q_status = res_json.get("query_status")
            if q_status == "ok":
                sig = res_json.get("signature") or "Unknown"
                ftype = res_json.get("file_type") or "Unknown"
                cnt = res_json.get("url_count") or 0
                return report(f"Payload: {sig} ({ftype}) | Seen on {cnt} URL(s)")
            elif q_status == "no_results":
                return report("No payload on URLhaus.", 'missing')
            return report(f"URLhaus: {q_status}")
        elif resp.status_code in (401, 403):
            return report("URLhaus Auth Error (check ABUSECH_API_KEY).", 'errors')
        return report(f"HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying URLhaus: {e}")


