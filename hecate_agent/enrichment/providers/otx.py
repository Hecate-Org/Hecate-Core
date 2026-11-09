"""AlienVault OTX threat pulses and indicator telemetry provider."""

from __future__ import annotations

from hecate_agent.enrichment.result import report

import logging
from typing import Any, Dict, List, Set

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


def query_otx_indicator(indicator_type: str, indicator: str) -> str:
    """Query AlienVault OTX Direct API for indicator general metadata, pulse associations, adversaries, and passive DNS.

    Supported indicator_type values: 'IPv4', 'domain', 'file', 'cve'.
    """
    key = _setting("OTX_API_KEY") or _setting("HECATE_RUNNER_OTX_API_KEY")
    if not key:
        return report("OTX_API_KEY not configured.", 'unconfigured')

    headers = {
        "X-OTX-API-KEY": key,
        "Accept": "application/json",
    }
    norm_type = indicator_type.strip()
    clean_val = indicator.strip()

    if norm_type.lower() in ("ip", "ipv4"):
        norm_type = "IPv4"
    elif norm_type.lower() in ("domain", "hostname"):
        norm_type = "domain"
        clean_val = clean_val.removeprefix("http://").removeprefix("https://").split("/")[0]
    elif norm_type.lower() in ("hash", "file", "sha256", "sha1", "md5"):
        norm_type = "file"
        clean_val = clean_val.lower()
    elif norm_type.lower() in ("cve", "vulnerability"):
        norm_type = "cve"
        clean_val = clean_val.upper()

    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/{norm_type}/{clean_val}/general"
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            pulse_info = data.get("pulse_info") or {}
            cnt = int(pulse_info.get("count", 0))
            pulses = pulse_info.get("pulses") or []

            adversaries: List[str] = []
            for p in pulses:
                adv = p.get("adversary")
                if adv and isinstance(adv, str):
                    adv_clean = adv.strip()
                    if adv_clean and adv_clean.lower() != "unknown" and adv_clean not in adversaries:
                        adversaries.append(adv_clean)

            titles: List[str] = [str(p.get("name")).strip() for p in pulses if p.get("name") and str(p.get("name")).strip()]

            tags: List[str] = []
            for p in pulses:
                for t in p.get("tags") or []:
                    if t and isinstance(t, str):
                        t_clean = t.strip()
                        if t_clean and t_clean not in tags:
                            tags.append(t_clean)

            # For IPs and domains, attempt a quick passive DNS query to get correlated hostnames
            pdns_hosts: List[str] = []
            if norm_type in ("IPv4", "domain"):
                try:
                    pdns_url = f"https://otx.alienvault.com/api/v1/indicators/{norm_type}/{clean_val}/passive_dns"
                    pdns_resp = httpx.get(pdns_url, headers=headers, timeout=3.0)
                    if pdns_resp.status_code == 200:
                        entries = pdns_resp.json().get("passive_dns") or []
                        for e in entries:
                            h = e.get("hostname") or e.get("address")
                            if h and isinstance(h, str) and h not in pdns_hosts and h.lower() != clean_val.lower():
                                pdns_hosts.append(h)
                                if len(pdns_hosts) >= 2:
                                    break
                except Exception:
                    pass

            parts: List[str] = []
            if cnt > 0:
                p_desc = f"{cnt} Pulse(s)"
                if titles:
                    p_desc += f" (e.g. '{titles[0]}')"
                parts.append(p_desc)
                if adversaries:
                    parts.append(f"Adversary: {', '.join(adversaries[:2])}")
                if tags:
                    parts.append(f"Tags: {', '.join(tags[:3])}")
                if pdns_hosts:
                    parts.append(f"Passive DNS: {', '.join(pdns_hosts)}")
                return report(" | ".join(parts))
            else:
                if pdns_hosts:
                    return report(f"0 Pulses | Passive DNS: {', '.join(pdns_hosts)}")
                return report("Not observed in OTX Pulses.", 'missing')
        elif resp.status_code == 404:
            return report("No record on OTX.", 'missing')
        elif resp.status_code in (401, 403):
            return report("OTX Auth Error (check OTX_API_KEY).", 'errors')
        return report(f"OTX error: HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying OTX: {e}")


def query_otx_ip(ip: str) -> str:
    """Query AlienVault OTX Direct API for an IPv4 address."""
    return report(query_otx_indicator("IPv4", ip))


def query_otx_domain(domain: str) -> str:
    """Query AlienVault OTX Direct API for a domain."""
    return report(query_otx_indicator("domain", domain))


def query_otx_hash(file_hash: str) -> str:
    """Query AlienVault OTX Direct API for a file hash."""
    return report(query_otx_indicator("file", file_hash))


def query_otx_cve(cve: str) -> str:
    """Query AlienVault OTX Direct API for a CVE vulnerability."""
    return report(query_otx_indicator("cve", cve))


def query_otx_pdns(indicator: str, is_ip: bool = False) -> List[Dict[str, Any]]:
    """Query AlienVault OTX Passive DNS endpoint for resolutions."""
    key = _setting("OTX_API_KEY")
    if not key:
        return []
    clean = refang(indicator).strip()
    norm_type = "IPv4" if is_ip else "domain"
    url = f"https://otx.alienvault.com/api/v1/indicators/{norm_type}/{clean}/passive_dns"
    headers = {"X-OTX-API-KEY": key, "Accept": "application/json"}
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            entries = []
            for item in resp.json().get("passive_dns", []):
                val = item.get("hostname") if is_ip else item.get("address")
                ts = item.get("last")
                if val:
                    entries.append({"value": val, "date": ts, "source": "OTX"})
            return entries
    except Exception:
        pass
    return []


