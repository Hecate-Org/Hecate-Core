"""Shodan and Censys infrastructure exposure and fingerprinting provider."""

from __future__ import annotations

import logging
from typing import Any, Dict, Set, cast

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


def query_shodan_ip(ip: str) -> str:
    url = f"https://api.shodan.io/shodan/host/{ip}?key={_setting('SHODAN_API_KEY')}"
    try:
        resp = httpx.get(url, timeout=10.0)
        if resp.status_code == 200:
            data = cast(Dict[str, Any], resp.json())
            org = data.get("org", "Unknown")
            os_name = data.get("os", "Unknown OS")
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])

            summary = f"Org: {org} | OS: {os_name} | Open Ports: {ports}"
            if vulns:
                summary += f" | Vulns: {', '.join(vulns[:5])}"
            return summary
        elif resp.status_code == 404:
            return "No open ports found on Shodan."
        else:
            return f"Shodan API error: {resp.status_code}"
    except Exception as e:
        return f"Error querying Shodan: {e}"


def query_censys_ip(ip: str) -> str:
    """Query Censys for open ports, services, TLS certificates, and JARM/JA4 fingerprints."""
    token = _setting("CENSYS_API_TOKEN")
    if not token:
        return "CENSYS_API_TOKEN not configured."

    url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
    headers = {
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
        "Authorization": f"Bearer {token}",
    }
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            result = resp.json().get("result", {})
            data = result.get("resource", result)
            services = data.get("services", [])
            ports = [str(s.get("port")) for s in services if s.get("port")]

            # Extract software
            software_list = []
            jarm_hashes = []
            ja4_hashes = []
            cert_subjects = []

            for s in services:
                if s.get("software"):
                    for sw in s["software"]:
                        product = sw.get("product")
                        if product and product not in software_list:
                            software_list.append(product)

                tls = s.get("tls") or {}
                jarm = tls.get("jarm") or s.get("jarm")
                if jarm and str(jarm) not in jarm_hashes:
                    jarm_hashes.append(str(jarm))
                ja4 = tls.get("ja4") or s.get("ja4")
                if ja4 and str(ja4) not in ja4_hashes:
                    ja4_hashes.append(str(ja4))
                ja4s = tls.get("ja4s") or s.get("ja4s")
                if ja4s and str(ja4s) not in ja4_hashes:
                    ja4_hashes.append(str(ja4s))

                cert = tls.get("certificate") or {}
                subj = (
                    cert.get("parsed", {}).get("subject_dn")
                    or cert.get("subject_dn")
                    or cert.get("subject", {}).get("common_name")
                )
                if subj and str(subj) not in cert_subjects:
                    cert_subjects.append(str(subj))

            parts = [f"Open Ports: {ports}"]
            if software_list:
                parts.append(f"Software: {', '.join(software_list[:4])}")
            if jarm_hashes:
                parts.append(f"JARM: {', '.join(jarm_hashes[:2])}")
            if ja4_hashes:
                parts.append(f"JA4: {', '.join(ja4_hashes[:2])}")
            if cert_subjects:
                parts.append(f"TLS Cert: {', '.join(cert_subjects[:2])}")
            return " | ".join(parts)
        elif resp.status_code in (401, 403):
            return "Censys Auth Error (check CENSYS_API_TOKEN)."
        elif resp.status_code == 422:
            return "Censys API limit reached (insufficient credits/balance)."
        elif resp.status_code == 429:
            return "Censys rate limit exceeded."
        elif resp.status_code == 404:
            return "No data on Censys."
        else:
            return f"Censys API error: {resp.status_code}"
    except Exception as e:
        return f"Error querying Censys: {e}"


