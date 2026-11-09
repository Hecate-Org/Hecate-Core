"""VirusTotal v3 file, IP, domain, and behavioral intelligence provider."""

from __future__ import annotations

from hecate_agent.enrichment.result import report

import logging
from typing import Any, Dict, List, Set

import httpx
from hecate_agent.enrichment.constants import _KNOWN_PUBLISHER_DOMAINS

from hecate_agent.core.provenance import is_valid_ipv4

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


def extract_vt_behavior_graph(file_hash: str) -> Dict[str, Any]:
    """Query VirusTotal v3 behaviour_summary endpoint for execution graph and sandbox techniques."""
    api_key = _setting("VT_API_KEY")
    if not api_key:
        return {}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        resp = httpx.get(url, headers=headers, timeout=12.0)
        if resp.status_code != 200:
            return {}
        data = resp.json().get("data", {})
        if not isinstance(data, dict):
            return {}

        tags = [str(t).upper() for t in data.get("tags", []) if t]

        techniques: List[Dict[str, str]] = []
        seen_techs: Set[str] = set()
        for item in data.get("mitre_attack_techniques", []):
            if isinstance(item, dict) and item.get("id"):
                tid = str(item["id"]).strip().upper()
                if tid and tid not in seen_techs:
                    seen_techs.add(tid)
                    techniques.append({"id": tid, "name": str(item.get("signature_description") or "")})

        contacted_ips: List[str] = []
        for traffic in data.get("ip_traffic", []):
            if isinstance(traffic, dict) and traffic.get("destination_ip"):
                cip = str(traffic["destination_ip"]).strip()
                if cip and is_valid_ipv4(cip) and cip not in contacted_ips:
                    contacted_ips.append(cip)

        contacted_domains: List[str] = []
        for d in data.get("dns_lookups", []):
            if isinstance(d, dict) and d.get("hostname"):
                dom = str(d["hostname"]).strip().lower()
                if dom and dom not in _KNOWN_PUBLISHER_DOMAINS and dom not in contacted_domains:
                    contacted_domains.append(dom)

        dropped_files: List[str] = []
        for f in data.get("files_dropped", []):
            if isinstance(f, dict) and f.get("path"):
                p = str(f["path"]).strip()
                if p and p not in dropped_files:
                    dropped_files.append(p)

        return {
            "tags": tags,
            "mitre_techniques": techniques,
            "contacted_ips": contacted_ips,
            "contacted_domains": contacted_domains,
            "dropped_files": dropped_files,
        }
    except Exception as exc:
        logger.debug("Failed to query VT behaviour_summary for %s: %s", file_hash, exc)
        return {}


def query_vt_hash(file_hash: str) -> str:
    api_key = _setting("VT_API_KEY")
    if not api_key:
        return report("Not found or error.", "unconfigured")
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            names = data.get("names", [])
            malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
            threat_label = data.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown")
            base = f"Malicious hits: {malicious} | Threat Label: {threat_label} | Known Filenames: {', '.join(names[:3])}"

            bg = extract_vt_behavior_graph(file_hash)
            extras = []
            if bg.get("tags"):
                extras.append(f"Capabilities: {', '.join(bg['tags'][:4])}")
            if bg.get("mitre_techniques"):
                t_ids = [t["id"] for t in bg["mitre_techniques"][:4]]
                extras.append(f"MITRE: {', '.join(t_ids)}")
            if bg.get("contacted_ips"):
                extras.append(f"C2 IPs: {', '.join(bg['contacted_ips'][:3])}")
            text = f"{base} | {' | '.join(extras)}" if extras else base
            return report(
                text,
                "flagged" if malicious else "found",
                verdict="malicious" if malicious else "clean",
                facts={"malicious": malicious, "threat_label": threat_label},
            )
        return report("Not found or error.", "missing")
    except Exception as e:
        return report(f"Error querying VT: {e}")


def query_vt_ip(ip: str) -> str:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": _setting("VT_API_KEY")}
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
            asn = data.get("asn", "Unknown")
            owner = data.get("as_owner", "Unknown")
            return report(
                f"Malicious hits: {malicious} | ASN: {asn} | Owner: {owner}",
                "flagged" if malicious else "found",
                verdict="malicious" if malicious else "clean",
                facts={"malicious": malicious},
            )
        return report("Not found or error.", "missing")
    except Exception as e:
        return report(f"Error querying VT: {e}")


def query_vt_domain(domain: str) -> str:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": _setting("VT_API_KEY")}
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
            registrar = data.get("registrar", "Unknown")
            categories = data.get("categories", {})
            cat_sample = list(categories.values())[:2]
            cat_str = f" | Category: {', '.join(cat_sample)}" if cat_sample else ""
            return report(
                f"Malicious hits: {malicious} | Registrar: {registrar}{cat_str}",
                "flagged" if malicious else "found",
                verdict="malicious" if malicious else "clean",
                facts={"malicious": malicious},
            )
        elif resp.status_code == 404:
            return report("Domain not found on VirusTotal.", "missing")
        return report(f"HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying VT: {e}")


def query_vt_pdns_domain(domain: str) -> List[Dict[str, Any]]:
    """Query VirusTotal v3 for domain passive DNS resolutions."""
    key = _setting("VT_API_KEY") or _setting("HECATE_RUNNER_VT_API_KEY")
    if not key:
        return []
    clean_domain = domain.strip().lower()
    url = f"https://www.virustotal.com/api/v3/domains/{clean_domain}/resolutions"
    headers = {"x-apikey": key, "Accept": "application/json"}
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            entries = []
            for item in resp.json().get("data", []):
                attr = item.get("attributes", {})
                ip = attr.get("ip_address")
                date_val = attr.get("date")
                if ip:
                    entries.append({"value": ip, "date": date_val, "source": "VT"})
            return entries
    except Exception:
        pass
    return []


def query_vt_pdns_ip(ip: str) -> List[Dict[str, Any]]:
    """Query VirusTotal v3 for IP passive DNS resolutions."""
    key = _setting("VT_API_KEY") or _setting("HECATE_RUNNER_VT_API_KEY")
    if not key:
        return []
    clean_ip = refang(ip).strip()
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{clean_ip}/resolutions"
    headers = {"x-apikey": key, "Accept": "application/json"}
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            entries = []
            for item in resp.json().get("data", []):
                attr = item.get("attributes", {})
                host = attr.get("host_name")
                date_val = attr.get("date")
                if host:
                    entries.append({"value": host, "date": date_val, "source": "VT"})
            return entries
    except Exception:
        pass
    return []


