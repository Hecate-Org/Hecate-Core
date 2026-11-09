"""Shadowserver Foundation device and malware reporting provider."""

from __future__ import annotations

from hecate_agent.enrichment.result import report

import ipaddress
import logging
import re
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


def query_shadowserver_ip(ip: str) -> str:
    """Query Shadowserver Foundation free public API for network origin, BGP ASN, and prefix."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return report("Invalid IP address.", 'skipped')
    try:
        addr = ipaddress.ip_address(clean_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return report("Private/internal IP address.", 'skipped')
    except ValueError:
        return report(f"Invalid IP address: {clean_ip}")

    try:
        url = f"https://api.shadowserver.org/net/asn?query={clean_ip}"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            if not data or not isinstance(data, dict):
                return report(f"No ASN record on Shadowserver for {clean_ip}.")
            asn = data.get("asn") or data.get("origin")
            asn_name = data.get("asn_name") or "Unknown"
            prefix = data.get("prefix") or ""
            isp = data.get("isp_name")
            parts = [f"ASN: AS{asn} ({asn_name})"]
            if prefix:
                parts.append(f"Prefix: {prefix}")
            if isp and isp != asn_name:
                parts.append(f"ISP: {isp}")
            return report(" · ".join(parts))
        elif resp.status_code == 404:
            return report(f"No record on Shadowserver ({clean_ip}).")
        return report(f"Shadowserver error: HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying Shadowserver: {e}")


def query_shadowserver_hash(file_hash: str) -> str:
    """Query Shadowserver Foundation free malware API for known sample signatures and imphash."""
    clean_hash = file_hash.strip().lower()
    if not re.match(r"^[a-f0-9]{32,64}$", clean_hash):
        return report(f"Invalid hash format '{file_hash}'.")

    try:
        url = f"https://api.shadowserver.org/malware/info?sample={clean_hash}"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            if not data or not isinstance(data, list):
                return report(f"No record on Shadowserver for {clean_hash}.")
            item = data[0] if isinstance(data[0], dict) else {}
            av_list = item.get("anti_virus") or []
            imphash = item.get("import_hash") or item.get("imphash")
            sigs = []
            for av in av_list:
                if isinstance(av, dict) and av.get("signature"):
                    sig = str(av["signature"]).strip()
                    if sig and sig not in sigs:
                        sigs.append(sig)
            parts = []
            if sigs:
                parts.append(f"AV Detections: {len(av_list)} hits ({', '.join(sigs[:3])})")
            elif av_list:
                parts.append(f"AV Detections: {len(av_list)} vendor hits")
            else:
                parts.append("Sample recorded in Shadowserver repository")
            if imphash:
                parts.append(f"imphash: {imphash}")
            return report(" · ".join(parts))
        elif resp.status_code == 404:
            return report(f"No record on Shadowserver ({clean_hash}).")
        return report(f"Shadowserver error: HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying Shadowserver: {e}")


