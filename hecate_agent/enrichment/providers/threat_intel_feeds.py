"""Abuse.ch feeds (ThreatFox, MalwareBazaar, Feodo, SSLBL) provider."""

from __future__ import annotations

from hecate_agent.enrichment.result import report

import logging
import time
from typing import Any, Dict, List, Set, Tuple, cast

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


_FEODO_CACHE: Dict[str, Any] = {"data": None, "ts": 0.0}


_SSLBL_CACHE: Dict[str, Any] = {"data": None, "ts": 0.0}


def query_threatfox(indicator: str) -> str:
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": _setting("ABUSECH_API_KEY"), "Content-Type": "application/json"}
    payload = {"query": "search_ioc", "search_term": indicator}
    try:
        resp = httpx.post(url, headers=headers, json=payload, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("data"):
                hits = data["data"]
                # Get the most recent threat type and malware alias
                threat_type = hits[0].get("threat_type", "Unknown")
                malware = hits[0].get("malware_printable", "Unknown Malware")
                tags = hits[0].get("tags", [])

                summary = f"Type: {threat_type} | Malware: {malware}"
                if tags:
                    summary += f" | Tags: {', '.join(tags[:3])}"
                return report(summary)
            elif data.get("query_status") == "no_result":
                return report("No results on ThreatFox.", 'missing')
            else:
                return report(f"ThreatFox error: {data.get('query_status')}")
        return report(f"HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying ThreatFox: {e}")


def query_malwarebazaar(file_hash: str) -> str:
    """Query Abuse.ch MalwareBazaar for sample metadata, file type, signature, and YARA rules."""
    key = _setting("ABUSECH_API_KEY")
    if not key:
        return report("ABUSECH_API_KEY not configured.", 'unconfigured')
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": key}
    data = {"query": "get_info", "hash": file_hash}
    try:
        resp = httpx.post(url, headers=headers, data=data, timeout=10.0)
        if resp.status_code == 200:
            payload = resp.json()
            status = payload.get("query_status")
            if status == "ok" and payload.get("data"):
                item = payload["data"][0]
                sig = item.get("signature") or "Unknown"
                ftype = item.get("file_type") or "Unknown"
                delivery = item.get("delivery_method")
                raw_yara = item.get("yara_rules") or []
                yara_rules: List[str] = [
                    str(y.get("rule_name")) for y in raw_yara if isinstance(y, dict) and y.get("rule_name")
                ]
                tags: List[str] = [str(t) for t in (item.get("tags") or []) if t]

                parts = [f"Family: {sig}", f"Type: {ftype}"]
                if delivery:
                    parts.append(f"Delivery: {delivery}")
                if yara_rules:
                    parts.append(f"YARA: {', '.join(yara_rules[:3])}")
                elif tags:
                    parts.append(f"Tags: {', '.join(tags[:3])}")
                return report(" | ".join(parts))
            elif status == "hash_not_found":
                return report("No sample found on MalwareBazaar.", 'missing')
            else:
                return report(f"MalwareBazaar: {status}")
        elif resp.status_code in (401, 403):
            return report("MalwareBazaar Auth Error (check ABUSECH_API_KEY).", 'errors')
        return report(f"HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying MalwareBazaar: {e}")


def _get_feodo_ip_map() -> Dict[str, Dict[str, Any]]:
    """Fetch and cache abuse.ch Feodo Tracker IP blocklist (1-hour TTL)."""
    now = time.time()
    if _FEODO_CACHE.get("data") is not None and (now - float(_FEODO_CACHE.get("ts", 0.0)) < 3600.0):
        return cast(Dict[str, Dict[str, Any]], _FEODO_CACHE["data"])
    try:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            entries = resp.json()
            ip_map: Dict[str, Dict[str, Any]] = {
                str(item["ip_address"]): item for item in entries if isinstance(item, dict) and item.get("ip_address")
            }
            _FEODO_CACHE["data"] = ip_map
            _FEODO_CACHE["ts"] = now
            return ip_map
    except Exception as e:
        logger.debug(f"Failed to fetch Feodo Tracker blocklist: {e}")
    cached = _FEODO_CACHE.get("data")
    return cast(Dict[str, Dict[str, Any]], cached) if cached is not None else {}


def _get_sslbl_fingerprint_map() -> Dict[str, Tuple[str, str]]:
    """Fetch and cache abuse.ch SSL Blacklist certificate & JA3 fingerprints (1-hour TTL)."""
    now = time.time()
    if _SSLBL_CACHE.get("data") is not None and (now - float(_SSLBL_CACHE.get("ts", 0.0)) < 3600.0):
        return cast(Dict[str, Tuple[str, str]], _SSLBL_CACHE["data"])
    try:
        url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            res_map: Dict[str, Tuple[str, str]] = {}
            for line in resp.text.splitlines():
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                if len(parts) >= 3:
                    dt, sha1, reason = parts[0].strip(), parts[1].strip().lower(), parts[2].strip()
                    res_map[sha1] = (reason, dt)
            try:
                ja3_resp = httpx.get("https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv", timeout=3.0)
                if ja3_resp.status_code == 200:
                    for line in ja3_resp.text.splitlines():
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(",")
                        if len(parts) >= 4:
                            ja3_md5, reason = parts[0].strip().lower(), parts[3].strip()
                            res_map[ja3_md5] = (f"JA3 {reason}", parts[1].strip())
            except Exception:
                pass
            _SSLBL_CACHE["data"] = res_map
            _SSLBL_CACHE["ts"] = now
            return res_map
    except Exception as e:
        logger.debug(f"Failed to fetch SSLBL blocklist: {e}")
    cached = _SSLBL_CACHE.get("data")
    return cast(Dict[str, Tuple[str, str]], cached) if cached is not None else {}


def query_feodotracker_ip(ip: str) -> str:
    """Check if an IPv4 address is an active botnet C2 on abuse.ch Feodo Tracker."""
    clean_ip = ip.strip()
    feodo_map = _get_feodo_ip_map()
    if not feodo_map:
        return report("Not listed on Feodo Tracker (feed empty/clean).", 'missing')
    entry = feodo_map.get(clean_ip)
    if entry:
        malware = entry.get("malware") or "Unknown Botnet"
        status = entry.get("status") or "active"
        port = entry.get("port")
        asn = entry.get("as_name") or ""
        first_seen = entry.get("first_seen", "").split()[0]
        details = [f"Botnet C2: {malware}"]
        if port:
            details.append(f"Port: {port}")
        details.append(f"Status: {status}")
        if first_seen:
            details.append(f"First Seen: {first_seen}")
        if asn:
            details.append(f"ASN: {asn}")
        return report(" · ".join(details))
    return report("Not listed on Feodo Tracker (clean).", 'missing')


def query_sslbl_fingerprint(fingerprint: str) -> str:
    """Check if a SHA1 SSL certificate or JA3 MD5 hash is on abuse.ch SSL Blacklist."""
    clean_fp = fingerprint.strip().lower()
    sslbl_map = _get_sslbl_fingerprint_map()
    if not sslbl_map:
        return report("Not listed on SSLBL (feed empty/clean).", 'missing')
    entry = sslbl_map.get(clean_fp)
    if entry:
        reason, listing_date = entry
        date_str = f" · Listed: {listing_date.split()[0]}" if listing_date else ""
        return report(f"Malicious SSL Cert / JA3: {reason}{date_str}")
    return report("Not listed on SSLBL (clean).", 'missing')


