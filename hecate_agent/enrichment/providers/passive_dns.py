"""Passive DNS aggregation and historical resolution provider."""

from __future__ import annotations

from hecate_agent.enrichment.result import report

import ipaddress
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from hecate_agent.enrichment.providers.otx import query_otx_pdns
from hecate_agent.enrichment.providers.virustotal import query_vt_pdns_domain, query_vt_pdns_ip


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


_PDNS_CACHE: Dict[str, Tuple[float, str, List[Dict[str, Any]]]] = {}


_PDNS_CACHE_TTL: float = 86400.0  # 24-hour cache TTL


def _normalize_pdns_timestamp(ts: Any) -> Optional[int]:
    """Normalize timestamp from VT (sec), Mnemonic (ms), or OTX (ISO string) into epoch seconds."""
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        return int(ts / 1000) if ts > 1e11 else int(ts)
    if isinstance(ts, str):
        if ts.isdigit():
            val = int(ts)
            return int(val / 1000) if val > 1e11 else val
        try:
            clean = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            return int(dt.timestamp())
        except Exception:
            return None
    return None


def _format_pdns_date(epoch_sec: Optional[int]) -> str:
    """Format epoch seconds into a concise YYYY-MM representation."""
    if not epoch_sec:
        return ""
    try:
        return datetime.fromtimestamp(epoch_sec, tz=timezone.utc).strftime("%Y-%m")
    except Exception:
        return ""


def query_mnemonic_pdns(indicator: str, is_ip: bool = False) -> List[Dict[str, Any]]:
    """Query Mnemonic PDNS v3 public keyless API (with optional Argus key) for resolutions."""
    clean = refang(indicator).strip()
    if not clean:
        return []
    url = f"https://api.mnemonic.no/pdns/v3/{clean}?limit=25"
    headers = {"Accept": "application/json"}
    argus_key = _setting("MNEMONIC_API_KEY")
    if argus_key:
        headers["Argus-API-Key"] = argus_key
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            entries = []
            for item in resp.json().get("data", []):
                val = item.get("query") if is_ip else item.get("answer")
                ts = item.get("lastSeenTimestamp") or item.get("lastUpdatedTimestamp")
                if val:
                    entries.append({"value": val, "date": ts, "source": "Mnemonic"})
            return entries
    except Exception:
        pass
    return []


def query_passive_dns(indicator: str, max_results: int = 8) -> str:
    """Unified multi-source Passive DNS aggregator (VirusTotal, Mnemonic, AlienVault OTX).

    Returns historical resolved IPs for a domain, or correlated resolving hostnames for an IP.
    """
    clean = refang(indicator).strip()
    if not clean:
        return report("No passive DNS records found.", 'missing')

    is_ip = False
    try:
        addr = ipaddress.ip_address(clean)
        is_ip = True
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return report("Private/internal IP address.", 'skipped')
    except ValueError:
        is_ip = False

    cache_prefix = "ip" if is_ip else "domain"
    cache_key = f"{cache_prefix}:{clean.lower()}"
    now = time.time()
    cached = _PDNS_CACHE.get(cache_key)
    if cached and (now - cached[0] < _PDNS_CACHE_TTL):
        return report(cached[1])

    all_entries: List[Dict[str, Any]] = []

    # Query VT
    if is_ip:
        all_entries.extend(query_vt_pdns_ip(clean))
    else:
        all_entries.extend(query_vt_pdns_domain(clean))

    # Query Mnemonic (Public keyless)
    all_entries.extend(query_mnemonic_pdns(clean, is_ip=is_ip))

    # Query OTX
    all_entries.extend(query_otx_pdns(clean, is_ip=is_ip))

    records: Dict[str, Dict[str, Any]] = {}
    for entry in all_entries:
        val = (entry.get("value") or "").strip()
        if not val or val.lower() == clean.lower() or val.endswith(".arpa"):
            continue
        val_norm = val.lower()
        ts = _normalize_pdns_timestamp(entry.get("date"))
        source = entry.get("source", "PDNS")
        if val_norm not in records:
            records[val_norm] = {
                "display": val,
                "timestamp": ts,
                "sources": {source},
            }
        else:
            records[val_norm]["sources"].add(source)
            if ts and (records[val_norm]["timestamp"] is None or ts > records[val_norm]["timestamp"]):
                records[val_norm]["timestamp"] = ts

    if not records:
        res = "No passive DNS records found."
        _PDNS_CACHE[cache_key] = (now, res, [])
        return report(res)

    sorted_records = sorted(
        records.values(),
        key=lambda x: (x["timestamp"] is not None, x["timestamp"] or 0),
        reverse=True,
    )

    items = []
    sources_used: Set[str] = set()
    for r in sorted_records[:max_results]:
        d = f" ({_format_pdns_date(r['timestamp'])})" if r["timestamp"] else ""
        items.append(f"{r['display']}{d}")
        sources_used.update(r["sources"])

    src_str = f" [via {', '.join(sorted(sources_used))}]" if sources_used else ""
    summary = f"Passive DNS: {', '.join(items)}{src_str}"
    _PDNS_CACHE[cache_key] = (now, summary, sorted_records)
    return report(summary)


def query_passive_dns_ip(ip: str, max_results: int = 8) -> str:
    """Convenience wrapper for IP passive DNS lookup."""
    return report(query_passive_dns(ip, max_results=max_results))


def query_passive_dns_domain(domain: str, max_results: int = 8) -> str:
    """Convenience wrapper for Domain passive DNS lookup."""
    return report(query_passive_dns(domain, max_results=max_results))


