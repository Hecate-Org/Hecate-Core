"""Registration Data Access Protocol (RDAP) domain intelligence provider."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
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


def _format_rdap_date(date_str: str) -> str:
    """Format an RDAP ISO-8601 date string and compute age / NRD classification."""
    if not date_str:
        return "Unknown"
    try:
        clean = re.sub(r"Z$", "+00:00", str(date_str).strip())
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days = (now - dt).days
        iso_day = date_str[:10]
        if days < 0:
            return iso_day
        if days < 60:
            return f"{iso_day} ({days} days old - RECENT/NRD)"
        elif days < 365:
            months = max(1, days // 30)
            return f"{iso_day} ({months} months old)"
        else:
            years = max(1, days // 365)
            return f"{iso_day} ({years} years old)"
    except Exception:
        return date_str[:10] if len(date_str) >= 10 else date_str


def query_rdap_domain(domain: str) -> str:
    """Query public RDAP service for domain registration age and registrar."""
    target_domain = _get_apex_domain(domain)
    url = f"https://rdap.org/domain/{target_domain}"
    headers = {"Accept": "application/rdap+json, application/json"}
    try:
        resp = httpx.get(url, headers=headers, follow_redirects=True, timeout=10.0)
        if resp.status_code == 200:
            data = cast(Dict[str, Any], resp.json())
            reg_date_raw = ""
            for ev in data.get("events", []):
                if ev.get("eventAction") in ("registration", "created"):
                    reg_date_raw = ev.get("eventDate", "")
                    break

            registrar = ""
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray")
                    if vcard and len(vcard) > 1 and isinstance(vcard[1], list):
                        for prop in vcard[1]:
                            if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                                registrar = str(prop[3])
                                break
                    if not registrar and ent.get("handle"):
                        registrar = str(ent.get("handle"))
                    if registrar:
                        break

            parts = []
            if reg_date_raw:
                age_formatted = _format_rdap_date(reg_date_raw)
                parts.append(f"Registered: {age_formatted}")
            if registrar:
                parts.append(f"Registrar: {registrar}")

            if parts:
                return " | ".join(parts)
            return "Domain active (no creation date recorded in RDAP)."
        elif resp.status_code == 404:
            return "Domain not found on RDAP."
        return f"RDAP error: HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying RDAP: {e}"


