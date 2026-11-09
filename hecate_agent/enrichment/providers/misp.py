"""MISP threat intelligence platform and TTP expansion provider."""

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


def query_misp_indicator(indicator: str) -> str:
    url = f"{_setting('MISP_BASE_URL', 'https://localhost:8443')}/attributes/restSearch"
    headers = {"Authorization": _setting("MISP_API_KEY"), "Accept": "application/json", "Content-Type": "application/json"}
    data = {"value": indicator, "limit": 5}
    try:
        resp = httpx.post(url, headers=headers, json=data, verify=_misp_verify_tls(), timeout=10.0)
        if resp.status_code == 200:
            events = resp.json().get("response", {}).get("Attribute", [])
            if events:
                event_ids = list(set([str(e.get("event_id")) for e in events]))
                return report(f"Found in MISP Incident(s): {', '.join(event_ids[:3])}")
        return report("Not seen in local MISP.", 'missing')
    except Exception as e:
        return report(f"Error querying MISP: {e}")


def expand_ttps(threat_intel: str) -> str:
    from hecate_agent.core.attack_matrix import _get_provider

    provider = _get_provider()

    try:
        if hasattr(provider, "_ensure_loaded"):
            provider._ensure_loaded()

        attack_data = getattr(provider, "_attack_data", None)
        if not attack_data:
            return ""

        software_list = attack_data.get_software(remove_revoked_deprecated=True)

        # Build a fast lookup of lowercase software names to their STIX objects
        software_map = {s.get("name", "").lower(): s for s in software_list if s.get("name")}

        found_software = []
        for soft_name, soft_obj in software_map.items():
            if len(soft_name) > 3 and soft_name in threat_intel.lower():
                found_software.append(soft_obj)

        if not found_software:
            return ""

        summary = ["\n### 🗺️ Automated TTP Expansion (MITRE ATT&CK STIX)"]
        for s in found_software[:3]:  # Limit to 3 to avoid massive context bloat
            techs = attack_data.get_techniques_used_by_software(s["id"])

            # Get external ATT&CK IDs
            tech_ids = []
            for t in techs:
                tech_obj = t.get("object")
                if tech_obj and tech_obj.get("external_references"):
                    for ref in tech_obj["external_references"]:
                        if ref.get("source_name") == "mitre-attack":
                            tech_ids.append(ref["external_id"])
                            break

            if tech_ids:
                summary.append(
                    f"- **{s.get('name')}**: Commonly uses {len(tech_ids)} techniques (e.g., {', '.join(tech_ids[:5])})"
                )

        if len(summary) > 1:
            return "\n".join(summary)
        return ""
    except Exception as e:
        logger.error(f"STIX TTP Expansion error: {e}")
        return ""


