"""GreyNoise internet scanner and contextual noise intelligence provider."""

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


def extract_greynoise_context(ip: str) -> Dict[str, Any]:
    """Return structured GreyNoise intelligence for an IP.

    Returns:
    - noise: bool (True if observed scanning the internet)
    - riot: bool (True if benign enterprise service)
    - classification: "benign" | "malicious" | "unknown" | "unseen" | "error"
    - actor: str (e.g. "ShadowServer.org", "Shodan.io", "Mirai")
    - tags: list[str]
    - raw_status: int (HTTP status code)
    """
    key = _setting("GREYNOISE_API_KEY")
    if not key:
        return {
            "noise": False,
            "riot": False,
            "classification": "unknown",
            "actor": "",
            "tags": [],
            "raw_status": 0,
        }

    headers = {"key": key, "Accept": "application/json"}
    try:
        url = f"https://api.greynoise.io/v3/ip/{ip}"
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 404:
            return {
                "noise": False,
                "riot": False,
                "classification": "unseen",
                "actor": "",
                "tags": [],
                "raw_status": 404,
            }
        if resp.status_code in (401, 403):
            comm_url = f"https://api.greynoise.io/v3/community/{ip}"
            resp = httpx.get(comm_url, headers=headers, timeout=10.0)
            if resp.status_code == 404:
                return {
                    "noise": False,
                    "riot": False,
                    "classification": "unseen",
                    "actor": "",
                    "tags": [],
                    "raw_status": 404,
                }
            if resp.status_code != 200:
                return {
                    "noise": False,
                    "riot": False,
                    "classification": "error",
                    "actor": "",
                    "tags": [],
                    "raw_status": resp.status_code,
                }

        if resp.status_code != 200:
            return {
                "noise": False,
                "riot": False,
                "classification": "error",
                "actor": "",
                "tags": [],
                "raw_status": resp.status_code,
            }

        data = resp.json()
        bsi = data.get("business_service_intelligence") or {}
        isi = data.get("internet_scanner_intelligence") or {}
        riot = (bsi.get("found") is True) or data.get("riot", False)
        noise = (isi.get("found") is True) or data.get("noise", data.get("seen", False))
        classification = isi.get("classification") or data.get("classification") or "unknown"
        actor = isi.get("actor") or bsi.get("name") or data.get("actor") or data.get("name") or "Unknown"

        raw_tags = isi.get("tags") or data.get("tags") or []
        tags: List[str] = []
        for t in raw_tags:
            if isinstance(t, str):
                tags.append(t)
            elif isinstance(t, dict) and t.get("name"):
                tags.append(t["name"])

        return {
            "noise": bool(noise),
            "riot": bool(riot),
            "classification": str(classification).lower(),
            "actor": str(actor),
            "tags": tags,
            "raw_status": resp.status_code,
        }
    except Exception as exc:
        logger.debug("Failed to query GreyNoise for %s: %s", ip, exc)
        return {
            "noise": False,
            "riot": False,
            "classification": "error",
            "actor": "",
            "tags": [],
            "raw_status": -1,
        }


def query_greynoise_ip(ip: str) -> str:
    key = _setting("GREYNOISE_API_KEY")
    if not key:
        return report("GREYNOISE_API_KEY not configured.", 'unconfigured')
    gn = extract_greynoise_context(ip)
    if gn["raw_status"] in (401, 403):
        return report(f"GreyNoise Auth/API Error: {gn['raw_status']}")
    if gn["classification"] == "error":
        return report(f"GreyNoise API Error: {gn['raw_status']}")
    if gn["classification"] == "unseen":
        return report("No mass-internet scanning observed on GreyNoise (Unseen / Targeted).", 'missing')

    tag_str = f" | Tags: {', '.join(gn['tags'][:3])}" if gn.get("tags") else ""
    actor = gn.get("actor") or "Unknown"
    classification = gn.get("classification") or "unknown"

    if gn.get("riot"):
        return report(f"RIOT: Benign Enterprise Service ({actor}) | Class: {classification}{tag_str}")
    if gn.get("noise"):
        return report(f"Mass Internet Scanner ({classification}) | Actor: {actor}{tag_str}")
    if classification != "unknown":
        return report(f"Observed ({classification}) | Actor: {actor}{tag_str}")
    return report("Not observed as scanner noise (Targeted or Inactive).", 'missing')


