"""EPSS, OSV, VulnCheck KEV, and Microsoft MSRC vulnerability intelligence provider."""

from __future__ import annotations

import functools
import logging
import re
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


def query_epss(cve: str) -> str:
    """Query FIRST EPSS API for vulnerability exploit prediction probability and percentile."""
    clean_cve = cve.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", clean_cve):
        return f"Invalid CVE identifier '{cve}'."
    try:
        url = f"https://api.first.org/data/v1/epss?cve={clean_cve}"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            if data and isinstance(data, list):
                item = data[0]
                epss_val = float(item.get("epss", 0.0))
                perc_val = float(item.get("percentile", 0.0))
                date_val = item.get("date", "")
                epss_pct = epss_val * 100
                perc_pct = perc_val * 100
                if epss_val >= 0.70:
                    severity = "CRITICAL EXPLOIT PROBABILITY"
                elif epss_val >= 0.35:
                    severity = "HIGH EXPLOIT PROBABILITY"
                elif epss_val >= 0.10:
                    severity = "ELEVATED EXPLOIT PROBABILITY"
                else:
                    severity = "MODERATE/LOW EXPLOIT PROBABILITY"
                date_str = f" · Date: {date_val}" if date_val else ""
                return f"EPSS: {epss_pct:.2f}% ({severity}) · {perc_pct:.1f}th percentile{date_str}"
            return f"No EPSS score published for {clean_cve}."
        return f"EPSS API HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying EPSS: {e}"


def query_epss_batch(cves: List[str]) -> Dict[str, str]:
    """Query FIRST EPSS API for multiple CVEs in a single HTTP request."""
    valid_cves = [c.strip().upper() for c in cves if re.match(r"^CVE-\d{4}-\d{4,7}$", c.strip().upper())]
    if not valid_cves:
        return {}
    results: Dict[str, str] = {}
    chunk = valid_cves[:30]
    try:
        url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
        resp = httpx.get(url, timeout=7.0)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            for item in data:
                cve_id = item.get("cve", "").upper()
                if not cve_id:
                    continue
                epss_val = float(item.get("epss", 0.0))
                perc_val = float(item.get("percentile", 0.0))
                date_val = item.get("date", "")
                epss_pct = epss_val * 100
                perc_pct = perc_val * 100
                if epss_val >= 0.70:
                    severity = "CRITICAL EXPLOIT PROBABILITY"
                elif epss_val >= 0.35:
                    severity = "HIGH EXPLOIT PROBABILITY"
                elif epss_val >= 0.10:
                    severity = "ELEVATED EXPLOIT PROBABILITY"
                else:
                    severity = "MODERATE/LOW EXPLOIT PROBABILITY"
                date_str = f" · Date: {date_val}" if date_val else ""
                results[cve_id] = f"EPSS: {epss_pct:.2f}% ({severity}) · {perc_pct:.1f}th percentile{date_str}"
        for c in chunk:
            if c not in results:
                results[c] = f"No EPSS score published for {c}."
    except Exception as e:
        for c in chunk:
            results[c] = f"Error querying EPSS: {e}"
    return results


def query_osv_vuln(vuln_id: str) -> str:
    """Query OSV.dev (Google / OpenSSF Open Source Vulnerabilities) API for advisory details, affected packages, and severity."""
    clean_id = vuln_id.strip()
    if not clean_id:
        return "Invalid vulnerability ID."
    try:
        url = f"https://api.osv.dev/v1/vulns/{clean_id}"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            summary = (data.get("summary") or "").strip()
            if not summary:
                details = (data.get("details") or "").strip()
                if details:
                    summary = details.split("\n")[0].strip()
            if summary and len(summary) > 120:
                summary = summary[:117] + "..."

            aliases = [a for a in data.get("aliases") or [] if isinstance(a, str) and a != clean_id]

            packages = []
            for aff in data.get("affected") or []:
                if isinstance(aff, dict):
                    pkg_info = aff.get("package") or {}
                    pname = pkg_info.get("name")
                    peco = pkg_info.get("ecosystem")
                    if pname:
                        formatted = f"{peco}:{pname}" if peco else str(pname)
                        if formatted not in packages:
                            packages.append(formatted)

            cvss = None
            for sev in data.get("severity") or []:
                if isinstance(sev, dict) and sev.get("score"):
                    cvss = sev.get("score")
                    break

            parts = []
            if summary:
                parts.append(f"Advisory: {summary}")
            if packages:
                pkg_str = ", ".join(packages[:3])
                if len(packages) > 3:
                    pkg_str += f" (+{len(packages) - 3} more)"
                parts.append(f"Affected: {pkg_str}")
            if aliases:
                parts.append(f"Aliases: {', '.join(aliases[:3])}")
            if cvss:
                parts.append(f"CVSS: {cvss}")

            return " | ".join(parts) if parts else "Advisory cataloged on OSV.dev."
        elif resp.status_code == 404:
            return "No open-source advisory on OSV.dev."
        return f"OSV.dev error: HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying OSV.dev: {e}"


def query_vulncheck_cve(cve: str) -> str:
    """Query VulnCheck KEV API for weaponization status, in-the-wild exploitation, and threat actors."""
    key = _setting("VULNCHECK_API_KEY")
    if not key:
        return "VULNCHECK_API_KEY not configured."

    clean_cve = cve.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", clean_cve):
        return f"Invalid CVE identifier '{cve}'."

    headers = {
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "User-Agent": "Hecate-Agent/1.0",
    }
    try:
        url = f"https://api.vulncheck.com/v3/index/vulncheck-kev?cve={clean_cve}"
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json().get("data") or []
            if not data:
                return f"Not listed in VulnCheck KEV ({clean_cve})."
            item = data[0] if isinstance(data, list) else data
            exploit_type = item.get("exploit_type") or "Actively Exploited"
            actors = item.get("threat_actors") or []
            in_the_wild = bool(item.get("vulncheck_reported_exploitation", True))
            vendor = item.get("vendor") or ""
            product = item.get("product") or ""
            target = f"{vendor} {product}".strip()

            parts = [f"Status: {exploit_type} (in-the-wild: {in_the_wild})"]
            if target:
                parts.append(f"Target: {target}")
            if actors:
                parts.append(f"Threat Actors: {', '.join(actors[:3])}")
            return " · ".join(parts)
        elif resp.status_code == 404:
            return f"Not listed in VulnCheck KEV ({clean_cve})."
        elif resp.status_code in (401, 403):
            return "VulnCheck Auth Error (check VULNCHECK_API_KEY)."
        elif resp.status_code == 429:
            return "VulnCheck rate limit reached."
        return f"VulnCheck error: HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying VulnCheck: {e}"


@functools.lru_cache(maxsize=16)
def _fetch_msrc_document(doc_id: str) -> Dict[str, Any]:
    url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{doc_id}"
    resp = httpx.get(url, headers={"Accept": "application/json"}, timeout=8.0)
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, dict):
            return data
    return {}


def query_msrc_cve(cve: str) -> str:
    """Query Microsoft Security Response Center (MSRC) for vulnerability severity, exploitability, and impact."""
    clean_cve = cve.strip().upper()
    m = re.match(r"^CVE-(\d{4})-\d{4,7}$", clean_cve)
    if not m:
        return f"Invalid CVE identifier '{cve}'."
    year = m.group(1)

    try:
        updates_url = "https://api.msrc.microsoft.com/cvrf/v2.0/updates"
        resp = httpx.get(updates_url, headers={"Accept": "application/json"}, timeout=6.0)
        if resp.status_code != 200:
            return f"MSRC API error (HTTP {resp.status_code})"
        updates = resp.json().get("value") or []
        matching_docs = [u["ID"] for u in updates if isinstance(u, dict) and u.get("ID", "").startswith(year)]
        for doc_id in matching_docs[:12]:
            doc = _fetch_msrc_document(doc_id)
            for vuln in doc.get("Vulnerability", []):
                if vuln.get("CVE") == clean_cve:
                    title = vuln.get("Title", {}).get("Value", "")
                    cvss = ""
                    for s in vuln.get("CVSSScoreSets", []):
                        if s.get("BaseScore"):
                            cvss = str(s.get("BaseScore"))
                            break
                    severity = ""
                    exploitability = ""
                    for t in vuln.get("Threats", []):
                        desc = t.get("Description", {}).get("Value", "")
                        if t.get("Type") == 3 and not severity:
                            severity = desc
                        if "Exploited:" in desc or "Exploitation" in desc:
                            exploitability = desc
                    parts = [f"MSRC: {title}"]
                    if severity:
                        parts.append(f"Severity: {severity}")
                    if cvss:
                        parts.append(f"CVSS: {cvss}")
                    if exploitability:
                        parts.append(f"Exploitability: {exploitability}")
                    return " · ".join(parts)
        return f"Not listed in Microsoft Security Updates ({clean_cve})."
    except Exception as e:
        return f"Error querying MSRC: {e}"


