"""Hybrid Analysis and Hatching Triage dynamic sandbox execution provider."""

from __future__ import annotations

from hecate_agent.enrichment.result import report

import logging
import re
from typing import List, Set

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


def query_hybrid_analysis(file_hash: str) -> str:
    """Query Hybrid Analysis (CrowdStrike Falcon Sandbox) API v2 for hash detonation results, threat score, and MITRE techniques."""
    key = _setting("HYBRID_ANALYSIS_API_KEY") or _setting("HA_API_KEY") or _setting("FALCON_SANDBOX_API_KEY")
    if not key:
        return report("HYBRID_ANALYSIS_API_KEY not configured.", 'unconfigured')

    clean_hash = file_hash.strip().lower()
    if not re.match(r"^[a-f0-9]{32,64}$", clean_hash):
        return report(f"Invalid hash format '{file_hash}'.")

    headers = {
        "api-key": key,
        "User-Agent": "Falcon Sandbox",
        "Accept": "application/json",
    }

    try:
        url = f"https://hybrid-analysis.com/api/v2/overview/{clean_hash}"
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            if not isinstance(data, dict) or not data:
                return report("No records on Hybrid Analysis.", 'missing')

            score = data.get("threat_score")
            verdict = data.get("verdict")
            vx_family = data.get("vx_family")
            ftype = data.get("type_short") or data.get("type")
            if isinstance(ftype, list):
                ftype = ftype[0] if ftype else "unknown"
            multiscan = data.get("multiscan_result")
            reports = data.get("reports") or []

            env = None
            mitre_ids: List[str] = []

            # If execution reports exist, fetch the primary report summary for dynamic environment & MITRE ATT&CK
            if reports and isinstance(reports, list):
                rep_id = str(reports[0]).strip()
                if rep_id:
                    try:
                        rep_url = f"https://hybrid-analysis.com/api/v2/report/{rep_id}/summary"
                        rep_resp = httpx.get(rep_url, headers=headers, timeout=4.0)
                        if rep_resp.status_code == 200:
                            r_json = rep_resp.json()
                            env = r_json.get("environment_description")
                            mitre_raw = r_json.get("mitre_attcks") or r_json.get("mitre_attcs") or []
                            for m in mitre_raw:
                                if isinstance(m, dict):
                                    mid = m.get("attck_id") or m.get("id")
                                    if mid and str(mid) not in mitre_ids:
                                        mitre_ids.append(str(mid).strip())
                    except Exception:
                        pass

            parts = []
            if verdict:
                score_str = f" (Score: {score}/100)" if score is not None else ""
                parts.append(f"Verdict: {verdict.upper()}{score_str}")
            elif score is not None:
                parts.append(f"Threat Score: {score}/100")

            if vx_family:
                parts.append(f"Family: {vx_family}")
            if ftype:
                parts.append(f"Type: {ftype}")
            if multiscan is not None:
                parts.append(f"Multi-Scan: {multiscan}%")
            if env:
                parts.append(f"Env: {env}")
            if mitre_ids:
                parts.append(f"MITRE: {', '.join(mitre_ids[:3])}")

            return report(" | ".join(parts) if parts else "Sample analyzed on Hybrid Analysis.")
        elif resp.status_code == 404:
            return report("No records on Hybrid Analysis.", 'missing')
        elif resp.status_code in (401, 403):
            return report("Hybrid Analysis Auth Error (check HYBRID_ANALYSIS_API_KEY).", 'errors')
        elif resp.status_code == 429:
            return report("Hybrid Analysis rate limit exceeded.", 'errors')
        return report(f"Hybrid Analysis error: HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying Hybrid Analysis: {e}")


def query_triage_hash(file_hash: str) -> str:
    """Query Hatching Triage (tria.ge) sandbox API for sample detonation overview and extracted config."""
    key = _setting("TRIAGE_API_KEY") or _setting("HATCHING_TRIAGE_KEY") or _setting("TRIA_GE_API_KEY")
    if not key:
        return report("TRIAGE_API_KEY not configured.", 'unconfigured')

    clean_hash = file_hash.strip().lower()
    if not re.match(r"^[a-f0-9]{32,64}$", clean_hash):
        return report(f"Invalid hash format '{file_hash}'.")

    headers = {
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "User-Agent": "Hecate-Agent/1.0",
    }

    try:
        search_url = f"https://api.tria.ge/v0/search?query={clean_hash}"
        resp = httpx.get(search_url, headers=headers, timeout=5.0)
        if resp.status_code == 404:
            return report("No records on tria.ge.", 'missing')
        elif resp.status_code in (401, 403):
            return report("tria.ge Auth Error (check TRIAGE_API_KEY).", 'errors')
        elif resp.status_code == 429:
            return report("tria.ge rate limit exceeded.", 'errors')
        elif resp.status_code != 200:
            return report(f"tria.ge error: HTTP {resp.status_code}")

        search_data = resp.json()
        samples = search_data.get("data") or []
        if not samples:
            return report("No records on tria.ge.", 'missing')

        sample_id = samples[0].get("id")
        if not sample_id:
            return report("Sample found on tria.ge without ID.", 'found')

        overview_url = f"https://api.tria.ge/v0/samples/{sample_id}/overview.json"
        ov_resp = httpx.get(overview_url, headers=headers, timeout=5.0)
        if ov_resp.status_code != 200:
            return report(f"tria.ge sample {sample_id} status HTTP {ov_resp.status_code}")

        ov_data = ov_resp.json()
        analysis = ov_data.get("analysis") or {}
        sample_info = ov_data.get("sample") or {}

        score = analysis.get("score")
        if score is None:
            score = sample_info.get("score")

        families_raw = analysis.get("family") or []
        families = [families_raw] if isinstance(families_raw, str) else list(families_raw)
        tags_raw = analysis.get("tags") or []
        tags = [tags_raw] if isinstance(tags_raw, str) else list(tags_raw)

        extracted = ov_data.get("extracted") or []
        c2_list: List[str] = []
        botnets: List[str] = []
        mutexes: List[str] = []
        cfg_families: List[str] = []

        for item in extracted:
            if not isinstance(item, dict):
                continue
            cfg = item.get("config")
            if not isinstance(cfg, dict):
                continue

            f_name = cfg.get("family")
            if f_name and str(f_name) not in cfg_families:
                cfg_families.append(str(f_name))

            c2_raw = cfg.get("c2") or cfg.get("c2_urls") or cfg.get("urls") or []
            if isinstance(c2_raw, str):
                c2_raw = [c2_raw]
            for c in c2_raw:
                c_str = str(c).strip()
                if c_str and c_str not in c2_list:
                    c2_list.append(c_str)

            bot_id = cfg.get("botnet") or cfg.get("bot_id") or cfg.get("campaign")
            if bot_id and str(bot_id) not in botnets:
                botnets.append(str(bot_id))

            mutex = cfg.get("mutex")
            if mutex and str(mutex) not in mutexes:
                mutexes.append(str(mutex))

        parts = []
        all_families = list(dict.fromkeys(families + cfg_families))
        if all_families:
            parts.append(f"Family: {', '.join(all_families)}")
        if score is not None:
            parts.append(f"Score: {score}/10")
        if c2_list:
            parts.append(f"Extracted C2: {', '.join(c2_list[:3])}")
        if botnets:
            parts.append(f"Botnet: {', '.join(botnets[:2])}")
        if mutexes:
            parts.append(f"Mutex: {', '.join(mutexes[:2])}")
        if tags:
            parts.append(f"Tags: {', '.join(tags[:4])}")

        return report(" | ".join(parts) if parts else "Sample analyzed on tria.ge.")
    except Exception as e:
        return report(f"Error querying tria.ge: {e}")


