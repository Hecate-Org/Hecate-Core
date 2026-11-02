"""Programmatic API for Hecate operations.

This module exposes Core functionalities as reusable Python functions rather
than CLI commands, eliminating subprocess overhead and stdout-parsing
brittleness for orchestrators like Hecate-Runner.
"""

import re
from typing import Optional, Dict, Any, Tuple, List
from pathlib import Path

from hecate_agent.agents.llm.hypothesis_generator import (
    HypothesisGeneratorAgent,
    HypothesisGenerationInput,
    HypothesisGenerationOutput,
)
from hecate_agent.agents.llm.sigma_generator import SigmaGeneratorAgent, SigmaGenerationInput, SigmaGenerationOutput
from hecate_agent.agents.llm.hunt_researcher import HuntResearcherAgent, ResearchInput, ResearchOutput, research_grounding
from hecate_agent.core.attack_matrix import get_technique, get_superseding_technique_id, is_using_stix
from hecate_agent.core.research_manager import ResearchManager
from hecate_agent.commands.research import _generate_research_markdown


class GenerationError(RuntimeError):
    """A generation step failed; ``metadata`` carries its usage and timing for callers that meter it."""

    def __init__(self, message: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.metadata: Dict[str, Any] = metadata or {}


def _generate_hypothesis(
    threat_intel: str,
    research_id: Optional[str] = None,
    indicators_only: bool = False,
    workspace: Optional[Path] = None,
) -> Tuple[HypothesisGenerationOutput, Dict[str, Any]]:
    """Run hypothesis generation and retain its usage metadata."""
    agent = HypothesisGeneratorAgent(llm_enabled=True)

    past_hunts: List[dict] = []
    environment = {}
    research_ctx = None

    if workspace:
        research_mgr = ResearchManager(workspace / "research")
        if research_id:
            research_doc = research_mgr.get_research(research_id)
            if research_doc:
                research_ctx = research_mgr.extract_research_context(research_doc)

        env_file = workspace / "knowledge" / "environment.md"
        if env_file.exists():
            environment = {"environment_md": env_file.read_text(encoding="utf-8")}

    input_data = HypothesisGenerationInput(
        threat_intel=threat_intel,
        past_hunts=past_hunts,
        environment=environment,
        research=research_ctx,
        intel_is_indicator_only=indicators_only,
    )

    result = agent.execute(input_data)
    if not result.success:
        raise GenerationError(f"Hypothesis generation failed: {result.error}", metadata=dict(result.metadata))

    if not result.data:
        raise RuntimeError("Hypothesis generation returned no data.")

    return result.data, dict(result.metadata)


def generate_hypothesis(
    threat_intel: str,
    research_id: Optional[str] = None,
    indicators_only: bool = False,
    workspace: Optional[Path] = None,
) -> HypothesisGenerationOutput:
    """Generate a hunt hypothesis directly via the Python API."""
    output, _ = _generate_hypothesis(
        threat_intel=threat_intel,
        research_id=research_id,
        indicators_only=indicators_only,
        workspace=workspace,
    )
    return output


def generate_hypothesis_with_metrics(
    threat_intel: str,
    research_id: Optional[str] = None,
    indicators_only: bool = False,
    workspace: Optional[Path] = None,
) -> Tuple[HypothesisGenerationOutput, Dict[str, Any]]:
    """Generate a hypothesis and return per-call LLM usage metadata."""
    return _generate_hypothesis(
        threat_intel=threat_intel,
        research_id=research_id,
        indicators_only=indicators_only,
        workspace=workspace,
    )


def generate_research(
    topic: str,
    technique: Optional[str] = None,
    depth: str = "basic",
    web_search_enabled: bool = True,
    workspace: Optional[Path] = None,
    source_context: Optional[str] = None,
) -> Tuple[ResearchOutput, Path]:
    """Execute research and create the research document."""
    manager = ResearchManager(workspace / "research") if workspace else ResearchManager()
    research_id = manager.get_next_research_id()

    agent = HuntResearcherAgent(llm_enabled=True)
    result = agent.execute(
        ResearchInput(
            topic=topic,
            mitre_technique=technique,
            depth=depth,
            include_past_hunts=True,
            include_telemetry_mapping=True,
            web_search_enabled=web_search_enabled,
            research_id=research_id,
            source_context=source_context,
        )
    )

    if not result.success or not result.data:
        raise GenerationError(f"Research failed: {result.error}", metadata=dict(result.metadata))

    output = result.data
    markdown_content = _generate_research_markdown(output)

    linked_hunts = []
    for source in output.related_work.sources:
        match = re.match(r"hunts/(H-\d+)\.md$", source.get("url", ""))
        if match:
            linked_hunts.append(match.group(1))

    frontmatter = {
        "research_id": output.research_id,
        "topic": output.topic,
        "mitre_techniques": output.mitre_techniques,
        "status": "completed",
        "depth": depth,
        "duration_minutes": round(output.total_duration_ms / 60000, 1),
        "linked_hunts": linked_hunts,
        "web_searches": output.web_searches_performed,
        "grounding": research_grounding(output.web_searches_performed),
        **({"web_search_note": output.web_search_note} if output.web_search_note else {}),
        "llm_calls": output.llm_calls,
        "total_cost_usd": output.total_cost_usd,
        "cost_basis": output.cost_basis,
        "data_source_availability": output.data_source_availability,
        "estimated_hunt_complexity": output.estimated_hunt_complexity,
    }

    file_path = manager.create_research_file(
        research_id=output.research_id,
        topic=output.topic,
        content=markdown_content,
        frontmatter=frontmatter,
    )

    return output, file_path


def generate_sigma(
    payload: Dict[str, Any],
    out_dir: Optional[Path] = None,
    hunt_id: Optional[str] = None,
    workspace: Optional[Path] = None,
) -> Tuple[SigmaGenerationOutput, List[Path]]:
    """Generate Sigma rules and optionally write them to disk."""
    output, written_paths, metadata = generate_sigma_with_metrics(
        payload=payload,
        out_dir=out_dir,
        hunt_id=hunt_id,
        workspace=workspace,
    )
    if not metadata.get("success", False):
        raise RuntimeError(f"Sigma generation failed: {metadata.get('error') or 'unknown error'}")
    return output, written_paths


def generate_sigma_with_metrics(
    payload: Dict[str, Any],
    out_dir: Optional[Path] = None,
    hunt_id: Optional[str] = None,
    workspace: Optional[Path] = None,
) -> Tuple[SigmaGenerationOutput, List[Path], Dict[str, Any]]:
    """Generate Sigma rules and return usage metadata, including failures."""
    known = set(SigmaGenerationInput.__dataclass_fields__)
    agent_input = SigmaGenerationInput(**{k: v for k, v in payload.items() if k in known})
    if hunt_id and not agent_input.hunt_id:
        agent_input.hunt_id = hunt_id

    config = {"workspace": workspace} if workspace else None
    result = SigmaGeneratorAgent(config=config, llm_enabled=True).execute(agent_input)
    output = result.data or SigmaGenerationOutput(logsources_considered=[])

    written_paths = []
    if result.success and out_dir:
        target = Path(workspace / out_dir) if (workspace and not Path(out_dir).is_absolute()) else Path(out_dir)
        target.mkdir(parents=True, exist_ok=True)
        from hecate_agent.agents.llm.sigma_generator import rule_filenames

        for rule, filename in zip(output.rules, rule_filenames(output.rules)):
            path = target / filename
            path.write_text(rule.rule_yaml, encoding="utf-8")
            written_paths.append(path)
            try:
                trans_queries = transpile_sigma_rule(rule.rule_yaml)
                for t_res in trans_queries.values():
                    if getattr(t_res, "success", False) and getattr(t_res, "query", None):
                        q_path = path.with_suffix(t_res.file_extension)
                        q_path.write_text(t_res.query.strip() + "\n", encoding="utf-8")
                        written_paths.append(q_path)
            except Exception:
                pass

    success = result.success and result.data is not None
    metadata = dict(result.metadata)
    metadata.update({"success": success, "error": result.error, "warnings": result.warnings})
    return output, written_paths, metadata


def lookup_technique(technique_id: str) -> Dict[str, Any]:
    """Look up an ATT&CK technique by ID."""
    if not is_using_stix():
        raise RuntimeError("stix_unavailable")

    tech = get_technique(technique_id)
    # Provenance of this call, not a property of the technique. Writing it
    # onto `tech` mutated the STIX provider's memoized index in place, so
    # every later lookup of the superseding ID -- and every tactic listing
    # handing back the same dict -- reported it as superseded from whatever
    # revoked ID happened to be asked for first.
    superseded_from = ""
    if not tech:
        # Check for superseded IDs
        latest = get_superseding_technique_id(technique_id)
        if latest and latest != technique_id:
            tech = get_technique(latest)
            if tech:
                superseded_from = technique_id

    if not tech:
        return {"found": False}

    return {
        "found": True,
        "technique_id": tech.get("id", ""),
        "name": tech.get("name", ""),
        "description": tech.get("description", ""),
        "tactics": tech.get("tactic_shortnames", []),
        "platforms": tech.get("platforms", []),
        "data_sources": tech.get("data_sources", []),
        "is_subtechnique": tech.get("is_subtechnique", False),
        "superseded_from": superseded_from,
    }


def link_research_to_hunt(
    research_id: str,
    hunt_id: str,
    workspace: Path | None = None,
) -> bool:
    """Link a drafted hunt ID back to its originating research document.

    Args:
        research_id: The ID of the research document to update.
        hunt_id: The ID of the drafted hunt.
        workspace: Path to Hecate workspace. If None, uses current directory.
    """
    from hecate_agent.core.research_manager import ResearchManager

    manager = ResearchManager(workspace / "research") if workspace else ResearchManager()
    return manager.link_hunt_to_research(research_id, hunt_id)


def generate_enrichment_summary(threat_intel: str) -> str:
    """Enrich indicators found in threat intelligence using external OSINT sources.

    Extracts hashes, IPs, and domains from the threat_intel text, concurrently queries
    configured OSINT platforms (VirusTotal, Shodan, Censys, ThreatFox, MISP, etc.),
    and returns a formatted markdown summary of the findings.
    """
    from hecate_agent.orchestrator.enrichment import generate_enrichment_summary as _enrich

    return _enrich(threat_intel)


def extract_indicators(threat_intel: str) -> Dict[str, List[str]]:
    """Extract observable indicators (IPs, hashes, domains) from text."""
    from hecate_agent.orchestrator.enrichment import extract_indicators as _extract

    return _extract(threat_intel)


def query_malwarebazaar(file_hash: str) -> str:
    """Query Abuse.ch MalwareBazaar for file hash metadata, family signature, and YARA rules."""
    from hecate_agent.orchestrator.enrichment import query_malwarebazaar as _q

    return _q(file_hash)


def query_abuseipdb_ip(ip: str) -> str:
    """Query AbuseIPDB for IP reputation, reports, ISP, and abuse confidence score."""
    from hecate_agent.orchestrator.enrichment import query_abuseipdb_ip as _q

    return _q(ip)


def query_rdap_domain(domain: str) -> str:
    """Query public RDAP registry for domain registration age and registrar."""
    from hecate_agent.orchestrator.enrichment import query_rdap_domain as _q

    return _q(domain)


def query_epss(cve: str) -> str:
    """Query FIRST EPSS API for vulnerability exploit prediction probability and percentile."""
    from hecate_agent.orchestrator.enrichment import query_epss as _q

    return _q(cve)


def query_epss_batch(cves: List[str]) -> Dict[str, str]:
    """Query FIRST EPSS API for multiple CVEs in a single HTTP request."""
    from hecate_agent.orchestrator.enrichment import query_epss_batch as _q

    return _q(cves)


def query_otx_indicator(indicator_type: str, indicator: str) -> str:
    """Query AlienVault OTX Direct API for indicator metadata, pulses, adversaries, and passive DNS."""
    from hecate_agent.orchestrator.enrichment import query_otx_indicator as _q

    return _q(indicator_type, indicator)


def query_otx_ip(ip: str) -> str:
    """Query AlienVault OTX Direct API for an IPv4 address."""
    from hecate_agent.orchestrator.enrichment import query_otx_ip as _q

    return _q(ip)


def query_otx_domain(domain: str) -> str:
    """Query AlienVault OTX Direct API for a domain."""
    from hecate_agent.orchestrator.enrichment import query_otx_domain as _q

    return _q(domain)


def query_otx_hash(file_hash: str) -> str:
    """Query AlienVault OTX Direct API for a file hash."""
    from hecate_agent.orchestrator.enrichment import query_otx_hash as _q

    return _q(file_hash)


def query_otx_cve(cve: str) -> str:
    """Query AlienVault OTX Direct API for a CVE vulnerability."""
    from hecate_agent.orchestrator.enrichment import query_otx_cve as _q

    return _q(cve)


def query_feodotracker_ip(ip: str) -> str:
    """Check if an IPv4 address is an active botnet C2 on abuse.ch Feodo Tracker."""
    from hecate_agent.orchestrator.enrichment import query_feodotracker_ip as _q

    return _q(ip)


def query_sslbl_fingerprint(fingerprint: str) -> str:
    """Check if a SHA1 SSL certificate or JA3 MD5 hash is on abuse.ch SSL Blacklist."""
    from hecate_agent.orchestrator.enrichment import query_sslbl_fingerprint as _q

    return _q(fingerprint)


def query_urlhaus_url(url: str) -> str:
    """Query abuse.ch URLhaus API for malicious URL status, threat classification, and payload info."""
    from hecate_agent.orchestrator.enrichment import query_urlhaus_url as _q

    return _q(url)


def query_urlhaus_host(host: str) -> str:
    """Query abuse.ch URLhaus API for host (domain or IP) malware distribution history."""
    from hecate_agent.orchestrator.enrichment import query_urlhaus_host as _q

    return _q(host)


def query_urlhaus_payload(file_hash: str) -> str:
    """Query abuse.ch URLhaus API for payload hash (MD5 or SHA256) distribution info."""
    from hecate_agent.orchestrator.enrichment import query_urlhaus_payload as _q

    return _q(file_hash)


def query_hybrid_analysis(file_hash: str) -> str:
    """Query Hybrid Analysis (CrowdStrike Falcon Sandbox) API v2 for hash detonation results."""
    from hecate_agent.orchestrator.enrichment import query_hybrid_analysis as _q

    return _q(file_hash)


def query_osv_vuln(vuln_id: str) -> str:
    """Query OSV.dev (Google / OpenSSF Open Source Vulnerabilities) API for advisory details, affected packages, and severity."""
    from hecate_agent.orchestrator.enrichment import query_osv_vuln as _q

    return _q(vuln_id)


def query_triage_hash(file_hash: str) -> str:
    """Query Hatching Triage (tria.ge) sandbox API for sample detonation overview and extracted config."""
    from hecate_agent.orchestrator.enrichment import query_triage_hash as _q

    return _q(file_hash)


def get_groups() -> List[Dict[str, Any]]:
    """Return all known threat actor groups."""
    from hecate_agent.core.attack_matrix import get_groups as _gg

    return [dict(g) for g in _gg()]


def get_group(group_id: str) -> Optional[Dict[str, Any]]:
    """Look up a threat actor group by ATT&CK ID."""
    from hecate_agent.core.attack_matrix import get_group as _gg

    res = _gg(group_id)
    return dict(res) if res else None


def find_group(name_or_alias: str) -> Optional[Dict[str, Any]]:
    """Find a threat actor group by name or alias."""
    from hecate_agent.core.attack_matrix import find_group as _fg

    res = _fg(name_or_alias)
    return dict(res) if res else None


def search_groups_in_text(text: str) -> List[Dict[str, Any]]:
    """Scan text for mentions of threat actor groups or their known aliases."""
    from hecate_agent.core.attack_matrix import search_groups_in_text as _sg

    return [dict(g) for g in _sg(text)]


def extract_vt_behavior_graph(file_hash: str) -> Dict[str, Any]:
    """Query VirusTotal v3 behaviour_summary for sandbox execution graph and MITRE techniques."""
    from hecate_agent.orchestrator.enrichment import extract_vt_behavior_graph as _evb

    return _evb(file_hash)


def extract_greynoise_context(ip: str) -> Dict[str, Any]:
    """Return structured GreyNoise intelligence (noise, riot, classification, actor, tags)."""
    from hecate_agent.orchestrator.enrichment import extract_greynoise_context as _egc

    return _egc(ip)


def get_atomic_tests(
    technique_id: str,
    workspace: Optional[Any] = None,
    platforms: Optional[List[str]] = None,
) -> List[Dict[str, str]]:
    """Return matching Atomic Red Team test descriptors for an ATT&CK technique."""
    from hecate_agent.core.atomic_red_team import get_atomic_tests as _gat

    return _gat(technique_id, workspace=workspace, platforms=platforms)


def format_atomic_tests_markdown(
    techniques: List[str],
    workspace: Optional[Any] = None,
    platforms: Optional[List[str]] = None,
) -> str:
    """Format matching Atomic Red Team tests as markdown table for hunt briefs."""
    from hecate_agent.core.atomic_red_team import format_atomic_tests_markdown as _fatm

    return _fatm(techniques, workspace=workspace, platforms=platforms)


def synthesize_atomic_telemetry(
    technique_id: str,
    workspace: Optional[Any] = None,
    platforms: Optional[List[str]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Synthesize structured, high-fidelity Sigma telemetry events from Atomic Red Team tests."""
    from hecate_agent.core.atomic_red_team import synthesize_atomic_telemetry as _sat

    return _sat(technique_id, workspace=workspace, platforms=platforms)


def run_dynamic_atomic_emulation(
    technique_id: str,
    backend: str = "simulation",
    platforms: Optional[List[str]] = None,
) -> Any:
    """Execute dynamic adversary emulation for a technique and return an EmulationResult."""
    from hecate_agent.core.emulation_runner import EmulationRunner

    runner = EmulationRunner(backend=backend)
    return runner.run_technique(technique_id, platforms=platforms)


def transpile_sigma_rule(
    rule_yaml: str,
    targets: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Transpile a Sigma YAML rule into native search queries for all supported SIEM/EDR targets."""
    from hecate_agent.core.sigma_transpiler import SigmaTranspiler

    transpiler = SigmaTranspiler()
    return transpiler.transpile(rule_yaml, targets=targets)


def validate_transpiled_query(
    target: str,
    query: str,
) -> Dict[str, Any]:
    """Validate a transpiled query string against universal and dialect-specific syntax rules."""
    from hecate_agent.core.query_validator import QueryValidator

    validator = QueryValidator()
    res = validator.validate(target, query)
    return {
        "target": res.target,
        "dialect": res.dialect,
        "query": res.query,
        "is_valid": res.is_valid,
        "sanity_score": res.sanity_score,
        "summary": res.summary(),
        "error_messages": res.error_messages,
        "issues": [
            {
                "severity": i.severity,
                "code": i.code,
                "message": i.message,
                "line_number": i.line_number,
            }
            for i in res.issues
        ],
    }


def deploy_transpiled_query(
    target: str,
    query: str,
    hunt_id: str,
    title: str,
    description: str = "",
    severity: str = "high",
    techniques: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """Deploy a transpiled search query to its target SIEM or EDR platform via REST API."""
    from hecate_agent.core.query_deployer import DeploymentPayload, QueryDeployer

    payload = DeploymentPayload(
        hunt_id=hunt_id,
        rule_title=title,
        target=target,
        dialect=target.split("_")[-1] if "_" in target else "txt",
        query=query,
        description=description,
        severity=severity,
        techniques=techniques or [],
        tags=tags or [],
    )
    deployer = QueryDeployer()
    result = deployer.deploy(payload, dry_run=dry_run)
    return result.to_dict()


def undeploy_transpiled_query(
    target: str,
    hunt_id: str,
    title: str,
    query: str = "",
    remote_id: Optional[str] = None,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """Undeploy/delete a transpiled search query from its target SIEM or EDR platform via REST API."""
    from hecate_agent.core.query_deployer import QueryDeployer, UndeploymentPayload

    payload = UndeploymentPayload(
        hunt_id=hunt_id,
        rule_title=title,
        target=target,
        remote_id=remote_id,
        query=query,
    )
    deployer = QueryDeployer()
    result = deployer.undeploy(payload, dry_run=dry_run)
    return result.to_dict()


def sync_transpiled_query(
    target: str,
    query: str,
    hunt_id: str,
    title: str,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """Verify synchronization and drift of a transpiled search query against target SIEM/EDR."""
    from hecate_agent.core.query_deployer import DeploymentPayload, QueryDeployer

    payload = DeploymentPayload(
        hunt_id=hunt_id,
        rule_title=title,
        target=target,
        dialect=target.split("_")[-1] if "_" in target else "txt",
        query=query,
    )
    deployer = QueryDeployer()
    result = deployer.sync(payload, dry_run=dry_run)
    return result.to_dict()


def tune_sigma_rule(
    rule_yaml: str,
    critique: str,
    events: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[str, str]:
    """Tune a Sigma rule using natural language analyst feedback and semantic validation."""
    from hecate_agent.core.sigma_self_tuner import SigmaSelfTuner

    tuner = SigmaSelfTuner()
    return tuner.tune_rule(rule_yaml, critique, events=events)
