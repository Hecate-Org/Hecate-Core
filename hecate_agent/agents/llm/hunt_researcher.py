"""Hunt researcher agent - LLM-powered thorough research before hunting.

Implements a structured 5-skill research methodology:
1. System Research - How does the technology/process normally work?
2. Adversary Tradecraft - How do adversaries abuse it? (web search)
3. Telemetry Mapping - What OCSF fields and data sources capture this?
4. Related Work - What past hunts/investigations are relevant?
5. Synthesis - Key findings, gaps, recommended focus areas
"""

import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from hecate_agent.agents.base import AgentResult, LLMAgent
from hecate_agent.core.telemetry_examples import render_examples
from hecate_agent.core.telemetry_mapping import documented_data_sources, map_findings
from hecate_agent.core.workspace import knowledge_file
from hecate_agent.core.hunting_knowledge import EVIDENCE_RULES, load_environment_context, load_stage_guidance

logger = logging.getLogger(__name__)

# Sentinel key_findings value each _llm_* method's except-block returns on
# failure (see e.g. _llm_summarize_tradecraft below). Every _skill_N_* caller
# used to compute confidence purely from whether *sources* existed (web
# search results), completely blind to whether the LLM call itself
# succeeded -- so a failed call whose "summary" is literally an error
# message could still be reported at 0.8-0.95 confidence. Checking for this
# sentinel lets the skill methods force confidence down on a real failure.
_LLM_ERROR_KEY_FINDING = "Error during LLM analysis"

# Skill 3 is now allowed to return no fields at all: a source that describes
# no adversary behavior (a bare indicator list, say) has no telemetry to map,
# and the prompt used to demand "4-6 specific OCSF fields" regardless. That
# quota is what produced sections mapping unrelated behavior lifted from the
# environment profile. An empty result is rendered as this visible gap rather
# than a blank section, so a reviewer sees the absence.
_NO_TELEMETRY_KEY_FINDING = "No telemetry mapped - the source describes no behavior to detect"


def _llm_call_failed(key_findings: List[str]) -> bool:
    return key_findings == [_LLM_ERROR_KEY_FINDING]


def _no_telemetry_mapped(key_findings: List[str]) -> bool:
    return key_findings == [_NO_TELEMETRY_KEY_FINDING]


# Web search snippets are truncated to 200 chars each (see
# _skill_1_system_research/_skill_2_adversary_tradecraft) -- barely more than
# a headline. Asking for "4-6 key findings about attack methods, tools used,
# and indicators" from a handful of title+200-char fragments pressures the
# model to invent plausible-sounding specifics to fill the gap, especially
# for an evocative/ambiguous title. This instruction used to only appear in
# the zero-sources fallback context string; a real, observed case (R-0005,
# topic: a Talos report quoting a captured attacker<->AI-agent prompt log)
# had *some* thin sources and fabricated an unrelated claim ("malware embeds
# this phrase to manipulate victims") that the fallback-only wording never
# would have reached. Applying it unconditionally closes that gap.
#
# The source-quality sentence below is a second, independent gap: web_search.py's
# EXCLUDE_DOMAINS blocks known social-media reposts and URL-tracker tools at
# the API level, but that's a fixed list and can't anticipate every generic
# content-mill/tutorial domain (observed: oxfordhomestudy.com, a "how does AI
# work?" tutoring-site explainer, cited as a source because it was topically
# relevant to an otherwise-vague CTI topic). A hard filter can't catch that
# long tail; asking the model to weigh source authority when it already has
# the title/snippet in front of it can.
#: How much of the source item reaches each prompt. Enough for a full OTX or
#: MISP blurb including its key indicators; the local model's context is the
#: constraint, and the skills already carry schema and search context.
# Raised from 4,000 once the workspace model ran with a 16K context: the
# Runner now sends the feed item plus the primary source's verified artifacts
# (hecate_agent.core.source_evidence), which a 4,000 cut truncated mid-list.
_SOURCE_CONTEXT_MAX_CHARS = 12000

_GROUNDING_INSTRUCTION = (
    "Base your summary and findings strictly on the Research Context above. "
    "Do not invent facts, statistics, named campaigns, or technical details "
    "that are not present in it -- infer only what a careful reader would "
    "reasonably conclude from the text given. If the context doesn't contain "
    "enough detail to support a specific claim, omit it or flag it with "
    "[UNCERTAIN] rather than filling the gap with a plausible-sounding guess. "
    "Also weigh source quality: prioritize named security vendors, "
    "researchers, and established publications, and discount or ignore "
    "generic tutorial/explainer content, personal blogs, and other "
    "low-authority material even when it's topically relevant. "
    "Documentation/example IP ranges (including RFC 5737 TEST-NET) are exercise data, "
    "not live adversary infrastructure. Their reserved status is not misclassification "
    "or an adversary evasion technique."
)


# Keyword presence (lowercased, substring match) used to derive data-source
# availability from skill 3's free-text telemetry-mapping output. See
# _extract_data_sources.
# Match the label at the start of a synthesis key_finding, tolerating
# markdown bold markers and the phrasing variations models actually produce
# ("Hypothesis:", "**Recommended Hypothesis:**", "Hunt Hypothesis:", ...).
# See _extract_hypothesis/_extract_gaps.
_HYPOTHESIS_PREFIX_RE = re.compile(r"^\**\s*(recommended\s+|hunt\s+)?hypothesis\s*:?\**\s*", re.IGNORECASE)
_GAP_PREFIX_RE = re.compile(r"^\**\s*(knowledge\s+|coverage\s+)?gaps?\s*:?\**\s*", re.IGNORECASE)

# CVE identifiers asserted by the model are checked against the sources
# actually retrieved; see _drop_unsupported_cve_findings.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Keywords that say a research doc's telemetry mapping *discusses* a data
# source. Deliberately spelling-tolerant: the original list held only OCSF
# dotted names ("file.path", "network."), so a mapping whose Key Fields
# section literally read "file_paths: Tracks file paths accessed" scored
# file_operations as absent. Underscore, spaced and bare-field spellings all
# describe the same telemetry and all appear in real model output.
_DATA_SOURCE_KEYWORDS: Dict[str, List[str]] = {
    "process_execution": [
        "process.name",
        "process execution",
        "process creation",
        "command_line",
        "process.cmd_line",
        "process_name",
        "commandline",
        "command line",
        "parentproc",
        "parent process",
        "image|",
        "childproc",
    ],
    "file_operations": [
        "file operation",
        "file.path",
        "file.name",
        "file write",
        "file creation",
        "file access",
        "file_path",
        "file paths",
        "file path",
        "filename",
        "file_name",
        "targetfilename",
        "file event",
    ],
    "network_connections": [
        "network connection",
        "network.",
        "dst_endpoint",
        "src_endpoint",
        "connection_info",
        "network_connection",
        "destination ip",
        "destinationip",
        "dst_ip",
        "dns",
        "http",
        "beacon",
        "c2 ",
        "command and control",
        "network traffic",
        "netflow",
    ],
    "registry_events": [
        "registry",
        "reg_key",
        "regkey",
        "run key",
        "targetobject",
        "service registration",
        "autorun",
    ],
}


@dataclass
class ResearchInput:
    """Input for hunt research."""

    topic: str  # Research topic (e.g., "LSASS memory dumping")
    mitre_technique: Optional[str] = None  # Optional T-code to focus research
    depth: str = "advanced"  # "basic" (5 min) or "advanced" (15-20 min)
    include_past_hunts: bool = True
    include_telemetry_mapping: bool = True
    web_search_enabled: bool = True  # Can be disabled for offline mode
    # ID allocated by the caller, so a caller that needs to name the document
    # before research starts (the `hecate-agent research new` banner) does not have to
    # allocate a second one. Allocation persists a high-water mark, so a
    # discarded ID is a permanent gap in the numbering -- and the caller's
    # banner would name a document that never gets written. None means this
    # agent allocates its own.
    research_id: Optional[str] = None
    # The intelligence item this research is about, verbatim. The topic is a
    # short label for web search; without this the skills saw only the label,
    # so a PolinRider pulse describing Git history rewriting, font-file
    # payloads and IDE-task autorun was researched from its headline alone,
    # and a pun in a title ("We'll Call Your APIs") became a telemetry gap.
    source_context: Optional[str] = None
    workspace: Optional[Path] = None


@dataclass
class ResearchSkillOutput:
    """Output from a single research skill."""

    skill_name: str  # e.g., "system_research", "adversary_tradecraft"
    summary: str
    key_findings: List[str]
    sources: List[Dict[str, str]]  # {"title": "", "url": "", "snippet": ""}
    confidence: float  # 0-1 confidence in findings
    duration_ms: int = 0
    #: Telemetry mapping only: fields the model proposed that are not OCSF
    #: paths even after normalization, listed apart from the mapping.
    removed_fields: List[str] = field(default_factory=list)


@dataclass
class ResearchOutput:
    """Complete research output following OTR-inspired 5 skills."""

    research_id: str  # R-XXXX format
    topic: str
    mitre_techniques: List[str]

    # 5 OTR-inspired research skills
    system_research: ResearchSkillOutput
    adversary_tradecraft: ResearchSkillOutput
    telemetry_mapping: ResearchSkillOutput
    related_work: ResearchSkillOutput
    synthesis: ResearchSkillOutput

    # Synthesis outputs
    recommended_hypothesis: Optional[str] = None
    data_source_availability: Dict[str, bool] = field(default_factory=dict)
    #: What availability rests on: "environment" (a telemetry section of
    #: environment.md documents it) or "mapping" (no profile; the telemetry
    #: mapping's needs, which say nothing about the estate).
    data_source_basis: str = ""
    estimated_hunt_complexity: str = "medium"  # low/medium/high
    gaps_identified: List[str] = field(default_factory=list)

    # Cost tracking
    total_duration_ms: int = 0
    threat_actor_profiles: List[Dict[str, Any]] = field(default_factory=list)
    web_searches_performed: int = 0
    #: Whether this run asked for web search, and when none succeeded, why:
    #: disabled for the item, no key, client unavailable, or searches failed.
    web_search_requested: bool = False
    web_search_note: str = ""
    llm_calls: int = 0
    #: None when the cost is not known: a local model with no per-token
    #: price, or a provider that reported no usage. ``cost_basis`` says which.
    total_cost_usd: Optional[float] = 0.0
    cost_basis: str = ""
    max_input_tokens: Optional[int] = None
    input_token_samples: Optional[int] = None
    input_tokens: int = 0
    output_tokens: int = 0
    llm_duration_ms: int = 0
    llm_models: List[str] = field(default_factory=list)


def _availability_basis(environment: str) -> str:
    """Mirrors `_extract_data_sources`: the profile when one loaded, else the mapping."""
    text = (environment or "").lower()
    return "environment" if text and "not found" not in text[:60] else "mapping"


def research_grounding(web_searches: int) -> str:
    """``independent`` when at least one web search succeeded, else ``source-only``.

    Source-only research restates the item it was given. It can organise and
    explain that item, but it cannot corroborate it, and callers must not
    count it as independent evidence.
    """
    return "independent" if web_searches > 0 else "source-only"


class HuntResearcherAgent(LLMAgent[ResearchInput, ResearchOutput]):
    """Performs thorough research before hunt creation.

    Implements a structured 5-skill research methodology:
    1. System Research - How does the technology/process normally work?
    2. Adversary Tradecraft - How do adversaries abuse it? (web search)
    3. Telemetry Mapping - What OCSF fields and data sources capture this?
    4. Related Work - What past hunts/investigations are relevant?
    5. Research Synthesis - Key findings, gaps, recommended focus areas

    Features:
    - Web search via Tavily API for external threat intel
    - OCSF schema awareness for telemetry mapping
    - Past hunt correlation via similarity search
    - Cost tracking across all operations
    - Fallback to limited research when APIs unavailable
    """

    def __init__(
        self,
        llm_enabled: bool = True,
        tavily_api_key: Optional[str] = None,
        provider: Optional[Any] = None,
    ) -> None:
        """Initialize researcher with optional API keys."""
        super().__init__(llm_enabled=llm_enabled, provider=provider)
        self.tavily_api_key = tavily_api_key or os.getenv("TAVILY_API_KEY")
        self._search_client: Optional[Any] = None
        self._search_client_failed = False
        self._search_failed = False
        #: First failure detail, for the research document's grounding note.
        self._search_failure_detail = ""
        self._web_searches = 0
        self._workspace: Optional[Path] = None

    def _log_llm_metrics(
        self,
        agent_name: str,
        model_id: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        duration_ms: int,
    ) -> None:
        """Track LLM call metrics for cost reporting."""
        super()._log_llm_metrics(
            agent_name=agent_name,
            model_id=model_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            duration_ms=duration_ms,
        )

    def _get_search_client(self) -> Optional[Any]:
        """Get or create Tavily search client.

        A failure here is reported, not swallowed. Returning None silently
        makes the caller skip web search, so research completes and looks
        successful while being entirely ungrounded -- the exact degradation
        that is hardest to notice from the finished document.
        """
        if self._search_client is None and self.tavily_api_key:
            try:
                from hecate_agent.core.web_search import TavilySearchClient

                self._search_client = TavilySearchClient(
                    api_key=self.tavily_api_key,
                )
            except Exception as exc:
                if not self._search_client_failed:
                    # Once per agent: this is called per skill, and a repeated
                    # traceback per research run buries the first one.
                    logger.warning(
                        "Web search client unavailable, research will run UNGROUNDED: %s",
                        exc,
                    )
                    self._search_client_failed = True
                    self._search_failure_detail = f"search client unavailable: {exc}"
        return self._search_client

    def _web_search_note(self, requested: bool) -> str:
        """Why this run has no web searches, or "" when it has some."""
        if self._web_searches > 0:
            return ""
        if not requested:
            return "web search not requested for this item"
        if not self.tavily_api_key:
            return "no TAVILY_API_KEY configured"
        return self._search_failure_detail or "no search returned usable results"

    def _note_search_failure(self, exc: BaseException) -> None:
        """Report a failed web search once per agent.

        Swallowing this is how grounding stayed off unnoticed. The client built
        fine and the key was set, so every check upstream looked healthy, while
        the search itself returned 403 "exceeds your plan's set usage limit" on
        every call -- research completed, recorded `web_searches: 0`, and read
        as a finished document.
        """
        if self._search_failed:
            return
        self._search_failed = True
        self._search_failure_detail = f"web search failed: {type(exc).__name__}: {exc}"
        logger.warning(
            "Web search FAILED, research for this run is UNGROUNDED: %s: %s",
            type(exc).__name__,
            exc,
        )

    def _technique_grounding(self, technique: Optional[str]) -> str:
        """Ground truth for a technique ID from local STIX data, if available.

        Skill prompts used to hand the model a bare technique ID (e.g.
        "T1053.005") and ask it to reason about it from memory. An eval
        harness spot check (``hecate-agent eval``) measured that cold recall gets
        MITRE technique identity right only ~30% of the time; handing the
        model the real name/description from ``hecate-agent attack lookup`` instead
        of asking it to recall them raised that to 100% on the same model in
        the same check. This is that fix, applied to the research prompts.

        Returns an empty string (not an error) if there's no technique, no
        STIX data installed, or the ID isn't found — callers already handle
        an empty technique_str/context gracefully.
        """
        if not technique:
            return ""
        try:
            from hecate_agent.core.attack_matrix import get_technique

            info = get_technique(technique)
        except Exception:
            return ""
        if info is None:
            return ""

        name = info.get("name", technique)
        description = (info.get("description") or "").strip()[:400]
        return f'MITRE ATT&CK ground truth for {technique}: officially named "{name}". {description}\n\n'

    def execute(
        self,
        input_data: ResearchInput,
    ) -> AgentResult[ResearchOutput]:
        """Execute complete research workflow.

        Args:
            input_data: Research input with topic, technique, and depth

        Returns:
            AgentResult with complete research output or error
        """
        start_time = time.time()
        self._reset_llm_usage()
        self._web_searches = 0
        self._workspace = input_data.workspace
        # Read by every skill's prompt; set once before the skills fan out.
        self._source_context = (input_data.source_context or "").strip()[:_SOURCE_CONTEXT_MAX_CHARS]

        from hecate_agent.core.attack_matrix import search_groups_in_text

        primary_context = self._source_context.split("SECONDARY OSINT ENRICHMENT", 1)[0]
        actor_profiles = [dict(p) for p in search_groups_in_text(f"{input_data.topic} {primary_context}")]
        self._actor_profiles = actor_profiles

        try:
            # Get next research ID
            from hecate_agent.core.research_manager import ResearchManager

            manager = ResearchManager()
            research_id = input_data.research_id or manager.get_next_research_id()

            # Determine search depth based on input
            search_depth = "basic" if input_data.depth == "basic" else "advanced"

            # Execute skills 1-4 in parallel (they are independent)
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=4) as executor:
                future_1 = executor.submit(
                    self._skill_1_system_research,
                    input_data.topic,
                    search_depth,
                    input_data.web_search_enabled,
                )
                future_2 = executor.submit(
                    self._skill_2_adversary_tradecraft,
                    input_data.topic,
                    input_data.mitre_technique,
                    search_depth,
                    input_data.web_search_enabled,
                )
                future_3 = executor.submit(
                    self._skill_3_telemetry_mapping,
                    input_data.topic,
                    input_data.mitre_technique,
                )
                future_4 = executor.submit(
                    self._skill_4_related_work,
                    input_data.topic,
                )

                skill_1 = future_1.result()
                skill_2 = future_2.result()
                skill_3 = future_3.result()
                skill_4 = future_4.result()

            # Skill 5 (synthesis) depends on skills 1-4
            skill_5 = self._skill_5_synthesis(
                input_data.topic,
                input_data.mitre_technique,
                [skill_1, skill_2, skill_3, skill_4],
            )

            # Strip findings that assert a CVE no retrieved source mentions.
            # A real run stated "CVE-2024-1234 is associated with the initial
            # access vector" as fact; no such CVE appeared in the source event
            # or in any snippet the search returned. A fabricated identifier
            # is worse than a vague one -- it is specific, checkable, and
            # propagates into the hunt as grounding.
            for skill in (skill_1, skill_2, skill_3, skill_4, skill_5):
                self._drop_unsupported_cve_findings(skill, " ".join([input_data.topic, self._source_context]))

            # Extract synthesis outputs
            mitre_techniques = [input_data.mitre_technique] if input_data.mitre_technique else []

            # Build output
            total_duration_ms = int((time.time() - start_time) * 1000)
            usage = self._llm_usage_metadata()

            output = ResearchOutput(
                research_id=research_id,
                topic=input_data.topic,
                mitre_techniques=mitre_techniques,
                system_research=skill_1,
                adversary_tradecraft=skill_2,
                telemetry_mapping=skill_3,
                related_work=skill_4,
                synthesis=skill_5,
                recommended_hypothesis=self._extract_hypothesis(skill_5),
                data_source_availability=self._extract_data_sources(
                    skill_3,
                    self._load_environment(),
                ),
                data_source_basis=_availability_basis(self._load_environment()),
                estimated_hunt_complexity=self._estimate_complexity(
                    skill_2,
                    skill_3,
                ),
                gaps_identified=self._extract_gaps(skill_5),
                total_duration_ms=total_duration_ms,
                threat_actor_profiles=actor_profiles,
                web_searches_performed=self._web_searches,
                web_search_requested=input_data.web_search_enabled,
                web_search_note=self._web_search_note(input_data.web_search_enabled),
                llm_calls=usage["llm_calls"],
                total_cost_usd=usage["estimated_cost_usd"],
                cost_basis=usage.get("cost_basis", ""),
                max_input_tokens=usage["max_input_tokens"],
                input_token_samples=usage["input_token_samples"],
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                llm_duration_ms=usage["llm_duration_ms"],
                llm_models=usage["models"],
            )

            return AgentResult(
                success=True,
                data=output,
                error=None,
                warnings=[],
                metadata={
                    "research_id": research_id,
                    "duration_ms": total_duration_ms,
                    "web_searches": self._web_searches,
                    **usage,
                },
            )

        except Exception as e:
            return AgentResult(
                success=False,
                data=None,
                error=str(e),
                warnings=[],
                metadata={
                    "duration_ms": int((time.time() - start_time) * 1000),
                    "web_searches": self._web_searches,
                    **self._llm_usage_metadata(),
                },
            )

    def _skill_1_system_research(
        self,
        topic: str,
        search_depth: str,
        web_search_enabled: bool,
    ) -> ResearchSkillOutput:
        """Skill 1: Research how the system/technology normally works.

        Args:
            topic: Research topic
            search_depth: "basic" or "advanced"
            web_search_enabled: Whether web search is enabled. Used to be
                ignored here (only skill 2 checked it) -- a caller passing
                web_search_enabled=False specifically because the topic has
                nothing real to search for (e.g. hecate-runner disabling it
                for narrative-free CTI, a bare IOC-count blurb with no
                description) would still have this skill search anyway.

        Returns:
            ResearchSkillOutput with system research findings
        """
        start_time = time.time()
        sources: List[Dict[str, str]] = []
        search_results = None

        # Try web search for system internals
        search_client = self._get_search_client()
        if search_client and web_search_enabled:
            try:
                search_results = search_client.search_system_internals(
                    topic,
                    search_depth,
                )
                self._web_searches += 1

                for result in search_results.results[:5]:
                    snippet = result.content
                    if len(snippet) > 200:
                        snippet = snippet[:200] + "..."
                    sources.append(
                        {
                            "title": result.title,
                            "url": result.url,
                            "snippet": snippet,
                        }
                    )
            except Exception as exc:
                self._note_search_failure(exc)

        # Generate summary using LLM
        if self.llm_enabled:
            summary, key_findings = self._llm_summarize_system_research(
                topic,
                sources,
                search_results,
            )
        else:
            summary = "System research for {} - requires LLM for detailed analysis".format(topic)
            key_findings = ["LLM disabled - manual research required"]

        duration_ms = int((time.time() - start_time) * 1000)

        confidence = 0.8 if sources else 0.5
        if _llm_call_failed(key_findings):
            confidence = 0.1  # summary is an error message, not a finding

        return ResearchSkillOutput(
            skill_name="system_research",
            summary=summary,
            key_findings=key_findings,
            sources=sources,
            confidence=confidence,
            duration_ms=duration_ms,
        )

    def _skill_2_adversary_tradecraft(
        self,
        topic: str,
        technique: Optional[str],
        search_depth: str,
        web_search_enabled: bool,
    ) -> ResearchSkillOutput:
        """Skill 2: Research adversary tradecraft via web search.

        Args:
            topic: Research topic
            technique: Optional MITRE ATT&CK technique
            search_depth: "basic" or "advanced"
            web_search_enabled: Whether web search is enabled

        Returns:
            ResearchSkillOutput with adversary tradecraft findings
        """
        start_time = time.time()
        sources: List[Dict[str, str]] = []
        search_results = None

        # Try web search for adversary tradecraft
        search_client = self._get_search_client()
        if search_client and web_search_enabled:
            try:
                search_results = search_client.search_adversary_tradecraft(
                    topic,
                    technique,
                    search_depth,
                )
                self._web_searches += 1

                for result in search_results.results[:7]:
                    snippet = result.content
                    if len(snippet) > 200:
                        snippet = snippet[:200] + "..."
                    sources.append(
                        {
                            "title": result.title,
                            "url": result.url,
                            "snippet": snippet,
                        }
                    )
            except Exception as exc:
                self._note_search_failure(exc)

        # Generate summary using LLM
        if self.llm_enabled:
            summary, key_findings = self._llm_summarize_tradecraft(
                topic,
                technique,
                sources,
                search_results,
            )
        else:
            summary = "Adversary tradecraft for {} - requires LLM for detailed analysis".format(topic)
            key_findings = ["LLM disabled - manual research required"]

        duration_ms = int((time.time() - start_time) * 1000)

        confidence = 0.85 if sources else 0.4
        if _llm_call_failed(key_findings):
            confidence = 0.1  # summary is an error message, not a finding

        return ResearchSkillOutput(
            skill_name="adversary_tradecraft",
            summary=summary,
            key_findings=key_findings,
            sources=sources,
            confidence=confidence,
            duration_ms=duration_ms,
        )

    def _skill_3_telemetry_mapping(
        self,
        topic: str,
        technique: Optional[str],
    ) -> ResearchSkillOutput:
        """Skill 3: Map to OCSF fields and available data sources.

        Args:
            topic: Research topic
            technique: Optional MITRE ATT&CK technique

        Returns:
            ResearchSkillOutput with telemetry mapping
        """
        start_time = time.time()
        sources: List[Dict[str, str]] = []

        # Load OCSF schema reference
        ocsf_schema = self._load_ocsf_schema()
        schema_available = ocsf_schema != "OCSF schema reference not found"
        environment_data = self._load_environment()

        # Generate telemetry mapping using LLM
        if self.llm_enabled:
            summary, key_findings = self._llm_map_telemetry(
                topic,
                technique,
                ocsf_schema,
                environment_data,
            )
        else:
            summary = "Telemetry mapping for {} - requires LLM for detailed analysis".format(topic)
            key_findings = [
                "Common fields: process.name, process.cmd_line, actor.user.name",
                # Not "population rates": the prompt forbids stating them,
                # because this estate has not been measured and any figure
                # would be invented. The reference carries field *names*.
                "See knowledge/OCSF_SCHEMA_REFERENCE.md for canonical field names",
            ]

        if not key_findings:
            key_findings = [_NO_TELEMETRY_KEY_FINDING]

        # Normalized (event-class prefixes stripped), validated, and mapped to
        # the environment profile's own field names; invalid fields are
        # removed and listed apart, not flagged inline in the mapping.
        mapped = map_findings(key_findings, environment_data)
        key_findings, removed_fields = mapped.findings, mapped.removed

        # Add schema reference as source
        sources.append(
            {
                "title": "OCSF Schema Reference",
                "url": "knowledge/OCSF_SCHEMA_REFERENCE.md",
                "snippet": (
                    "Canonical OCSF field names for the classes this program hunts in"
                    if schema_available
                    else "Schema file not found — field findings are based on model recall"
                ),
            }
        )

        duration_ms = int((time.time() - start_time) * 1000)

        # Confidence is high only when backed by the local schema file;
        # without it the LLM is reasoning from memory alone.
        confidence = 0.9 if schema_available else 0.4
        if _llm_call_failed(key_findings):
            confidence = 0.1  # summary is an error message, not a finding
        elif _no_telemetry_mapped(key_findings):
            # The call succeeded; there was simply nothing to map. Schema
            # availability says nothing about the quality of that answer.
            confidence = 0.2

        return ResearchSkillOutput(
            skill_name="telemetry_mapping",
            summary=summary,
            key_findings=key_findings,
            sources=sources,
            confidence=confidence,
            duration_ms=duration_ms,
            removed_fields=removed_fields,
        )

    def _skill_4_related_work(
        self,
        topic: str,
    ) -> ResearchSkillOutput:
        """Skill 4: Find related past hunts and investigations.

        Args:
            topic: Research topic

        Returns:
            ResearchSkillOutput with related work
        """
        start_time = time.time()
        sources: List[Dict[str, str]] = []
        key_findings: List[str] = []

        # Use similarity search to find related hunts
        similar_hunts: List[Dict[str, Any]] = []
        try:
            from hecate_agent.commands.similar import (
                SimilarityUnavailable,
                _find_similar_hunts,
            )

            similar_hunts = _find_similar_hunts(
                topic,
                limit=5,
                threshold=0.3,
            )

            for hunt in similar_hunts:
                sources.append(
                    {
                        "title": "{}: {}".format(
                            hunt["hunt_id"],
                            hunt["title"],
                        ),
                        "url": "hunts/{}.md".format(hunt["hunt_id"]),
                        "snippet": "Status: {}, Score: {:.3f}".format(
                            hunt["status"],
                            hunt["similarity_score"],
                        ),
                    }
                )
                key_findings.append(
                    "{}: {} (similarity: {:.2f})".format(
                        hunt["hunt_id"],
                        hunt["title"],
                        hunt["similarity_score"],
                    )
                )

        except SimilarityUnavailable as exc:
            # Never fold this into "no similar hunts found". A search that
            # could not run and a search that ran and matched nothing say
            # opposite things about how novel the topic is, and the model
            # reads this line as evidence.
            logger.warning("Related-hunt similarity unavailable: %s", exc)
            key_findings.append("Similarity search unavailable - related-hunt coverage was NOT checked")
        except Exception as exc:
            logger.warning("Related-hunt similarity failed: %s", exc)
            key_findings.append("Similarity search failed - related-hunt coverage was NOT checked")

        summary = "Found {} related hunts for {}".format(
            len(sources),
            topic,
        )
        if not sources:
            summary = "No related hunts found for {} - this may be a new research area".format(topic)

        duration_ms = int((time.time() - start_time) * 1000)

        return ResearchSkillOutput(
            skill_name="related_work",
            summary=summary,
            key_findings=(key_findings if key_findings else ["No related past hunts found"]),
            sources=sources,
            confidence=0.95,  # High confidence - based on internal search
            duration_ms=duration_ms,
        )

    def _skill_5_synthesis(
        self,
        topic: str,
        technique: Optional[str],
        skills: List[ResearchSkillOutput],
    ) -> ResearchSkillOutput:
        """Skill 5: Synthesize all research into actionable insights.

        Args:
            topic: Research topic
            technique: Optional MITRE ATT&CK technique
            skills: Outputs from skills 1-4

        Returns:
            ResearchSkillOutput with synthesis
        """
        start_time = time.time()

        # Generate synthesis using LLM
        if self.llm_enabled:
            summary, key_findings = self._llm_synthesize(
                topic,
                technique,
                skills,
            )
        else:
            summary = "Research synthesis for {}".format(topic)
            key_findings = [
                "LLM disabled - manual synthesis required",
                "Review individual skill outputs for findings",
            ]

        duration_ms = int((time.time() - start_time) * 1000)

        confidence = 0.8
        if _llm_call_failed(key_findings):
            confidence = 0.1  # summary is an error message, not a finding

        return ResearchSkillOutput(
            skill_name="synthesis",
            summary=summary,
            key_findings=key_findings,
            sources=[],  # Synthesis doesn't have external sources
            confidence=confidence,
            duration_ms=duration_ms,
        )

    def _source_block(self) -> str:
        """The source intelligence, framed as primary evidence, or nothing."""
        text = getattr(self, "_source_context", "")
        if not text:
            return ""
        return (
            "Source Intelligence (the report this research is about -- primary"
            " evidence; where web results disagree with it, it wins):\n"
            "{}\n\n".format(text)
        )

    def _llm_summarize_system_research(
        self,
        topic: str,
        sources: List[Dict[str, str]],
        search_results: Optional[Any],
    ) -> Tuple[str, List[str]]:
        """Use LLM to summarize system research findings."""
        try:
            # Build context from sources
            context = ""
            if search_results and hasattr(search_results, "answer") and search_results.answer:
                context = "Web search summary: {}\n\n".format(
                    search_results.answer,
                )

            for source in sources[:5]:
                context += "- {}: {}\n".format(
                    source["title"],
                    source["snippet"],
                )

            if not context:
                context = (
                    "No external sources are available. "
                    "Rely only on well-established, widely-documented knowledge. "
                    "Clearly flag any claims you are uncertain about with [UNCERTAIN]."
                )

            prompt = (
                "You are a security researcher studying system"
                " internals.\n\n"
                "Topic: {topic}\n\n"
                "{source}"
                "Research Context:\n{context}\n\n"
                "{grounding}\n\n"
                "Based on this context, provide:\n"
                "1. A concise summary (2-3 sentences) of how this"
                " system/technology normally works from the perspective of an endpoint or network sensor.\n"
                "2. 3-5 key findings about normal behavior, focusing on the specific processes, files, network connections, or telemetry generated. Avoid generic corporate IT descriptions.\n\n"
                "Return JSON format:\n"
                '{{\n  "summary": "string",\n'
                '  "key_findings": ["finding1", "finding2",'
                ' "finding3"]\n}}'
            ).format(
                topic=topic,
                source=self._source_block(),
                context=context,
                grounding=_GROUNDING_INSTRUCTION,
            )

            def validate_json(text: str) -> Optional[str]:
                try:
                    data = self._parse_json_response(text)
                except ValueError as exc:
                    return str(exc)
                if "summary" not in data or "key_findings" not in data:
                    return "response JSON missing summary or key_findings"
                return None

            response = self._call_llm_with_retry(
                prompt,
                validate_json,
                max_retries=1,
                max_tokens=2048,
                capability="research_summarize",
            )
            data = self._parse_json_response(response)
            return data["summary"], data["key_findings"]

        except Exception as e:
            return (
                "System research for {} (LLM error: {})".format(
                    topic,
                    str(e)[:50],
                ),
                [_LLM_ERROR_KEY_FINDING],
            )

    def _actor_grounding(self) -> str:
        profiles = getattr(self, "_actor_profiles", [])
        if not profiles:
            return ""
        lines = []
        for a in profiles:
            soft_names = [
                f"{s.get('name')} ({s.get('type', 'software').title()} - {s.get('id')})"
                for s in a.get("software", [])
                if s.get("name")
            ]
            tech_names = [f"{t.get('id')} ({t.get('name')})" for t in a.get("techniques", []) if t.get("id")]
            desc = (a.get("description") or "").strip()[:400]
            block = (
                f"Adversary Threat Actor Profile ({a.get('name')} - {a.get('id')}):\n"
                f"- Aliases: {', '.join(a.get('aliases', []))}\n"
                f"- Background: {desc}\n"
            )
            if soft_names:
                block += f"- Known Associated Software & Toolkits: {', '.join(soft_names[:12])}\n"
            if tech_names:
                block += f"- Observed ATT&CK Techniques: {', '.join(tech_names[:15])}\n"
            lines.append(block)
        return "Authoritative MITRE ATT&CK STIX Threat Actor Grounding:\n" + "\n".join(lines) + "\n\n"

    def _llm_summarize_tradecraft(
        self,
        topic: str,
        technique: Optional[str],
        sources: List[Dict[str, str]],
        search_results: Optional[Any],
    ) -> Tuple[str, List[str]]:
        """Use LLM to summarize adversary tradecraft findings."""
        try:
            # Build context from sources
            context = ""
            if search_results and hasattr(search_results, "answer") and search_results.answer:
                context = "Web search summary: {}\n\n".format(
                    search_results.answer,
                )

            for source in sources[:7]:
                context += "- {}: {}\n".format(
                    source["title"],
                    source["snippet"],
                )

            if not context:
                context = (
                    "No external sources are available. "
                    "Rely only on well-established, widely-documented adversary techniques. "
                    "Clearly flag any claims you are uncertain about with [UNCERTAIN]."
                )

            technique_str = " ({})".format(technique) if technique else ""
            grounding = self._technique_grounding(technique)
            actor_grounding = self._actor_grounding()

            prompt = (
                "You are a threat intelligence analyst studying"
                " adversary techniques.\n\n"
                "{actor_grounding}"
                "{grounding}"
                "Topic: {topic}{technique_str}\n\n"
                "{source}"
                "Research Context:\n{context}\n\n"
                "{anti_hallucination}\n\n"
                "Based on this context, provide:\n"
                "1. A concise summary (2-3 sentences) of how"
                " adversaries abuse this system/technique\n"
                "2. 4-6 key findings about attack methods, tools"
                " used, and indicators\n\n"
                "Return JSON format:\n"
                '{{\n  "summary": "string",\n'
                '  "key_findings": ["finding1", "finding2",'
                ' "finding3", "finding4"]\n}}'
            ).format(
                actor_grounding=actor_grounding,
                grounding=grounding,
                anti_hallucination=_GROUNDING_INSTRUCTION,
                topic=topic,
                technique_str=technique_str,
                source=self._source_block(),
                context=context,
            )

            def validate_json(text: str) -> Optional[str]:
                try:
                    data = self._parse_json_response(text)
                except ValueError as exc:
                    return str(exc)
                if "summary" not in data or "key_findings" not in data:
                    return "response JSON missing summary or key_findings"
                return None

            response = self._call_llm_with_retry(
                prompt,
                validate_json,
                max_retries=1,
                max_tokens=2048,
                capability="research_summarize",
            )
            data = self._parse_json_response(response)
            return data["summary"], data["key_findings"]

        except Exception as e:
            return (
                "Adversary tradecraft for {} (LLM error: {})".format(
                    topic,
                    str(e)[:50],
                ),
                [_LLM_ERROR_KEY_FINDING],
            )

    def _llm_map_telemetry(
        self,
        topic: str,
        technique: Optional[str],
        ocsf_schema: str,
        environment_data: str,
    ) -> Tuple[str, List[str]]:
        """Use LLM to map topic to OCSF telemetry fields."""
        try:
            technique_str = " ({})".format(technique) if technique else ""
            grounding = self._technique_grounding(technique)

            prompt = (
                "You are a detection engineer mapping attack"
                " behaviors to telemetry.\n\n"
                "{grounding}"
                "Topic: {topic}{technique_str}\n\n"
                "{source}"
                "OCSF Schema Reference (partial):\n"
                "{ocsf_schema}\n\n"
                "{telemetry_examples}"
                "Environment:\n{environment_data}\n\n"
                "FIRST decide: does the topic or source intelligence describe adversary"
                " behavior -- actions, tooling or technique? A bare list of"
                " indicators (domains, IP addresses, file hashes, URLs) does"
                " not. If it does not, return an empty key_findings list and"
                " say so in the summary. Do not substitute generic, example"
                " or typical attacker behavior to fill the list.\n\n"
                "The environment profile above lists which log sources"
                " exist here. It is not evidence of adversary behavior:"
                " never infer a technique, tool or attack pattern from it,"
                " and do not map fields it happens to mention unless the"
                " topic itself calls for them.\n\n"
                "Do not state field population rates or percentages. This"
                " environment has not been measured, so any figure would be"
                " invented.\n\n"
                "If the topic does describe behavior, provide:\n"
                "1. A concise summary of what telemetry would"
                " capture that behavior\n"
                "2. Up to 6 specific OCSF fields that behavior calls for,"
                " and no others.\n\n"
                "Return JSON format:\n"
                '{{\n  "summary": "string",\n'
                '  "key_findings": ["field1: description",'
                ' "field2: description"]\n}}'
            ).format(
                grounding=grounding,
                topic=topic,
                technique_str=technique_str,
                source=self._source_block(),
                ocsf_schema=ocsf_schema[:3000],
                telemetry_examples=render_examples(f"{topic}\n{self._source_block()}"),
                environment_data=environment_data[:1000],
            )

            def validate_json(text: str) -> Optional[str]:
                try:
                    data = self._parse_json_response(text)
                except ValueError as exc:
                    return str(exc)
                if "summary" not in data or "key_findings" not in data:
                    return "response JSON missing summary or key_findings"
                return None

            response = self._call_llm_with_retry(
                prompt,
                validate_json,
                max_retries=1,
                max_tokens=2048,
                capability="research_summarize",
            )
            data = self._parse_json_response(response)
            return data["summary"], data["key_findings"]

        except Exception as e:
            return (
                "Telemetry mapping for {} (LLM error: {})".format(
                    topic,
                    str(e)[:50],
                ),
                [_LLM_ERROR_KEY_FINDING],
            )

    def _llm_synthesize(
        self,
        topic: str,
        technique: Optional[str],
        skills: List[ResearchSkillOutput],
    ) -> Tuple[str, List[str]]:
        """Use LLM to synthesize all research findings."""
        try:
            # Build context from all skills
            context = ""
            for skill in skills:
                skill_title = skill.skill_name.replace("_", " ").title()
                context += "\n### {}\n".format(skill_title)
                context += "Summary: {}\n".format(skill.summary)
                context += "Key findings:\n"
                for finding in skill.key_findings[:4]:
                    context += "- {}\n".format(finding)

            technique_str = " ({})".format(technique) if technique else ""
            grounding = self._technique_grounding(technique)

            prompt = (
                "You are a senior threat hunter synthesizing"
                " research for a hunt.\n\n"
                "{tradecraft}\n\n"
                "{grounding}"
                "Topic: {topic}{technique_str}\n\n"
                "{source}"
                "Research Findings:\n{context}\n\n"
                "Based on all research findings, provide:\n"
                "1. An executive summary (2-3 sentences)"
                " synthesizing all findings with a strict focus on technical hunt tradecraft (DO NOT include generic security awareness or IT admin advice)\n"
                "2. A recommended hypothesis statement in the"
                ' format: "Adversaries use [behavior] to [goal]'
                ' on [target]"\n'
                "3. 2-3 specific, technical gaps identified in our ability to detect this behavior (e.g., missing specific telemetry, encryption blinding the payload, etc.). Do NOT list generic security awareness gaps like 'missing SPF/DKIM' or 'employee training'.\n"
                "4. 2-3 recommended technical focus areas for the hunt\n\n"
                "Return JSON format:\n"
                '{{\n  "summary": "string",\n'
                '  "key_findings": [\n'
                '    "Hypothesis: Adversaries use...",\n'
                '    "Gap: ...",\n'
                '    "Focus: ..."\n'
                "  ]\n}}"
            ).format(
                tradecraft=EVIDENCE_RULES
                + "\n"
                + load_stage_guidance("research", workspace=getattr(self, "_workspace", None)),
                grounding=grounding,
                topic=topic,
                technique_str=technique_str,
                source=self._source_block(),
                context=context,
            )

            def validate_json(text: str) -> Optional[str]:
                try:
                    data = self._parse_json_response(text)
                except ValueError as exc:
                    return str(exc)
                if "summary" not in data or "key_findings" not in data:
                    return "response JSON missing summary or key_findings"
                return None

            response = self._call_llm_with_retry(
                prompt,
                validate_json,
                max_retries=1,
                max_tokens=2048,
                capability="research_synthesize",
            )
            data = self._parse_json_response(response)
            return data["summary"], data["key_findings"]

        except Exception as e:
            return (
                "Research synthesis for {} (LLM error: {})".format(
                    topic,
                    str(e)[:50],
                ),
                [_LLM_ERROR_KEY_FINDING],
            )

    def _load_ocsf_schema(self) -> str:
        """Load OCSF schema reference content.

        Resolved against the workspace rather than the working directory, so
        a caller that does not chdir into the workspace first still finds it.
        """
        schema_path = knowledge_file("OCSF_SCHEMA_REFERENCE.md", getattr(self, "_workspace", None))
        if schema_path.exists():
            return schema_path.read_text(encoding="utf-8")[:5000]  # Limit size
        return "OCSF schema reference not found"

    def _load_environment(self) -> str:
        """Load environment.md content.

        Workspace-relative for the same reason as the schema above.
        """
        return load_environment_context(workspace=getattr(self, "_workspace", None))

    def _extract_hypothesis(
        self,
        synthesis: ResearchSkillOutput,
    ) -> Optional[str]:
        """Extract recommended hypothesis from synthesis's key_findings.

        Matches phrasing variations (optional markdown bold markers,
        "Recommended Hypothesis:", "Hunt Hypothesis:") instead of only the
        exact literal prefix "hypothesis:" the prompt's own JSON example
        happens to use -- the model doesn't reliably echo that exact
        wording (e.g. "**Recommended Hypothesis:** Adversaries use..." was
        silently dropped by a strict `.startswith("hypothesis:")` check),
        and a research doc missing its hypothesis with no warning is a
        bigger problem than either extra false-positive matching or a
        slightly noisier warning log.
        """
        for finding in synthesis.key_findings:
            match = _HYPOTHESIS_PREFIX_RE.match(finding)
            if match:
                extracted = finding[match.end() :].strip()
                if extracted:
                    return extracted
        if not _llm_call_failed(synthesis.key_findings):
            logger.warning(
                "Could not extract a recommended hypothesis from synthesis key_findings: %r", synthesis.key_findings
            )
        return None

    def _drop_unsupported_cve_findings(self, skill: ResearchSkillOutput, topic: str = "") -> None:
        """Remove key findings citing a CVE that no retrieved source mentions.

        The whole finding goes, not just the identifier. A model that invented
        a CVE invented the sentence around it too, and surgically deleting the
        ID would leave a confident claim about an unnamed vulnerability --
        less obviously wrong, equally unfounded.

        Matched against the search snippets actually returned for this skill
        plus the research topic, so a CVE genuinely reported in a source is
        kept.
        """
        corpus_parts = [topic]
        for source in skill.sources or []:
            corpus_parts.extend(str(source.get(key, "")) for key in ("title", "url", "snippet"))
        corpus_cves: Set[str] = {c.upper() for c in _CVE_RE.findall(" ".join(corpus_parts))}

        kept: List[str] = []
        for finding in skill.key_findings:
            unsupported = sorted({c.upper() for c in _CVE_RE.findall(finding)} - corpus_cves)
            if unsupported:
                logger.warning(
                    "Dropping %s finding citing unsupported %s (absent from every retrieved source): %r",
                    skill.skill_name,
                    ", ".join(unsupported),
                    finding[:120],
                )
                continue
            kept.append(finding)
        skill.key_findings = kept

        skill.summary = self._redact_unsupported_cves(skill.summary, corpus_cves, skill.skill_name)

    @staticmethod
    def _redact_unsupported_cves(summary: str, corpus_cves: Set[str], skill_name: str) -> str:
        """Drop the sentences of a summary that cite an unsourced CVE.

        Findings are discrete claims, so an unsupported one is removed whole.
        A summary is a paragraph, and deleting all of it over a single
        identifier throws away sound analysis -- which is why this used to
        warn and leave the text alone. But "warn and leave" still put the
        fabrication in the document, where it reads as reported fact.

        Sentence granularity is the middle ground: the invented claim goes,
        the surrounding analysis stays, and a marker records that something
        was removed so the gap is visible rather than silent.
        """
        if not summary.strip():
            return summary

        # Split on sentence-ending punctuation followed by whitespace, keeping
        # the punctuation with its sentence.
        sentences = re.split(r"(?<=[.!?])\s+", summary)
        kept, dropped = [], []
        for sentence in sentences:
            unsupported = sorted({c.upper() for c in _CVE_RE.findall(sentence)} - corpus_cves)
            if unsupported:
                dropped.extend(unsupported)
                continue
            kept.append(sentence)

        if not dropped:
            return summary

        logger.warning(
            "Redacted %d sentence(s) from the %s summary citing unsupported %s.",
            len(sentences) - len(kept),
            skill_name,
            ", ".join(sorted(set(dropped))),
        )
        marker = "[A sentence citing an unsourced CVE was removed from this summary.]"
        # Everything was a fabrication -- say so rather than return an empty
        # summary that reads as "the model had nothing to say".
        return " ".join(kept + [marker]) if kept else marker

    def _extract_data_sources(
        self,
        telemetry: ResearchSkillOutput,
        environment_data: str = "",
    ) -> Dict[str, bool]:
        """Availability comes from the configured estate, not the model's needs.

        Missing environment information leaves availability unconfirmed (false).
        The research prose can still describe which sources the hunt requires.
        """
        env_text = (environment_data or "").lower()
        if env_text and "not found" not in env_text[:60]:
            # Only what a configured telemetry section documents: the template's
            # EDR section lists registry modifications under a product that is
            # still "[To be configured]", which documents nothing.
            return documented_data_sources(environment_data)

        logger.warning(
            "No environment profile available; falling back to what the telemetry "
            "mapping discusses, which describes the hunt's needs rather than the "
            "estate's coverage."
        )
        if _llm_call_failed(telemetry.key_findings):
            # Both signals are gone. Claiming availability here would be
            # fabricating from a failure.
            return dict.fromkeys(_DATA_SOURCE_KEYWORDS, False)

        # Required telemetry is not evidence that the estate collects it.
        return dict.fromkeys(_DATA_SOURCE_KEYWORDS, False)

    def _estimate_complexity(
        self,
        tradecraft: ResearchSkillOutput,
        telemetry: ResearchSkillOutput,
    ) -> str:
        """Estimate hunt complexity based on research."""
        total_findings = len(tradecraft.key_findings) + len(telemetry.key_findings)

        if total_findings <= 4:
            return "low"
        elif total_findings <= 8:
            return "medium"
        else:
            return "high"

    def _extract_gaps(
        self,
        synthesis: ResearchSkillOutput,
    ) -> List[str]:
        """Extract identified gaps from synthesis's key_findings. See
        _extract_hypothesis for why this matches phrasing variations
        (optional bold markers, "Knowledge Gap:", "Coverage Gap:") rather
        than only an exact "gap:" prefix."""
        gaps = []
        for finding in synthesis.key_findings:
            match = _GAP_PREFIX_RE.match(finding)
            if match:
                extracted = finding[match.end() :].strip()
                if extracted:
                    gaps.append(extracted)
        return gaps
