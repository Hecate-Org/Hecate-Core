"""Hypothesis generator agent - LLM-powered hypothesis generation."""

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hecate_agent.agents.base import AgentResult, LLMAgent
from hecate_agent.core.hunting_knowledge import EVIDENCE_RULES, load_stage_guidance
from hecate_agent.core.telemetry_examples import render_examples

logger = logging.getLogger(__name__)


@dataclass
class ResearchContext:
    """Structured research context for hypothesis generation."""

    research_id: str
    topic: str
    mitre_techniques: List[str]
    recommended_hypothesis: Optional[str]
    gaps_identified: List[str]
    data_source_availability: Dict[str, bool]
    estimated_hunt_complexity: str
    adversary_tradecraft_findings: List[str]
    telemetry_mapping_findings: List[str]
    system_research_summary: str
    adversary_tradecraft_summary: str
    telemetry_mapping_summary: str
    threat_actors: List[str] = field(default_factory=list)


@dataclass
class HypothesisGenerationInput:
    """Input for hypothesis generation."""

    threat_intel: str  # User-provided threat context
    past_hunts: List[Dict[str, Any]]  # Similar past hunts for context
    environment: Dict[str, Any]  # Data sources, platforms, etc.
    research: Optional[ResearchContext] = None
    # True when `threat_intel` is a bare indicator list (a ThreatFox/Maltrail
    # style feed dump: domains, IPs, URLs, hashes) with no prose describing
    # how any of it was used. Such a source is genuine threat intel -- unlike
    # the marketing case `is_threat_report` covers -- but it evidences no
    # delivery mechanism, actor, malware family or technique, so the prompt
    # has to stop the model supplying those from background knowledge.
    # Set by the caller, which knows its own source formats; defaults False
    # so callers passing free prose are unaffected.
    intel_is_indicator_only: bool = False
    workspace: Optional[Path] = None


@dataclass
class HypothesisGenerationOutput:
    """Output from hypothesis generation."""

    hypothesis: str
    justification: str
    mitre_techniques: List[str]
    data_sources: List[str]
    expected_observables: List[str]
    known_false_positives: List[str]
    time_range_suggestion: str
    # ABLE scoping (see templates/HUNT_LOCK.md) -- defaulted to "" rather
    # than required so a model that omits one of these four (unlike the
    # longer-established fields above, which every provider we've tested
    # against reliably returns) degrades to an empty field a human fills
    # in, not a TypeError that discards an otherwise-good hypothesis and
    # forces the low-quality template fallback for the whole response.
    actor: str = ""
    behavior: str = ""
    location: str = ""
    evidence: str = ""
    # Self-assessed grounding: does the threat intel actually describe
    # observed/reported adversary behavior, or is it vendor/product
    # marketing, compliance news, or other non-incident content the model
    # still produced a plausible-sounding hypothesis and "Adversary
    # Tradecraft"-shaped narrative for anyway? Defaults to True (assume
    # legitimate) so a model that doesn't support this field -- or omits it
    # -- doesn't retroactively flag every prior hunt as low-confidence.
    is_threat_report: bool = True
    low_confidence_reason: str = ""
    # Self-assessed backstop for the indicator-only case, mirroring
    # is_threat_report above. `HypothesisGenerationInput` has a caller-set
    # flag for this, but only a caller that knows its own source formats can
    # set it -- a direct CLI or MCP caller passing a raw feed dump gets no
    # such protection, so the model is asked to recognise the case itself.
    # Defaults False (assume real narrative) so a model that omits the field
    # keeps the normal behavior-hypothesis path.
    is_indicator_only: bool = False
    indicator_records: List[Dict[str, Any]] = field(default_factory=list)
    # Quality rubric & baseline anchors (Unified Threat Hunting)
    expected_malicious: str = ""
    expected_benign: str = ""
    falsification_criteria: str = ""
    rubric_score: Dict[str, Any] = field(default_factory=dict)
    # Model-provided claim-to-source references. Callers must verify that each
    # quote exists in the source text before presenting it as provenance.
    evidence_citations: List[Dict[str, str]] = field(default_factory=list)


def _is_substantive(val: Any) -> bool:
    """Return True if val is substantive, not empty, placeholder, or schema template echo."""
    if not val:
        return False
    if isinstance(val, str):
        t = val.strip().lower()
        if not t or t in ("none", "n/a", "tbd", "unknown", "[tbd]", "[none]", "null", "[review cti and populate]"):
            return False
        if t.startswith("<") and t.endswith(">"):
            return False
        if t.startswith("[") and t.endswith("]"):
            return False
        if t.startswith("string ("):
            return False
        return len(t) >= 3
    if isinstance(val, (list, tuple, set)):
        return any(_is_substantive(item) for item in val)
    return True


def score_hypothesis_rubric(output: HypothesisGenerationOutput) -> Dict[str, Any]:
    """Score hypothesis quality according to the 5-dimension rubric.

    Dimensions scored 1-3: Specificity, Testability, Falsifiability, Relevance, Pyramid Level.
    Threshold: >= 10 total with no dimension scoring 1 yields 'GO'.
    """
    has_behavior = _is_substantive(output.behavior)
    has_evidence = _is_substantive(output.evidence)
    has_observables = _is_substantive(output.expected_observables)
    has_data_sources = _is_substantive(output.data_sources)
    has_falsification = _is_substantive(output.falsification_criteria)
    has_benign = _is_substantive(output.expected_benign)
    has_malicious = _is_substantive(output.expected_malicious)
    has_false_positives = _is_substantive(output.known_false_positives)
    has_techniques = _is_substantive(output.mitre_techniques)
    has_justification = _is_substantive(output.justification)

    # 1. Specificity:
    spec = 1
    if has_behavior and (has_evidence or has_observables):
        spec = 3
    elif has_behavior or has_techniques:
        spec = 2

    # 2. Testability:
    test = 1
    if has_data_sources and (has_observables or has_evidence):
        test = 3
    elif has_data_sources or has_observables:
        test = 2

    # 3. Falsifiability:
    fals = 1
    if has_falsification or (has_benign and has_malicious):
        fals = 3
    elif has_false_positives or has_benign:
        fals = 2

    # 4. Relevance:
    rel = 1
    if output.is_threat_report and (has_techniques or has_justification):
        rel = 3
    elif output.is_threat_report:
        rel = 2

    # 5. Pyramid Level:
    pyr = 3 if has_techniques else (1 if output.is_indicator_only else 2)

    total = spec + test + fals + rel + pyr
    scores: Dict[str, Any] = {
        "specificity": spec,
        "testability": test,
        "falsifiability": fals,
        "relevance": rel,
        "pyramid_level": pyr,
        "total": total,
    }

    if total >= 10 and min(spec, test, fals, rel, pyr) > 1:
        verdict = "GO"
    elif total <= 6:
        verdict = "NO-GO"
    else:
        verdict = "CONDITIONAL"

    scores["verdict"] = verdict
    return scores


def _bullet_block(heading: str, items: List[str]) -> List[str]:
    """A heading followed by indented bullets, or nothing when there are none.

    The empty case is why this is a function: repeating the "only emit the
    heading if the list is non-empty" guard at each call site is what pushed
    _build_research_section over the complexity limit, and every repetition
    was the same three lines.
    """
    if not items:
        return []
    return [heading] + ["  - {}".format(item) for item in items]


#: Character budget for the tradecraft excerpt. Sections 1, 2 and 5 total
#: ~63 KB, which would crowd the CTI out of a local model's context; this
#: keeps the framing without drowning the intel the hunt is actually about.
_HUNTING_KNOWLEDGE_BUDGET = 4000


class HypothesisGeneratorAgent(LLMAgent[HypothesisGenerationInput, HypothesisGenerationOutput]):
    """Generates hunt hypotheses using an LLM provider.

    Uses the provider-agnostic LLM abstraction for context-aware hypothesis
    generation with fallback to template-based generation when LLM is disabled.

    Features:
    - TTP-focused hypothesis generation
    - MITRE ATT&CK technique mapping
    - Data source validation
    - False positive prediction
    - Cost tracking (via provider layer)
    """

    def execute(self, input_data: HypothesisGenerationInput) -> AgentResult[HypothesisGenerationOutput]:
        """Generate hypothesis using LLM.

        Measures wall-clock time for the entire execution (including retries,
        prompt building, and JSON parsing) and includes it in metadata as
        ``duration_ms``.

        Args:
            input_data: Hypothesis generation input

        Returns:
            AgentResult with hypothesis output or error
        """
        start = time.monotonic()
        self._reset_llm_usage()

        if not self.llm_enabled:
            result = self._template_generate(input_data)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            result.metadata["duration_ms"] = elapsed_ms
            result.metadata.update(self._llm_usage_metadata())
            return result

        try:
            prompt = self._build_prompt(input_data)

            def validate_json(text: str) -> Optional[str]:
                try:
                    self._parse_json_response(text)
                    return None
                except ValueError as e:
                    return str(e)

            # Low temperature because step 1 of this prompt is a
            # classification, not prose: "is this actually a threat report?"
            # has one right answer for a given source, but sampled at the
            # creative default it varied run to run on identical input --
            # measured 0/5 correct on a defensive-engineering blog post
            # before the step-1 wording was sharpened, and still only 2/5
            # after, purely from sampling. The hypothesis text itself is
            # better for being less inventive here too.
            output_text = self._call_llm_with_retry(
                prompt,
                validate_json,
                max_retries=2,
                temperature=0.2,
                capability="hypothesis",
            )
            output_data = self._parse_json_response(output_text)
            # A caller that set the flag knows its own source formats; its
            # statement of fact outranks the model's self-assessment, which
            # exists only for callers that can't say (see the field's note).
            if input_data.intel_is_indicator_only:
                output_data["is_indicator_only"] = True
            output = HypothesisGenerationOutput(**output_data)

            # Validate technique IDs against the real ATT&CK matrix and extracted evidence
            output, warnings = self._apply_technique_validation(output, input_data)
            output.rubric_score = score_hypothesis_rubric(output)

            provider = self._get_provider()
            model_name = getattr(
                provider,
                "model",
                getattr(provider, "model_id", "unknown"),
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)
            metadata = {
                "llm_provider": provider.provider_name,
                "llm_model": model_name,
                "duration_ms": elapsed_ms,
                **self._llm_usage_metadata(),
            }

            return AgentResult(
                success=True,
                data=output,
                error=None,
                warnings=warnings,
                metadata=metadata,
            )

        except Exception as e:
            result = self._template_generate(input_data, error=str(e))
            elapsed_ms = int((time.monotonic() - start) * 1000)
            result.metadata["duration_ms"] = elapsed_ms
            result.metadata.update(self._llm_usage_metadata())
            return result

    def _technique_grounding(self, techniques: List[str]) -> str:
        """Inject real ATT&CK names and descriptions for a list of technique IDs.

        Prevents the model from recalling technique identity from memory, which
        has a ~30% error rate on smaller models (measured via eval harness).
        Returns an empty string if STIX data is unavailable or no IDs given.
        """
        if not techniques:
            return ""
        lines = []
        try:
            from hecate_agent.core.attack_matrix import get_technique

            for tid in techniques:
                info = get_technique(tid)
                if info:
                    name = info.get("name", tid)
                    desc = (info.get("description") or "").strip()[:300]
                    lines.append('  {}: "{}" — {}'.format(tid, name, desc))
        except Exception:
            return ""
        if not lines:
            return ""
        return "**ATT&CK Ground Truth (use these exact names):**\n" + "\n".join(lines) + "\n\n"

    def _extract_techniques_from_text(self, text: str) -> List[str]:
        """Extract T-code strings from free text."""
        return re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)

    def _apply_technique_validation(
        self, output: HypothesisGenerationOutput, input_data: HypothesisGenerationInput
    ) -> Tuple[HypothesisGenerationOutput, List[str]]:
        """Reconcile the model's ATT&CK IDs with the real matrix and evidence table.

        Returns the output (rebuilt with the corrected technique list when
        anything changed) and any warnings describing what changed.
        """
        warnings: List[str] = []

        # Research can propose leads, but only the source text can evidence a
        # technique for this specific item. Candidate mappings are generated
        # from that text and are subsequently checked again by the Runner.
        evidenced = set(self._extract_techniques_from_text(input_data.threat_intel))
        try:
            from hecate_agent.core.technique_candidates import named_techniques

            evidenced.update(tid for tid, _ in named_techniques(input_data.threat_intel))
        except Exception:
            pass
        if evidenced:
            filtered = []
            for tid in output.mitre_techniques:
                if tid in evidenced or tid.split(".")[0] in evidenced:
                    filtered.append(tid)
                else:
                    warnings.append(f"Removed '{tid}' because the primary threat-intel text does not support it.")
            output.mitre_techniques = filtered
        else:
            for tid in output.mitre_techniques:
                warnings.append(f"Removed '{tid}' because no source-grounded technique candidate was found.")
            output.mitre_techniques = []

        valid, remapped, invalid = self._validate_techniques(output.mitre_techniques)

        if remapped:
            warnings.append(
                "Remapped {} deprecated ATT&CK ID(s) to their current equivalent: {}".format(
                    len(remapped),
                    ", ".join("{} -> {}".format(old, new) for old, new in remapped),
                )
            )
        if invalid:
            warnings.append("Removed {} unrecognised ATT&CK ID(s): {}".format(len(invalid), ", ".join(invalid)))
        if not (remapped or invalid):
            return output, warnings

        # Rebuilt field-by-field rather than mutated: every field must be
        # carried forward explicitly, so a newly added one that's forgotten
        # here shows up as a test failure instead of silently reverting to
        # its default on any hypothesis that had a technique corrected.
        return (
            HypothesisGenerationOutput(
                hypothesis=output.hypothesis,
                justification=output.justification,
                mitre_techniques=valid,
                data_sources=output.data_sources,
                expected_observables=output.expected_observables,
                known_false_positives=output.known_false_positives,
                time_range_suggestion=output.time_range_suggestion,
                actor=output.actor,
                behavior=output.behavior,
                location=output.location,
                evidence=output.evidence,
                is_threat_report=output.is_threat_report,
                low_confidence_reason=output.low_confidence_reason,
                is_indicator_only=output.is_indicator_only,
                indicator_records=output.indicator_records,
                evidence_citations=output.evidence_citations,
                expected_malicious=output.expected_malicious,
                expected_benign=output.expected_benign,
                falsification_criteria=output.falsification_criteria,
                rubric_score=output.rubric_score,
            ),
            warnings,
        )

    def _validate_techniques(self, techniques: List[str]) -> Tuple[List[str], List[Tuple[str, str]], List[str]]:
        """Check each technique ID against the real ATT&CK matrix.

        Returns (valid_techniques, remapped, invalid_techniques), where
        `remapped` holds (old_id, new_id) pairs for IDs ATT&CK has revoked
        but still maps to a current replacement, and `valid_techniques`
        carries the replacements in place of the originals.

        Remapping matters because a revoked ID is not the same failure as a
        made-up one: a model trained on years of threat reporting routinely
        names a real behavior by its pre-restructure ID (T1093 for Process
        Hollowing, T1067 for Bootkit). Dropping those discarded a correct
        call and, when it emptied the list, left the hunt with no ATT&CK
        mapping at all. A genuinely fabricated ID (e.g. T1065.003, a
        sub-technique that never existed) has no successor and is still
        rejected here.

        Skips validation and passes through unchanged when STIX data is not
        installed (FallbackProvider has no technique data).
        """
        valid: List[str] = []
        remapped: List[Tuple[str, str]] = []
        invalid: List[str] = []
        try:
            from hecate_agent.core.attack_matrix import _get_provider, get_superseding_technique_id, get_technique

            provider = _get_provider()
            # FallbackProvider has no technique data — skip validation rather
            # than incorrectly flagging every ID as invalid.
            if not provider.is_stix():
                return techniques, [], []

            for tid in techniques:
                if get_technique(tid) is not None:
                    resolved = tid
                else:
                    successor = get_superseding_technique_id(tid)
                    if successor is None:
                        invalid.append(tid)
                        continue
                    remapped.append((tid, successor))
                    resolved = successor
                # A model that emitted both the old and new ID for the same
                # technique must not leave a duplicate behind after remapping.
                if resolved not in valid:
                    valid.append(resolved)
        except Exception:
            return techniques, [], []
        return valid, remapped, invalid

    def _build_prompt(self, input_data: HypothesisGenerationInput) -> str:
        """Build LLM prompt for hypothesis generation.

        Args:
            input_data: Hypothesis generation input

        Returns:
            Formatted prompt string
        """
        # Collect any T-codes mentioned in inputs and inject real ATT&CK context
        mentioned = self._extract_techniques_from_text(input_data.threat_intel)
        grounding = self._technique_grounding(list(dict.fromkeys(mentioned)))
        candidates = "" if input_data.intel_is_indicator_only else self._candidate_section(input_data)

        # Placed directly after the intel and before the step-1 assessment:
        # it's a fact about the input the model needs while reading it, not
        # a judgement it should try to make for itself.
        indicator_only_note = (
            (
                "**This source is an indicator list, not a narrative "
                "report.** It is a feed dump of indicators (domains, IPs, "
                "URLs, file hashes) with no prose describing how any of "
                "them was used. Feeds like this are genuine threat intel, "
                "so treat step 1 accordingly -- but they carry no evidence "
                "about delivery mechanism, actor identity, malware family, "
                "post-compromise activity, or any ATT&CK technique. Do not "
                "supply those from background knowledge: naming phishing "
                "as the delivery vector, or credential theft and lateral "
                "movement as follow-on activity, is fabrication when the "
                "source is a list of domains. Keep the hypothesis to what "
                "the data supports -- that these indicators appear in the "
                "environment's own telemetry -- and leave "
                '"mitre_techniques" empty unless the source names a '
                "technique explicitly. An empty technique list is the "
                "correct answer here, not a gap to fill.\n\n"
            )
            if input_data.intel_is_indicator_only
            # Backstop for callers that can't set the flag (direct CLI, MCP):
            # ask the model to recognise the case itself. Deliberately not
            # used when the caller *has* flagged it -- a definite statement
            # of fact beats asking the model to re-derive it.
            else (
                "**Before anything else, check what kind of source this "
                "is.** If the threat intel above is a bare indicator list -- "
                "a feed dump of domains, IPs, URLs or file hashes (ThreatFox, "
                "Maltrail and similar) with no prose describing how any of "
                "them was used -- then it evidences no delivery mechanism, "
                "actor identity, malware family, post-compromise activity or "
                'ATT&CK technique. In that case set "is_indicator_only" '
                "true in your JSON, write the hypothesis as indicator "
                'presence ("Indicators published in [source] appear in '
                '[telemetry] on [target]") rather than adversary behavior, '
                'and leave "mitre_techniques" empty -- naming phishing as '
                "the delivery vector, or credential theft and lateral "
                "movement as follow-on activity, is fabrication when the "
                "source is a list of domains. If the intel does contain real "
                "narrative, set it false and continue normally.\n\n"
            )
        )

        # The default template has a [behavior] slot the model is obliged to
        # fill. Against an indicator list there is no evidenced behavior to
        # put in it, so the template itself was driving the invention it is
        # asked above not to commit -- give it a shape that fits the source.
        hypothesis_format = (
            (
                '- Hypothesis: "Indicators published in [source] appear in '
                '[telemetry] on [target]" -- describe indicator presence, '
                "not adversary behavior you cannot evidence.\n"
            )
            if input_data.intel_is_indicator_only
            else '- Hypothesis: "Adversaries use [behavior] to [goal] on [target]"\n'
        )

        return (
            "You are a threat hunting expert.\n\n"
            "{grounding}"
            "**Threat Intel:**\n"
            "{threat_intel}\n\n"
            "**Evidence discipline (mandatory):** The Threat Intel block above is the only source of case-specific facts. "
            "Research Context, ATT&CK descriptions, prior hunts, and general malware knowledge are background leads, "
            "not evidence that this sample or campaign performed a behavior. Do not turn family-level behavior into "
            "sample-specific claims. Include a claim in the hypothesis, justification, actor, behavior, location, "
            "evidence, techniques, or observables only when the Threat Intel block contains a relevant passage. "
            "For each such claim, return an evidence_citations entry with its exact field name, a short excerpt "
            "copied verbatim from that output field, and a verbatim quote copied from Threat Intel. Never invent or "
            "paraphrase the quote. Leave the citation out when no supporting passage exists, and leave unknown actor, behavior, or "
            "platform fields empty rather than filling them from general knowledge.\n\n"
            "{indicator_only_note}"
            "{candidates}"
            "**Step 1 -- assess the threat intel above before doing "
            "anything else:** does it actually describe adversary behavior "
            "that was observed or reported -- an attack, campaign, TTP, or "
            "IOC -- or is it vendor/product marketing, a compliance "
            "announcement, a feature release, or other content that "
            "doesn't describe anything an adversary did? Do not let a "
            "well-written vendor blog post read as a genuine incident "
            "report just because it uses security-adjacent terminology -- "
            "if no adversary is described doing something, it isn't a "
            "threat report. For example: an announcement introducing a new "
            "product integration or feature that happens to mention "
            "credentials, MFA, or billing data only because that's what "
            "the product itself accesses -- not because any adversary was "
            "observed abusing them -- is marketing, not a threat report, "
            "even though every sentence in it could plausibly appear in "
            "one. The same applies to defensive engineering content: a "
            "post about how to instrument, audit, log, or hunt over "
            "some system describes what a *defender* does, and "
            "telemetry pipelines, detection queries and hunting "
            "guidance are its subject matter, not evidence that anyone "
            "attacked anything. Security-vendor research blogs publish "
            "both kinds, so the publisher is not the test -- an "
            "adversary doing something is. "
            "Decide this now, before drafting anything below, and "
            'record it as "is_threat_report" in your JSON response.\n\n'
            "**Step 2 -- generate the hunt hypothesis.** If step 1 "
            "concluded this is not a genuine threat report, still produce "
            "your best-effort hypothesis below (mark it as speculative in "
            "the justification, and give a one-sentence "
            '"low_confidence_reason" explaining what kind of content it '
            "actually is) -- but do not invent an adversary, a specific "
            "attack technique, or named tooling (e.g. a phishing-proxy "
            "kit, a named malware family) that the source material never "
            "mentioned, just to make the hypothesis sound concrete. A "
            "hypothesis honestly built on thin, non-adversarial source "
            "material is more useful than a fabricated one that reads as "
            "credible.\n\n"
            "**Past Similar Hunts:**\n"
            "{past_hunts}\n\n"
            "**Available Environment:**\n"
            "{environment}\n\n"
            "{hunting_knowledge}"
            "{research_section}"
            "{telemetry_examples}"
            "Generate a hypothesis following this format:\n"
            "{hypothesis_format}"
            "- Justification: Why hunting for this specific behavior matters. Do NOT write generic filler like 'This hypothesis is valuable because'. Tie the specific TTP directly to the threat actor's goals and the organization's risk, citing the intel.\n"
            "- MITRE Techniques: Only include real ATT&CK technique IDs you are certain exist. "
            "If 'Candidate ATT&CK techniques' are listed above, YOU MUST select your IDs from that list. "
            "Do NOT guess or infer techniques from memory unless the threat intel explicitly and undeniably describes them. "
            "MUST MATCH THE TARGET OS: Do not include Windows-only techniques (like T1207 Rogue Domain Controller or T1047 WMI) if the threat intel describes a Linux or macOS threat.\n"
            "- Data Sources: Which data sources to query. MUST MATCH THE TARGET OS: If the threat intel targets Linux or macOS, you MUST NOT list Windows-only data sources like `registry_events` or `wmi`.\n"
            "- Expected Observables: What we expect to find\n"
            "- Known False Positives: Specific, concrete IT or administrative activities that overlap with the targeted behavior. Do NOT write generic defaults like 'Legitimate network traffic' or 'Legitimate software updates'. Name the exact administrative tools, processes, or configurations that might trigger these observables.\n"
            "- Expected Malicious: What an anomalous or true-positive execution looks like in telemetry (specific anomalous pattern).\n"
            "- Expected Benign Baseline: What normal/legitimate administrative behavior looks like (authorized IT baseline to contrast against).\n"
            "- Falsification Criteria: What specific telemetry finding or absence of events would disprove/falsify this hypothesis.\n"
            "- Time Range: Suggested time window with justification\n\n"
            "Also provide ABLE scoping (Actor, Behavior, Location, Evidence) "
            "-- Hecate's standard hunt-scoping framework. Base every ABLE field "
            "strictly on the source text; research is context only and does not "
            "establish what happened in this specific case:\n"
            "- Actor: The threat actor, activity cluster, or malware family this hunt targets "
            "(e.g. named APT, campaign, or malware family identified in the CTI or linked research). "
            "If no specific threat actor is attributed, state 'Unattributed' or describe the threat cluster "
            "(e.g. 'Unattributed / Opportunistic Threat Actors' or 'Unattributed (threat actors exploiting <vulnerability/campaign>)'). "
            "Do NOT return an empty string or leave this blank.\n"
            "- Behavior: The specific TTP or behavior pattern to hunt for, "
            "more concrete/actionable than the hypothesis's own [behavior] "
            "clause.\n"
            "- Location: The systems, networks, or environments to hunt in. "
            "Name the platforms the environment above actually lists, and "
            "the ones the threat intel implicates -- do not default to "
            "Windows or to domain-joined endpoints unless one of those two "
            "sources says so. A Linux server compromise scoped to Windows "
            "endpoints finds nothing.\n"
            "- Evidence: The specific data sources and key fields a hunter "
            "would actually query to test this hypothesis. DO NOT suggest Windows registry keys for macOS/Linux hunts.\n"
            "- Indicator Records: A strictly structured list of observables (IPs, domains, hashes, URLs) extracted exactly as they appear in the intel. Do not extract file paths or registry keys here. Each record must be an object with 'value', 'type' (e.g., 'ipv4', 'domain', 'sha256', 'md5', 'url'), and 'role' (e.g., 'c2', 'delivery', 'unknown'). If none exist, return an empty array.\n\n"
            "**IMPORTANT:** Return your response as a JSON object matching "
            "this schema. The values below show the *shape* only -- anything "
            "in angle brackets is a placeholder, and copying it, or any "
            "example value from the instructions above, into your answer is "
            "an error:\n"
            "{{\n"
            '  "hypothesis": "string",\n'
            '  "justification": "string",\n'
            '  "mitre_techniques": ["T1234.001", "T5678.002"],\n'
            '  "data_sources": ["<data source from the environment above>"],\n'
            '  "expected_observables": '
            '["<a specific artifact from the intel: file name, command line, domain, registry path>"],\n'
            '  "known_false_positives": '
            '["<a named benign activity that produces the same artifact in this hunt>"],\n'
            '  "expected_malicious": "string (specific anomalous execution in logs)",\n'
            '  "expected_benign": "string (normal/authorized baseline behavior)",\n'
            '  "falsification_criteria": "string (what negative finding or absence falsifies this hypothesis)",\n'
            '  "time_range_suggestion": "7 days (justification)",\n'
            '  "actor": "string (threat actor, malware cluster, or \'Unattributed\')",\n'
            '  "behavior": "string",\n'
            '  "location": "string",\n'
            '  "evidence": "string",\n'
            '  "is_threat_report": true,\n'
            '  "low_confidence_reason": "string (only if is_threat_report is false)",\n'
            '  "is_indicator_only": false,\n'
            '  "indicator_records": [\n'
            '    {{"value": "198.51.100.45", "type": "ipv4", "role": "c2"}}\n'
            "  ],\n"
            '  "evidence_citations": [\n'
            '    {{"field": "behavior", "claim": "exact excerpt from the Behavior field", '
            '"quote": "verbatim supporting passage from Threat Intel"}}\n'
            "  ]\n"
            "}}\n"
        ).format(
            grounding=grounding,
            threat_intel=input_data.threat_intel,
            indicator_only_note=indicator_only_note,
            candidates=candidates,
            hypothesis_format=hypothesis_format,
            past_hunts=json.dumps(input_data.past_hunts, indent=2),
            environment=json.dumps(input_data.environment, indent=2),
            research_section=self._build_research_section(input_data.research),
            # A3: where the internals this intel names really appear in logs, so
            # observables name an event and field, not a syscall as a file name.
            telemetry_examples=render_examples(input_data.threat_intel),
            hunting_knowledge=self._build_hunting_knowledge_section(input_data.workspace),
        )

    @staticmethod
    def _build_hunting_knowledge_section(workspace: Optional[Path] = None) -> str:
        """Compact workspace rules without copyable reference hypotheses."""
        body = load_stage_guidance("hypothesis", _HUNTING_KNOWLEDGE_BUDGET, workspace=workspace)
        return f"**Hunting Tradecraft:**\n{EVIDENCE_RULES}\n{body}\n\n"

    def _candidate_section(self, input_data: HypothesisGenerationInput) -> str:
        """Technique candidates found in the primary threat-intel text."""
        from hecate_agent.core.technique_candidates import candidate_techniques, format_candidates

        candidates = candidate_techniques(input_data.threat_intel, limit=16)
        # Logged so a reviewer can tell "the model was never shown the right
        # technique" from "it was shown it and chose something else".
        logger.info(
            "Candidate ATT&CK techniques offered to the model: %s",
            ", ".join(f"{tid} {name}" for tid, name in candidates) or "none matched the intel's wording",
        )
        block = format_candidates(candidates)
        if not block:
            return ""
        return (
            "**Candidate ATT&CK techniques** -- matched on the source's own "
            "wording, not guessed. YOU MUST choose from these exact IDs. "
            "Add another ID ONLY if the intel plainly and undeniably describes it:\n" + block + "\n\n"
        )

    def _build_research_section(self, research: Optional[ResearchContext]) -> str:
        """Build the research context section for the prompt.

        Args:
            research: Optional research context

        Returns:
            Formatted research section string, or empty string if no research
        """
        if research is None:
            return ""

        lines = [
            "**Research Context:**",
            "- Context only: these generated findings are not evidence for this specific case "
            "unless the same fact appears in Threat Intel.",
            "- Research ID: {}".format(research.research_id),
            "- Topic: {}".format(research.topic),
            "- Techniques: {}".format(", ".join(research.mitre_techniques)),
        ]
        if getattr(research, "threat_actors", None):
            lines.append("- Threat Actors: {}".format(", ".join(research.threat_actors)))

        lines.extend(
            [
                "",
                "Adversary Tradecraft: {}".format(research.adversary_tradecraft_summary),
            ]
        )

        lines.extend(_bullet_block("Key findings:", research.adversary_tradecraft_findings))

        lines.append("")
        lines.append("Telemetry Mapping: {}".format(research.telemetry_mapping_summary))
        lines.extend(_bullet_block("Key fields:", research.telemetry_mapping_findings))

        if research.data_source_availability:
            lines.append("")
            lines.extend(
                _bullet_block(
                    "Data Source Availability:",
                    [
                        "{}: {}".format(source, "Available" if available else "Unavailable")
                        for source, available in research.data_source_availability.items()
                    ],
                )
            )

        if research.gaps_identified:
            lines.append("")
            lines.extend(_bullet_block("Gaps Identified:", research.gaps_identified))

        if research.recommended_hypothesis:
            lines.append("")
            lines.append("Recommended Hypothesis from Research: {}".format(research.recommended_hypothesis))

        lines.append("")
        return "\n".join(lines) + "\n"

    def _template_generate(
        self,
        input_data: HypothesisGenerationInput,
        error: Optional[str] = None,
    ) -> AgentResult[HypothesisGenerationOutput]:
        """Fallback template-based generation (no LLM).

        Args:
            input_data: Hypothesis generation input
            error: Optional error message from LLM attempt

        Returns:
            AgentResult with template-generated hypothesis
        """
        # Use research recommended hypothesis if available
        if input_data.research and input_data.research.recommended_hypothesis:
            hypothesis = input_data.research.recommended_hypothesis
            mitre_techniques = list(input_data.research.mitre_techniques)
        else:
            hypothesis = "Investigate suspicious activity related to: {}".format(input_data.threat_intel[:100])
            mitre_techniques = []

        output = HypothesisGenerationOutput(
            hypothesis=hypothesis,
            justification=("Template-generated hypothesis (LLM disabled or failed)"),
            mitre_techniques=mitre_techniques,
            data_sources=["EDR telemetry", "SIEM logs"],
            expected_observables=[
                "Process execution",
                "Network connections",
            ],
            known_false_positives=[
                "Legitimate software updates",
                "Administrative tools",
            ],
            time_range_suggestion="7 days (standard baseline)",
            expected_malicious="Unscheduled execution of target process or script from non-standard directory",
            expected_benign="Standard system administration scripts and approved deployment tools",
            falsification_criteria="Absence of target behavior in telemetry over the 7-day lookback window",
        )
        output.rubric_score = score_hypothesis_rubric(output)

        warnings = ["LLM disabled - using template generation"]
        if error:
            warnings.append("LLM error: {}".format(error))

        return AgentResult(
            success=True,
            data=output,
            error=None,
            warnings=warnings,
            metadata={"fallback": True},
        )
