"""Sigma rule generator agent - drafts portable detection logic for a hunt.

Emits Sigma because the hunt program has no committed query platform yet: a
Sigma rule converts to Splunk, Elastic, CrowdStrike or Defender later via
pySigma, so drafting here commits to nothing. Rules are *proposals for an
operator to review*, never anything executed -- generation deliberately sits
before human review in the hunt lifecycle, not after it.

Two design choices are worth stating, because both are load-bearing:

**The model never writes YAML.** It returns JSON, and this module serialises
the YAML itself. A model asked for YAML directly produces plausible-looking
text that fails to parse (or, worse, parses into the wrong shape) often
enough to matter, and a malformed rule is indistinguishable from a real one
until someone tries to convert it. Generating structure and rendering it
deterministically makes malformed output impossible by construction.

**Applicable log sources are derived, not asked for.** Which telemetry a hunt
needs follows from its ATT&CK techniques and the indicator types the CTI
actually carried -- both facts already in hand. Asking the model to nominate
them invites it to reach for whatever it writes about most, which is how a
hunt against a backdoor with nine C2 URLs ends up scoped to process
telemetry alone.
"""

import json
import logging
import re
import time
import uuid
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

import yaml

from hecate_agent.agents.base import AgentResult, LLMAgent
from hecate_agent.agents.llm.rule_reviewer import RuleReview, RuleReviewer, review_prompt
from hecate_agent.core.sigma_semantics import base_field, blocks, repair_sigma_semantics, semantic_problem

from hecate_agent.agents.llm.sigma.logsources import (
    APPLIANCE_PLATFORMS as APPLIANCE_PLATFORMS,
    HOST_SENSOR_LOGSOURCES,
    VALID_LEVELS,
    VALID_LOGSOURCE_CATEGORIES,
    _AGGREGATION_RE,
    _DOMAIN_RE as _DOMAIN_RE,
    _HASH_TYPES as _HASH_TYPES,
    _HEX_RE as _HEX_RE,
    _INDICATOR_LOGSOURCES as _INDICATOR_LOGSOURCES,
    _IP_TYPES as _IP_TYPES,
    _LOGSOURCE_FIELDS,
    _NAME_TYPES as _NAME_TYPES,
    _PLATFORM_ONLY_LOGSOURCES as _PLATFORM_ONLY_LOGSOURCES,
    _TECHNIQUE_LOGSOURCES,
    _URL_HOST_RE as _URL_HOST_RE,
    _URL_TYPES as _URL_TYPES,
    applicable_logsources,
    appliance_only,
    _classify_network_value as _classify_network_value,
    _global_ip as _global_ip,
    hash_selectors,
    network_selectors,
    _platform_consistent_logsources,
)
from hecate_agent.agents.llm.sigma.models import (
    SigmaGenerationInput,
    SigmaGenerationOutput,
    SigmaRule,
    _SHARED_SYSTEM_FILE_RE,
    _behaviour_techniques,
    rule_filenames as rule_filenames,
)
from hecate_agent.agents.llm.sigma.validators import (
    _BROWSER_DELIVERY_TERMS as _BROWSER_DELIVERY_TERMS,
    _BROWSER_PARENTS as _BROWSER_PARENTS,
    _DOCUMENTATION_NETS as _DOCUMENTATION_NETS,
    _EXTENSION_ONLY_RE as _EXTENSION_ONLY_RE,
    _FILENAME_FIELDS as _FILENAME_FIELDS,
    _FLAT_OR_RE as _FLAT_OR_RE,
    _FULL_IPV4_RE as _FULL_IPV4_RE,
    _FULL_PATH_FIELDS as _FULL_PATH_FIELDS,
    _GENERIC_DESCRIPTOR_WORDS as _GENERIC_DESCRIPTOR_WORDS,
    _HOST_FIELDS as _HOST_FIELDS,
    _IP_FIELDS as _IP_FIELDS,
    _LIBRARY_SUFFIXES as _LIBRARY_SUFFIXES,
    _MODIFIER_IN_VALUE_RE as _MODIFIER_IN_VALUE_RE,
    _PLACEHOLDER_EXACT as _PLACEHOLDER_EXACT,
    _PLACEHOLDER_FILE_RE as _PLACEHOLDER_FILE_RE,
    _PLACEHOLDER_SUBSTRINGS as _PLACEHOLDER_SUBSTRINGS,
    _PORT_FIELDS as _PORT_FIELDS,
    _PROCESS_IMAGE_FIELDS as _PROCESS_IMAGE_FIELDS,
    _PYSIGMA_WARNED as _PYSIGMA_WARNED,
    _SCALAR_EVENT_FIELDS as _SCALAR_EVENT_FIELDS,
    _SCRIPT_SUFFIXES as _SCRIPT_SUFFIXES,
    _SECOND_LEVEL_SUFFIXES as _SECOND_LEVEL_SUFFIXES,
    _SIGNATURE_FIELDS as _SIGNATURE_FIELDS,
    _SNAKE_PLACEHOLDER_RE as _SNAKE_PLACEHOLDER_RE,
    _SWITCH_RE as _SWITCH_RE,
    _UNTRUSTED_SIGNATURE_VALUES as _UNTRUSTED_SIGNATURE_VALUES,
    _URL_FIELDS as _URL_FIELDS,
    _anchor_bare_filenames,
    _blocks_of as _blocks_of,
    _breadth_problem,
    _complete_indicator_lists,
    _detection_values as _detection_values,
    _documentation_address as _documentation_address,
    _excluded_threat_problem,
    _field_type_problem,
    _hash_role_problem,
    _impossible_ipv4 as _impossible_ipv4,
    _impossible_modifier_problem,
    _invented_domain_problem,
    _invented_hash_problem,
    _invented_ip_problem,
    _is_snake_placeholder as _is_snake_placeholder,
    _library_as_process_problem,
    _literal_problem,
    _looks_like_address as _looks_like_address,
    _modifier_in_value_problem,
    _negated_blocks as _negated_blocks,
    _network_role_problem,
    _network_selections,
    _nonspecific as _nonspecific,
    _or_branch_breadth_problem,
    _partial_indicator_problem,
    _placeholder_problem,
    _platform_legit_filters,
    _pysigma_problem,
    _registered_name as _registered_name,
    _remediate_platform_contradiction,
    _reversed_guidance_chain_problem,
    _select_for_logsource,
    _self_defeating_filter_problem,
    _strip_empty_filters,
    rule_provenance,
)

logger = logging.getLogger(__name__)


def _value_tokens(rule_yaml: str) -> set:
    """Program and path basenames a rule's positive selections match, e.g. ``{"node-red", "sh"}``."""
    try:
        detection = (yaml.safe_load(rule_yaml) or {}).get("detection") or {}
    except yaml.YAMLError:
        return set()
    condition = str(detection.get("condition", "")).lower()
    tokens = set()
    for name, block in detection.items():
        if name == "condition" or re.search(rf"\bnot\s+{re.escape(str(name).lower())}\b", condition):
            continue
        for item in block if isinstance(block, list) else [block]:
            if not isinstance(item, dict):
                continue
            for raw in item.values():
                for value in raw if isinstance(raw, list) else [raw]:
                    for word in str(value).split():
                        token = word.replace("\\", "/").rsplit("/", 1)[-1].strip("*'\"").lower()
                        if len(token) >= 2 and not token.startswith("-"):
                            tokens.add(token)
    return tokens


_AUTH_CLAIM_RE = re.compile(
    r"(?i)\bunauthenticated\b|\bwithout (?:auth\w*|credentials)\b|\bno (?:auth\w*|credentials)\b|\bmissing auth\w*"
)
#: Fields that can show whether a request or session was authenticated.
_AUTH_FIELD_RE = re.compile(r"(?i)auth|username|^user$|token|cookie|session|logon|credential|^sc-status$")


def _unobservable_auth_claim_problem(detection: Dict[str, Any], description: str) -> Optional[str]:
    """A rule titled "unauthenticated" whose fields cannot tell authenticated from not.

    H-0026's "Unauthenticated Node-RED Flow Deployment" matched only POST and
    /flows, which every legitimate deploy sends too.
    """
    if not _AUTH_CLAIM_RE.search(description):
        return None
    fields = {base_field(key) for _, block in blocks(detection) for key in block}
    if any(_AUTH_FIELD_RE.search(f) for f in fields):
        return None
    return (
        "the title or description says the activity is unauthenticated, but no field in the rule records "
        f"authentication ({', '.join(sorted(fields)) or 'none'}); describe what the fields show, or add one that "
        "records the credential or user"
    )


def _outbound_to_target_port_problem(
    detection: Dict[str, Any], category: str, artifacts: List[Dict[str, Any]]
) -> Optional[str]:
    """An outbound connection to the port the target service listens on.

    H-0026 matched ``Initiated: true`` to port 1880 from Node-RED: the attack is a
    connection *to* Node-RED on 1880, which its host records as inbound.
    """
    if category != "network_connection":
        return None
    target_ports = {
        str(a.get("value", "")).strip()
        for a in artifacts
        if a.get("kind") == "port" and str(a.get("role", "")).endswith("target")
    }
    if not target_ports:
        return None
    for _, block in blocks(detection):
        initiated = [str(v).lower() for k, v in block.items() if base_field(k) == "Initiated"]
        ports = {
            str(v)
            for k, raw in block.items()
            if base_field(k) == "DestinationPort"
            for v in (raw if isinstance(raw, list) else [raw])
        }
        if "true" in initiated and ports & target_ports and any(base_field(k) == "Image" for k in block):
            port = sorted(ports & target_ports)[0]
            return (
                f"the source has the target listening on port {port}, but the rule matches an outbound connection "
                f"(Initiated: true) to it from a local process; on the target the attack is an inbound connection "
                f"(Initiated: false, DestinationPort: {port})"
            )
    return None


def _drop_model_rules_covered_by_guidance(rules: List[SigmaRule]) -> Tuple[List[SigmaRule], List[str]]:
    """Drop a model rule for the same match a source-guidance rule or hunting lead already makes.

    H-0025 shipped the source's own "Node launching sh" rule beside a model rule
    for the same behaviour that matched the wrong process, and H-0026 the README's
    low-severity `POST /flows` lead beside a model copy at high severity.
    """
    guidance = [
        (r.logsource_category, _value_tokens(r.rule_yaml))
        for r in rules
        if r.origin == "deterministic" and r.title.startswith(("Source guidance ", "Hunting lead: "))
    ]
    kept: List[SigmaRule] = []
    dropped: List[str] = []
    for rule in rules:
        if rule.origin == "model":
            tokens = _value_tokens(rule.rule_yaml)
            if any(cat == rule.logsource_category and len(tokens & g) >= 2 for cat, g in guidance):
                dropped.append(
                    f"{rule.logsource_category}: {rule.title}: duplicates a rule built from the source's own "
                    "detection guidance"
                )
                continue
        kept.append(rule)
    return kept, dropped


class SigmaGeneratorAgent(LLMAgent[SigmaGenerationInput, SigmaGenerationOutput]):
    """Drafts Sigma rules covering each log source a hunt applies to."""

    def execute(self, input_data: SigmaGenerationInput) -> AgentResult[SigmaGenerationOutput]:
        start = time.monotonic()
        self._reset_llm_usage()
        platforms = list(input_data.platforms)
        from hecate_agent.core.command_rules import LINUX_MARKERS

        if not platforms and LINUX_MARKERS.search(input_data.threat_intel or ""):
            platforms.append("linux")

        logsources = input_data.logsources or applicable_logsources(
            input_data.techniques,
            list(input_data.indicators.keys()),
        )
        logsources = _platform_consistent_logsources(logsources, platforms)

        if not self.llm_enabled:
            return AgentResult(
                success=False,
                data=SigmaGenerationOutput(logsources_considered=logsources),
                error="Sigma generation requires an LLM; no provider is configured.",
                warnings=[],
                metadata={
                    "duration_ms": int((time.monotonic() - start) * 1000),
                    **self._llm_usage_metadata(),
                },
            )

        rules: List[SigmaRule] = []
        rejected: List[str] = []
        warnings: List[str] = []
        from hecate_agent.core.provenance import NETWORK_TYPES, IndicatorRecord, placements, scoped_placements

        for record, where in scoped_placements([IndicatorRecord.from_dict(r) for r in input_data.indicator_records]):
            if where:
                continue
            if record.type in NETWORK_TYPES and record.role == "unknown" and record.source != "cti":
                reason = "the primary source does not establish a current infrastructure role"
            elif placements(record):
                reason = "excluded by historical or target domain scope"
            else:
                reason = f"role={record.role}, status={record.status} has no supported telemetry placement"
            warnings.append(f"indicator deferred: {record.value}: {reason} (source: {record.source})")

        # One call per log source rather than one call for all of them. The
        # combined prompt asked for six rules in a single response, which on a
        # 4096-token context is close enough to the ceiling that a truncated
        # reply loses every rule at once -- the first live run produced six
        # rules of which none survived validation. Per-source, each response is
        # short, a failure costs one rule instead of all six, and the field
        # guidance can be narrowed to the category actually being written.
        from concurrent.futures import ThreadPoolExecutor

        omitted: List[str] = []
        # Each worker owns its cache; merge only after it finishes. Reviews live
        # for this execution and are keyed by the complete reviewer prompt.
        completed_reviews: Dict[str, RuleReview] = {}
        jobs: List[Tuple[str, Dict[str, RuleReview]]] = [(source, {}) for source in logsources]

        with ThreadPoolExecutor(max_workers=min(len(logsources) or 1, 6)) as executor:
            futures = {
                executor.submit(self._generate_for_logsource, input_data, logsource, cache): (logsource, cache)
                for logsource, cache in jobs
            }
            for future in futures:
                source_name, cache = futures[future]
                rule, rule_problems, rule_omitted = future.result()
                completed_reviews.update(cache)
                rejected.extend(rule_problems)
                omitted.extend(rule_omitted)
                if rule is not None:
                    rules.append(rule)
                elif rule_problems:
                    warnings.append(f"rejected rule: {source_name}: {'; '.join(rule_problems)}")

        # Built from the indicators alone, with no model call. On the first
        # live cycle with the fixed pipeline, a pulse carrying ten file hashes
        # produced no rule that used any of them: the model's file_event rule
        # matched only '.ps1' and was rejected, and its process rule was
        # behavioural. Exact hashes are the one thing a rule can be written
        # from without judgement, so they no longer depend on the model.
        # The same now holds for domains and addresses: both DNS rules in the
        # 25 Sep review were rejected (the model matched '.com' and '.xyz'),
        # leaving hunts with supplied C2 domains no DNS coverage at all.
        for ioc_rule, ioc_problem in [
            *self._written_file_rules(input_data),
            *self._command_rules(input_data),
            *self._guidance_rules(input_data),
            *self._ioc_rules(input_data),
            *self._cloud_control_plane_rules(input_data),
        ]:
            if ioc_rule is not None:
                rules.append(ioc_rule)
            elif ioc_problem:
                rejected.append(ioc_problem)

        rules, duplicates = _drop_model_rules_covered_by_guidance(rules)
        rejected.extend(duplicates)

        review_gaps: List[Dict[str, str]] = []
        if input_data.review_rules and rules:
            rules, review_rejected, review_gaps, review_warnings = self._review_rules(rules, input_data, completed_reviews)
            rejected.extend(review_rejected)
            warnings.extend(review_warnings)

        if not rules:
            all_reasons = rejected or omitted or ["no log source produced a valid rule"]
            return AgentResult(
                success=False,
                data=SigmaGenerationOutput(
                    logsources_considered=logsources,
                    rejected=rejected or omitted,
                    omitted=omitted,
                ),
                error="no log source produced a valid rule: " + "; ".join(all_reasons),
                warnings=warnings,
                metadata={
                    "duration_ms": int((time.monotonic() - start) * 1000),
                    **self._llm_usage_metadata(),
                },
            )

        warnings.extend(f"rejected rule: {r}" for r in rejected if not any(w.endswith(r) for w in warnings))
        provider = self._get_provider()
        return AgentResult(
            success=True,
            data=SigmaGenerationOutput(
                rules=rules, logsources_considered=logsources, rejected=rejected, omitted=omitted, review_gaps=review_gaps
            ),
            error=None,
            warnings=warnings,
            metadata={
                "llm_provider": provider.provider_name,
                "llm_model": getattr(provider, "model", getattr(provider, "model_id", "unknown")),
                "duration_ms": int((time.monotonic() - start) * 1000),
                **self._llm_usage_metadata(),
            },
        )

    @staticmethod
    def _source_passages(input_data: SigmaGenerationInput) -> List[str]:
        """The verified source text the reviewer judges against: artifact and indicator evidence, and guidance."""
        passages: List[str] = []
        texts = [
            *(str(a.get("evidence", "")) for a in input_data.source_artifacts),
            *(str(c.get("passage", "")) for c in input_data.reference_candidates),
            *(str(g.get("text", "")) for g in input_data.detection_guidance),
            *(str(r.get("evidence", "")) for r in input_data.indicator_records),
        ]
        if input_data.indicators:
            for kind, vals in input_data.indicators.items():
                if vals:
                    texts.append(f"Indicators ({kind}): {', '.join(str(v) for v in vals)}")
        if input_data.threat_intel:
            from hecate_agent.core.source_evidence import chunk_text

            texts.extend(chunk_text(input_data.threat_intel, size=300, overlap=50))

        for text in texts:
            if not text or text == "cti":
                continue
            text = " ".join(text.split())[:300]
            if len(text) >= 12 and text not in passages:
                passages.append(text)
        return passages[:25]

    def _review_rules(
        self,
        rules: List[SigmaRule],
        input_data: SigmaGenerationInput,
        prior_reviews: Optional[Dict[str, RuleReview]] = None,
    ) -> Tuple[List[SigmaRule], List[str], List[Dict[str, str]], List[str]]:
        """Reuse generation reviews for identical rule-and-evidence prompts.

        Missing or failed reviews are retried here; coverage is always checked
        against the final rule set. Only a verified source contradiction drops a rule.
        """
        reviewer = RuleReviewer(
            lambda prompt, validate: self._call_llm_with_retry(
                prompt,
                validate,
                max_retries=1,
                max_tokens=1024,
                temperature=0.0,
                capability="sigma_review",
            )
        )
        passages = self._source_passages(input_data)
        kept: List[SigmaRule] = []
        rejected: List[str] = []
        warnings: List[str] = []

        model_rules = [r for r in rules if r.origin == "model"]
        from concurrent.futures import ThreadPoolExecutor

        def _review_one(rule: SigmaRule) -> Tuple[SigmaRule, Optional[Any], Optional[Exception]]:
            try:
                key = review_prompt(rule.rule_yaml, input_data.hypothesis, passages)
                rev = (prior_reviews or {}).get(key)
                if rev is None:
                    rev = reviewer.review(rule.rule_yaml, input_data.hypothesis, passages)
                return rule, rev, None
            except Exception as exc:  # noqa: BLE001 - a failed review keeps the rule, unreviewed
                return rule, None, exc

        review_map: Dict[int, Any] = {}
        if model_rules:
            with ThreadPoolExecutor(max_workers=min(len(model_rules), 6)) as executor:
                for rule, rev, exc in executor.map(_review_one, model_rules):
                    review_map[id(rule)] = (rev, exc)

        for rule in rules:
            if rule.origin != "model":
                kept.append(rule)
                continue
            rev, exc = review_map.get(id(rule), (None, None))
            if exc is not None:
                warnings.append(f"rule review failed for {rule.title!r}: {exc}")
                kept.append(rule)
                continue
            if rev is None:
                kept.append(rule)
                continue
            if rev.verdict == "reject" and rev.verified:
                remediation = _remediate_platform_contradiction(rule.rule_yaml, rev.contradiction)
                if remediation:
                    remediated_yaml, old_prod, new_os = remediation
                    rule.rule_yaml = remediated_yaml
                    warnings.append(
                        f"rule {rule.title!r} auto-remediated platform from {old_prod!r} to {new_os!r} "
                        f"based on reviewer diagnostic"
                    )
                    kept.append(rule)
                    continue
                rejected.append(f'{rule.logsource_category}: reviewer: {rev.contradiction} (source: "{rev.quote[:160]}")')
                continue
            document = yaml.safe_load(rule.rule_yaml)
            note: Dict[str, Any] = {"verdict": rev.verdict}
            if rev.issues:
                note["issues"] = rev.issues
            if rev.contradiction:
                note["unverified_contradiction"] = rev.contradiction
            document["hecate_review"] = note
            rule.rule_yaml = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=100)
            kept.append(rule)
        gaps: List[Dict[str, str]] = []
        try:
            gaps = reviewer.gaps(
                [
                    {
                        "title": r.title,
                        "description": str(yaml.safe_load(r.rule_yaml).get("description", "")),
                        "detection": yaml.safe_dump(yaml.safe_load(r.rule_yaml).get("detection") or {}),
                    }
                    for r in kept
                ],
                input_data.hypothesis,
                passages,
            )
        except Exception as exc:  # noqa: BLE001 - coverage is advice, never fatal
            warnings.append(f"coverage review failed: {exc}")
        return kept, rejected, gaps, warnings

    def _command_rules(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """A command the source quotes being run becomes a process rule: the program and its distinctive argument.

        The ClickFix report quoted ``xattr -d com.apple.quarantine`` and
        ``launchctl bootstrap ...``; the model turned them into at most one generic rule.
        """
        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        for candidate in [*input_data.observed_commands, *input_data.reference_candidates]:
            reference = candidate in input_data.reference_candidates
            cat = str(candidate.get("category", "process_creation"))
            title = str(candidate.get("title", ""))
            cand_platform = candidate.get("platform")
            if not cand_platform:
                det = candidate.get("detection") or {}
                sel = det.get("selection") or {}
                img = str(sel.get("Image|endswith", ""))
                cmd_str = str(candidate.get("command", ""))
                if img.startswith("/") or any(
                    u in cmd_str or u in img for u in ("nsenter", "bpftool", "bash", "sh", "kprobe")
                ):
                    cand_platform = "linux"
            if not reference and not title.startswith(("Command", "File", "Scheduled")):
                title = (
                    f"Command the source shows being run: {title}"
                    if cat == "process_creation"
                    else f"File created by command: {title}"
                )
            preamble = (
                "Deterministic rule built from a command quoted in the primary source, with no model involvement. "
                if cat == "process_creation"
                else "Deterministic rule built for artifact written by a command quoted in the primary source, with no model involvement. "
            )
            if reference:
                preamble = "Deterministic candidate from a documented reference procedure; not evidence of an observed intrusion or successful exploitation. "
            results.append(
                self._ioc_rule(
                    input_data,
                    category=cat,
                    label="documented reference" if reference else "observed command" if cat == "process_creation" else "written file",
                    title=title[:120],
                    description=(f'The source documents this procedure: "{candidate.get("command", "")}".' if reference
                                 else f'The source shows this command being run: "{candidate.get("command", "")}".'),
                    detection=dict(candidate.get("detection") or {}),
                    falsepositives=str(
                        candidate.get("falsepositives")
                        or "Administrators or software running the same command or creating the task for legitimate reasons"
                    ),
                    preamble=preamble,
                    level=str(candidate.get("level", "medium")),
                    author="hecate (auto-generated from commands quoted in the source - requires analyst review)",
                    behaviour=str(
                        candidate.get("behaviour") or f"{candidate.get('title', '')} {candidate.get('command', '')}"
                    ),
                    rule_platform=cand_platform,
                )
            )
        return results

    def _written_file_rules(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """Pass two, mechanically: a file the source says the malware writes becomes a file_event rule.

        The A1 replay's model wrote the decoy rule with pass one's wildcard,
        then dropped its directory and filtered out C:\\Windows\\Temp\\, where the
        decoy is written. Mapping a written path to TargetFilename needs no judgement.
        """
        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        for literal in input_data.query_literals():
            if not literal.get("written") or "file_event.TargetFilename" not in (literal.get("fields") or []):
                continue
            sigma, how = str(literal["sigma"]), str(literal.get("match", "exact"))
            if "/" not in sigma and "\\" not in sigma:
                # A file event records a full path, and a bare name says nothing of where: the
                # Redis botnet replay built rules for SAM.save and fleet.b64, files in the
                # operator's own directory. The name stays a literal the model may use.
                continue
            key = "TargetFilename|endswith" if how == "endswith" else "TargetFilename"
            name = sigma.replace("/", "\\").rsplit("\\", 1)[-1]
            shared = bool(_SHARED_SYSTEM_FILE_RE.search(sigma))
            results.append(
                self._ioc_rule(
                    input_data,
                    category="file_event",
                    label="written file",
                    title=f"File the source says the malware writes: {name}"[:120],
                    description=f"The source reports the malware writing this file ({literal.get('role', '')}): "
                    f'"{literal.get("evidence", "")}".'
                    + (
                        ' The report elided part of the name; "*" stands for the missing characters.'
                        if how == "wildcard"
                        else ""
                    )
                    + (
                        " The operating system and its administrators write this file too, so a match is a lead"
                        " to review, not a detection on its own."
                        if shared
                        else ""
                    ),
                    detection={"selection": {key: sigma}, "condition": "selection"},
                    falsepositives=(
                        "Routine administration: this is a standard system file that legitimate changes also write"
                        if shared
                        else "A legitimate file with the same name and location"
                    ),
                    preamble="Deterministic rule built from a file path verified in the primary source, "
                    "with no model involvement. ",
                    level="low" if shared else "high",
                    author="hecate (auto-generated from verified source artifacts - requires analyst review)",
                    behaviour=sigma,
                )
            )
        return results

    def _guidance_rules(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """Rules the source's detection guidance specifies, built without the model.

        H-0618's source said to hunt for resume-themed executables launching
        cmd.exe and then Word, and for %TEMP%\\log_de.log. The model, asked for
        behaviour instead, wrote Word launching cmd.exe. Each rule quotes the
        guidance it implements, and passes the same semantic gate as any other.
        """
        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        for item in input_data.detection_guidance:
            if item.get("route") != "sigma":
                continue
            quoted = str(item.get("text", ""))
            for candidate in item.get("candidates") or []:
                category = str(candidate.get("category", ""))
                if input_data.platforms and "Windows" not in input_data.platforms and "\\" in str(candidate):
                    results.append((None, f"{category} (guidance {item.get('id')}): Windows paths on a non-Windows hunt"))
                    continue
                results.append(
                    self._ioc_rule(
                        input_data,
                        category=category,
                        label=f"guidance {item.get('id')}",
                        title=f"Source guidance {item.get('id')}: {candidate.get('title', '')}"[:120],
                        description=f'The source advises hunting for: "{quoted}". Scope: {candidate.get("note", "")}.',
                        detection=dict(candidate.get("detection") or {}),
                        falsepositives="Legitimate activity that matches the guidance; tune against the environment",
                        preamble="Deterministic rule built from the detection guidance the source published, "
                        "with no model involvement. ",
                        level="medium",
                        behaviour=quoted,
                        author="hecate (auto-generated from source detection guidance - requires analyst review)",
                        references=[str(item.get("source", ""))] if item.get("source") else [],
                    )
                )
        return results

    def _cloud_control_plane_rules(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """Deterministic control plane detection rules for cloud/identity intrusions.

        Identifies OAuth application consent abuse, illicit app registrations, and
        AWS STS role assumptions described in the threat intelligence or hypothesis.
        """
        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        text = f"{input_data.threat_intel or ''} {input_data.hypothesis or ''} {input_data.justification or ''}"

        # 1. OAuth consent grants & illicit app role assignment (Stage 1 / Entra ID)
        oauth_match = re.search(
            r"(?i)\b(consent|oauth|approleassignment|service\s*principal|app\s*registration|directory\.readwrite\.all|mail\.readwrite)\b",
            text,
        )
        has_oauth_technique = any(t.upper().startswith(("T1550.001", "T1098.003", "T1528")) for t in input_data.techniques)
        if oauth_match or has_oauth_technique:
            detection: Dict[str, Any] = {
                "selection": {
                    "eventName": [
                        "Consent to application",
                        "Add app role assignment to service principal",
                        "Add service principal",
                        "Add service principal credentials",
                    ]
                },
                "condition": "selection",
            }
            perms = []
            for perm in (
                "Directory.ReadWrite.All",
                "Mail.ReadWrite",
                "User.ReadWrite.All",
                "RoleManagement.ReadWrite.Directory",
            ):
                if perm.lower() in text.lower():
                    perms.append(perm)
            if perms:
                detection["selection"]["permissions|contains"] = perms

            # Extract specific app worker/diagnostics name if mentioned
            app_matches = re.findall(r"\b([A-Za-z0-9_\-\.]+Worker|[A-Za-z0-9_\-\.]+Diagnostics[A-Za-z0-9_\-\.]*)\b", text)
            if app_matches:
                detection["selection"]["appDisplayName|contains"] = list(dict.fromkeys(app_matches[:3]))

            results.append(
                self._ioc_rule(
                    input_data,
                    category="identity_audit",
                    label="cloud identity OAuth consent abuse",
                    title="Suspicious OAuth application consent grant or app role assignment",
                    description=(
                        "Detects application consent grants or high-privilege service principal role assignments "
                        "commonly abused during initial access and persistence in cloud identity tenants."
                    ),
                    detection=detection,
                    falsepositives="Legitimate tenant administrator consenting to enterprise applications or configuring service principals",
                    preamble="Deterministic cloud identity rule built for control-plane tradecraft, with no model involvement. ",
                    level="high",
                    behaviour="OAuth consent grant and service principal role assignment",
                    techniques=["T1550.001", "T1098.003"],
                )
            )

        # 2. AWS STS AssumeRole / cloud privilege escalation
        sts_match = re.search(
            r"(?i)\b(assumerole|sts:assumerole|assumerolewithsaml|assumerolewithwebidentity|aws\s+sts)\b", text
        )
        has_sts_technique = (
            any(t.upper().startswith(("T1078.004", "T1550")) for t in input_data.techniques) and "aws" in text.lower()
        )
        if sts_match or has_sts_technique:
            detection_sts: Dict[str, Any] = {
                "selection": {
                    "eventSource": "sts.amazonaws.com",
                    "eventName": [
                        "AssumeRole",
                        "AssumeRoleWithSAML",
                        "AssumeRoleWithWebIdentity",
                    ],
                },
                "condition": "selection",
            }
            results.append(
                self._ioc_rule(
                    input_data,
                    category="cloud_audit",
                    label="cloud audit AWS STS AssumeRole",
                    title="Suspicious AWS STS AssumeRole or cross-account role assumption",
                    description=(
                        "Detects AWS Security Token Service (STS) AssumeRole API calls indicative of cross-account "
                        "access or temporary credential acquisition by an adversary."
                    ),
                    detection=detection_sts,
                    falsepositives="Legitimate cross-account administration, CI/CD pipelines, or federated IAM access",
                    preamble="Deterministic cloud audit rule built for control-plane tradecraft, with no model involvement. ",
                    level="medium",
                    behaviour="AWS STS AssumeRole credential acquisition",
                    techniques=["T1078.004", "T1550"],
                )
            )

        return results

    def _ioc_rules(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """Rules built from the supplied indicators alone, with no model call.

        Typed indicator records, when supplied, decide the placements; see
        :meth:`_ioc_rules_from_records`. Without them every indicator is
        placed as before.

        One per kind the intel carries: file hashes (process_creation, via
        Sysmon's ``Hashes`` field and SigmaHQ's ``ALGO=value`` convention),
        domains and hosts (dns_query), and addresses (network_connection).
        """
        if input_data.indicator_records:
            return self._ioc_rules_from_records(input_data)
        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        hashes = hash_selectors(input_data.indicators)
        if hashes:
            results.append(
                self._ioc_rule(
                    input_data,
                    category="process_creation",
                    label="hash IOC",
                    title="Execution of a file hash named in the source intelligence",
                    description="Matches a process whose image hash is one the source published.",
                    detection={"selection": {"Hashes|contains": hashes}, "condition": "selection"},
                    falsepositives="None expected for exact hashes; confirm the sensor records the listed algorithms",
                )
            )
        addresses, names, suffixes = network_selectors(input_data.indicators)
        from hecate_agent.core.provenance import is_dual_use

        direct_addresses = [a for a in addresses if not is_dual_use(a)]
        dual_addresses = [a for a in addresses if is_dual_use(a)]
        direct_names = [n for n in names if not is_dual_use(n)]
        dual_names = [n for n in names if is_dual_use(n)]
        direct_suffixes = [s for s in suffixes if not is_dual_use(s.lstrip("."))]
        dual_suffixes = [s for s in suffixes if is_dual_use(s.lstrip("."))]

        if direct_names:
            detection: Dict[str, Any] = {"selection_exact": {"QueryName": direct_names}}
            if direct_suffixes:
                detection["selection_subdomain"] = {"QueryName|endswith": direct_suffixes}
            detection["condition"] = "1 of selection_*"
            results.append(
                self._ioc_rule(
                    input_data,
                    category="dns_query",
                    label="domain IOC",
                    title="DNS lookup of a domain named in the source intelligence",
                    # Subdomains only when a suffix selection exists: hostnames stay exact.
                    description="Matches a DNS query for a domain or host the source published"
                    + (", or a subdomain of a published domain." if direct_suffixes else "."),
                    detection=detection,
                    falsepositives="Security tooling or analysts resolving the indicators themselves",
                )
            )
        if direct_addresses or direct_names:
            detection = {}
            if direct_addresses:
                detection["selection_address"] = {"DestinationIp": direct_addresses}
            if direct_names:
                detection["selection_host"] = {"DestinationHostname": direct_names}
            if direct_suffixes:
                detection["selection_subdomain"] = {"DestinationHostname|endswith": direct_suffixes}
            detection["condition"] = "1 of selection_*"
            results.append(
                self._ioc_rule(
                    input_data,
                    category="network_connection",
                    label="network IOC",
                    title="Connection to an address or host named in the source intelligence",
                    description=(
                        "Matches an outbound connection to an address the source published, "
                        "or to a host whose name it published."
                    ),
                    detection=detection,
                    falsepositives="Shared hosting or CDN addresses reused by unrelated sites",
                )
            )
        if dual_addresses or dual_names:
            candidate_procs = self._find_initiating_processes(input_data)
            dual_detection: Dict[str, Any] = {}
            if dual_addresses:
                dual_detection["selection_dest_ip"] = {"DestinationIp": dual_addresses}
            if dual_names:
                dual_detection["selection_dest_host"] = {"DestinationHostname": dual_names}
            if dual_suffixes:
                dual_detection["selection_dest_subdomain"] = {"DestinationHostname|endswith": dual_suffixes}
            if candidate_procs:
                dual_detection["selection_process"] = {"Image|endswith": candidate_procs}
                dual_detection["condition"] = "(1 of selection_dest_*) and selection_process"
            else:
                dual_detection["filter_legit"] = {"Image|endswith": _platform_legit_filters(input_data.platforms)}
                dual_detection["condition"] = "(1 of selection_dest_*) and not filter_legit"
            techs = [
                t
                for t in ("T1567.002", "T1567", "T1071.001", "T1071")
                if any(t.lower() == it.lower() for it in input_data.techniques)
            ]
            results.append(
                self._ioc_rule(
                    input_data,
                    category="network_connection",
                    label="dual-use network IOC",
                    title="Outbound Connection to Dual-Use Cloud Endpoint by Observed Staging/Exfiltration Process",
                    description=(
                        "Matches an outbound network connection to a dual-use cloud storage or SaaS endpoint "
                        "published in intelligence, bound to the observed suspicious/staging process to avoid "
                        "enterprise alert storms."
                    ),
                    detection=dual_detection,
                    falsepositives="Legitimate administrative synchronization or automated cloud storage jobs using the specified binary",
                    level="high",
                    references=input_data.references,
                    behaviour="exfiltration to cloud storage",
                    techniques=techs or None,
                )
            )
        return results

    def _find_initiating_processes(self, input_data: SigmaGenerationInput) -> List[str]:
        """Find candidate non-system executables tied to exfiltration, staging, or network activity."""
        from hecate_agent.core.query_literals import SYSTEM_IMAGES

        staging_keywords = re.compile(
            r"\b(s3|cloud|storage|rclone|sync|exfiltrat\w*|upload\w*|aws|blob|bucket|transfer)\b", re.I
        )
        procs: List[str] = []

        # 1. Look in threat intel text for binaries near staging/cloud keywords
        for line in (input_data.threat_intel or "").splitlines():
            if staging_keywords.search(line):
                for match in re.finditer(r"\b([a-zA-Z0-9_\-\.]+\.exe)\b", line, re.I):
                    name = match.group(1).lower()
                    if name not in SYSTEM_IMAGES and f"\\{name}" not in procs:
                        procs.append(f"\\{name}")

        # 2. Look in observed commands
        for cmd_dict in input_data.observed_commands:
            cmd = str(cmd_dict.get("command", "")).strip()
            if staging_keywords.search(cmd):
                for match in re.finditer(r"\b([a-zA-Z0-9_\-\.]+\.exe)\b", cmd, re.I):
                    name = match.group(1).lower()
                    if name not in SYSTEM_IMAGES and f"\\{name}" not in procs:
                        procs.append(f"\\{name}")

        # 3. Look in query literals
        for lit in input_data.query_literals():
            if "process_creation.Image" in lit.get("fields", []):
                val = str(lit.get("value", "")).strip()
                clean = val.split("\\")[-1].split("/")[-1].lower()
                if clean.endswith(".exe") and clean not in SYSTEM_IMAGES:
                    entry = f"\\{clean}"
                    if entry not in procs:
                        procs.append(entry)

        # 4. Fallback to any non-system .exe in threat intel if none found near keywords
        if not procs:
            for match in re.finditer(r"\b([a-zA-Z0-9_\-\.]+\.exe)\b", input_data.threat_intel or "", re.I):
                name = match.group(1).lower()
                if name not in SYSTEM_IMAGES and f"\\{name}" not in procs:
                    procs.append(f"\\{name}")

        return procs

    def _ioc_rules_from_records(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """IOC rules from typed records: each indicator only where its role can be observed.

        A hash reaches a process rule only as an executable (or an unreviewed
        hash), a library only an image-load rule; archives, documents, network
        content and in-memory payloads get none. Historical indicators get no
        rule at all. Each address is paired with the ports the source ties to
        it, one selection per port, so HTTP staging and a raw-TCP channel on
        the same host stay distinguishable. URL paths go to proxy logs, the
        only telemetry that records them. Dual-use cloud and SaaS indicators
        (AWS S3, Azure Blob, etc.) are bound to initiating suspicious processes
        rather than swept bare.
        """
        from hecate_agent.core.provenance import IndicatorRecord, hash_label, scoped_placements, url_parts

        records = [IndicatorRecord.from_dict(r) for r in input_data.indicator_records]
        placed = scoped_placements(records)

        def values_for(placement: str) -> List[IndicatorRecord]:
            return [r for r, where in placed if placement in where]

        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        for category, label, what in (
            ("process_creation", "hash IOC", "a process whose image hash is an executable the source published"),
            ("image_load", "library hash IOC", "a loaded library whose hash the source published"),
        ):
            hashes = [f"{hash_label(r.type)}={r.value}" for r in values_for(f"{category}.Hashes")]
            if hashes:
                results.append(
                    self._ioc_rule(
                        input_data,
                        category=category,
                        label=label,
                        title=f"{'Execution' if category == 'process_creation' else 'Load'} of a file hash named in the source intelligence",
                        description=f"Matches {what}. Hashes of archives, documents, network content and "
                        "in-memory payloads are excluded: no process image carries them.",
                        detection={"selection": {"Hashes|contains": hashes}, "condition": "selection"},
                        falsepositives="None expected for exact hashes; confirm the sensor records the listed algorithms",
                    )
                )

        names = values_for("dns_query.QueryName")
        if names:
            detection: Dict[str, Any] = {"selection_exact": {"QueryName": [r.value for r in names]}}
            domains = ["." + r.value for r in names if r.type == "domain"]
            if domains:
                detection["selection_subdomain"] = {"QueryName|endswith": domains}
            detection["condition"] = "1 of selection_*"
            results.append(
                self._ioc_rule(
                    input_data,
                    category="dns_query",
                    label="domain IOC",
                    title="DNS lookup of a domain named in the source intelligence",
                    description="Matches a DNS query for a current domain or host the source published"
                    + (", or a subdomain of a published domain." if domains else ".")
                    + " Indicators the source marks historical are excluded.",
                    detection=detection,
                    falsepositives="Security tooling or analysts resolving the indicators themselves",
                )
            )

        network = _network_selections([*values_for("network_connection.DestinationIp"), *names])
        if network:
            network["condition"] = "1 of selection_*"
            results.append(
                self._ioc_rule(
                    input_data,
                    category="network_connection",
                    label="network IOC",
                    title="Connection to an address or host named in the source intelligence",
                    description="Matches an outbound connection to a current address or host the source published, "
                    "on the ports the source ties to it where it names them. Indicators the source marks "
                    "historical are excluded.",
                    detection=network,
                    falsepositives="Shared hosting or CDN addresses reused by unrelated sites",
                )
            )

        # Addresses the source names as where the attack came from. H-0830's
        # exploitation "Source IPs" went into an outbound DestinationIp sweep
        # that could never see them: they are the client in web logs and the
        # source of an inbound connection.
        inbound = sorted({r.value for r in values_for("webserver.c-ip")})
        if inbound:
            results.append(
                self._ioc_rule(
                    input_data,
                    category="webserver",
                    label="inbound address IOC",
                    title="Web request from an address the source names as an attack source",
                    description="Matches a web or reverse-proxy access log entry whose client address the source "
                    "published as the origin of exploitation or scanning. Indicators the source marks historical "
                    "are excluded.",
                    detection={"selection": {"c-ip": inbound}, "condition": "selection"},
                    falsepositives="Addresses reassigned since the report, or shared egress (VPN, carrier NAT)",
                )
            )
            results.append(
                self._ioc_rule(
                    input_data,
                    category="network_connection",
                    label="inbound address IOC",
                    title="Inbound connection from an address the source names as an attack source",
                    description="Matches a connection accepted from an address the source published as the "
                    "origin of exploitation or scanning. Indicators the source marks historical are excluded.",
                    detection={
                        "selection": {"SourceIp": inbound, "Initiated": "false"},
                        "condition": "selection",
                    },
                    falsepositives="Addresses reassigned since the report, or shared egress (VPN, carrier NAT)",
                )
            )

        dual = values_for("network_connection.dual_use")
        dual_ips = [r.value for r in dual if r.type in ("ipv4", "ipv6")]
        dual_hosts = [r.value for r in dual if r.type in ("domain", "hostname")]
        # Only addresses and hosts can select a connection. H-0830's dual-use
        # set was four URL paths, and the rule shipped a condition naming
        # selection_dest_* with no such selection in it.
        if dual_ips or dual_hosts:
            candidate_procs = self._find_initiating_processes(input_data)
            dual_detection: Dict[str, Any] = {}
            if dual_ips:
                dual_detection["selection_dest_ip"] = {"DestinationIp": dual_ips}
            if dual_hosts:
                dual_detection["selection_dest_host"] = {"DestinationHostname": dual_hosts}
                domain_suffixes = ["." + r.value for r in dual if r.type == "domain" or r.value.startswith("s3.")]
                if domain_suffixes:
                    dual_detection["selection_dest_subdomain"] = {"DestinationHostname|endswith": sorted(set(domain_suffixes))}

            if candidate_procs:
                dual_detection["selection_process"] = {"Image|endswith": candidate_procs}
                dual_detection["condition"] = "(1 of selection_dest_*) and selection_process"
            else:
                dual_detection["filter_legit"] = {"Image|endswith": _platform_legit_filters(input_data.platforms)}
                dual_detection["condition"] = "(1 of selection_dest_*) and not filter_legit"

            techs = [
                t
                for t in ("T1567.002", "T1567", "T1071.001", "T1071")
                if any(t.lower() == it.lower() for it in input_data.techniques)
            ]
            results.append(
                self._ioc_rule(
                    input_data,
                    category="network_connection",
                    label="dual-use network IOC",
                    title="Outbound Connection to Dual-Use Cloud Endpoint by Observed Staging/Exfiltration Process",
                    description=(
                        "Matches an outbound network connection to a dual-use cloud storage or SaaS endpoint "
                        "published in intelligence, bound to the observed suspicious/staging process to avoid "
                        "enterprise alert storms."
                    ),
                    detection=dual_detection,
                    falsepositives="Legitimate administrative synchronization or automated cloud storage jobs using the specified binary",
                    level="high",
                    references=input_data.references,
                    behaviour="exfiltration to cloud storage",
                    techniques=techs or None,
                )
            )

        urls = sorted({url_parts(r.value) for r in values_for("proxy.c-uri")}, key=str)
        selections = {
            f"selection_{index}": {"cs-host": host, "c-uri|contains": path}
            for index, (host, _, path) in enumerate(urls)
            if host and path and path != "/"
        }
        if selections:
            results.append(
                self._ioc_rule(
                    input_data,
                    category="proxy",
                    label="URL IOC",
                    title="Request for a URL host and path named in the source intelligence",
                    description="Matches a proxy or web request for a current URL host and path the source published. "
                    "URL paths appear only in proxy and web logs, not in endpoint file or process events.",
                    detection={**selections, "condition": "1 of selection_*"},
                    falsepositives="Authorized investigation or retrieval of the published URL",
                )
            )
        return results

    def _ioc_rule(
        self,
        input_data: SigmaGenerationInput,
        *,
        category: str,
        label: str,
        title: str,
        description: str,
        detection: Dict[str, Any],
        falsepositives: str,
        preamble: str = (
            "Deterministic IOC rule built from the indicators the source intelligence published, with no model involvement. "
        ),
        level: str = "high",
        author: str = "hecate (auto-generated from source indicators - requires analyst review)",
        references: Optional[List[str]] = None,
        behaviour: str = "",
        techniques: Optional[List[str]] = None,
        rule_platform: Optional[str] = None,
    ) -> Tuple[Optional[SigmaRule], Optional[str]]:
        """Render and validate one deterministic rule: IOC sweeps and the source's own detection guidance."""
        detection, _ = repair_sigma_semantics(detection)
        # The same semantic gate as a model rule: a template change that put a
        # field in the wrong category would otherwise ship on every hunt.
        problem = semantic_problem(detection, category, description)
        if problem:
            return None, f"{category} ({label}): {problem}"
        rule_techniques = techniques if techniques is not None else _behaviour_techniques(behaviour, input_data.techniques)
        if category in HOST_SENSOR_LOGSOURCES and appliance_only(input_data.platforms):
            # Kept, because the artifact is real, but a reviewer must know no
            # sensor on the device will raise it.
            description += (
                " This hunt is scoped to appliances, which rarely run a host sensor: use this as a forensic "
                "check on the device, or where file-integrity or EDR coverage exists for it."
            )
        document: Dict[str, Any] = {
            "title": title,
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": preamble + description,
            "references": list(dict.fromkeys([*input_data.references, *(references or [])])),
            "author": author,
            "date": date.today().isoformat(),
            "tags": [f"attack.{t.lower()}" for t in rule_techniques],
            "logsource": self._logsource_block(category, input_data.platforms, rule_platform=rule_platform),
            "detection": detection,
            "falsepositives": [falsepositives],
            "level": level,
        }
        provenance = rule_provenance(detection, input_data)
        if provenance:
            document["hecate_provenance"] = provenance
        if input_data.hunt_id:
            document["hunt_id"] = input_data.hunt_id
        rule_yaml = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=100)
        problem = _pysigma_problem(rule_yaml)
        if problem:
            return None, f"{category} ({label}): {problem}"
        return (
            SigmaRule(
                logsource_category=category,
                title=title,
                rule_yaml=rule_yaml,
                level=level,
                techniques=rule_techniques,
                origin="deterministic",
            ),
            None,
        )

    def _generate_for_logsource(
        self,
        input_data: SigmaGenerationInput,
        logsource: str,
        review_cache: Optional[Dict[str, RuleReview]] = None,
    ) -> Tuple[Optional[SigmaRule], List[str], List[str]]:
        """Draft one rule for one log source.

        Returns ``(rule_or_None, problems, omitted)`` rather than raising, so one log
        source failing -- a timeout, a truncated reply, an unusable rule --
        costs only its own rule and the rest of the hunt still gets coverage.
        Problems are reported even alongside a successful rule: a response
        carrying one good rule and one malformed sibling is worth a warning.
        """

        # Preserve the exact artifact that was reviewed, including its generated
        # UUID. Rebuilding it after validation invalidates review reuse.
        built_rules: Dict[str, Tuple[Optional[SigmaRule], Optional[str]]] = {}
        if review_cache is None:
            review_cache = {}

        def validate_json(text: str) -> Optional[str]:
            try:
                payload = self._parse_json_response(text)
            except ValueError as exc:
                return str(exc)
            if not isinstance(payload.get("rules"), list):
                return "response must contain a 'rules' array"
            if not payload["rules"]:
                # Model explicitly determined no valid rule can be drafted without hallucinating
                return None

            problems = []
            for raw in payload["rules"]:
                raw_key = json.dumps(raw, sort_keys=True)
                if raw_key not in built_rules:
                    built_rules[raw_key] = self._build_rule(raw, input_data)
                rule, problem = built_rules[raw_key]
                if problem:
                    problems.append(problem)
                elif rule and rule.logsource_category == logsource:
                    if input_data.review_rules:
                        reviewer = RuleReviewer(
                            lambda prompt, validate: self._call_llm_with_retry(
                                prompt,
                                validate,
                                max_retries=1,
                                max_tokens=1024,
                                temperature=0.0,
                                capability="sigma_review",
                            )
                        )
                        passages = SigmaGeneratorAgent._source_passages(input_data)
                        try:
                            key = review_prompt(rule.rule_yaml, input_data.hypothesis, passages)
                            review = review_cache.get(key)
                            if review is None:
                                review = reviewer.review(rule.rule_yaml, input_data.hypothesis, passages)
                                review_cache[key] = review
                            if review.verdict == "reject" and review.verified:
                                msg = f"The rule was rejected by review: {review.contradiction or '; '.join(review.issues)}"
                                if review.quote:
                                    msg += f" (source: '{review.quote[:160]}')"
                                msg += f'. Fix these issues, or return {{"rules": []}} if {logsource} is not supported by the evidence.'
                                problems.append(msg)
                                continue
                        except Exception as exc:
                            logger.warning("rule review failed during generation: %s", exc)
                    return None  # We successfully built the requested rule!

            if problems:
                return "Your generated rules failed validation. Fix these errors:\n" + "\n".join(f"- {p}" for p in problems)
            return f"No valid rule was generated for the requested log source category '{logsource}'. If this category is unsupported, return {{\"rules\": []}}."

        try:
            # Low temperature: detection logic is not a place for invention.
            # A creative sample here means a field name that does not exist
            # in the target telemetry, which fails silently at conversion.
            output_text = self._call_llm_with_retry(
                self._build_prompt(input_data, logsource),
                validate_json,
                max_retries=3,
                temperature=0.1,
                capability="sigma_draft",
            )
            raw_rules = self._parse_json_response(output_text).get("rules", [])
        except Exception as exc:  # noqa: BLE001 - reported per log source, not fatal
            return None, [f"{logsource}: {exc}"], []

        built, problems = self._collect_rules(raw_rules, input_data, built_rules)
        return _select_for_logsource(built, logsource, problems)

    def _collect_rules(
        self,
        raw_rules: Any,
        input_data: SigmaGenerationInput,
        built_rules: Optional[Dict[str, Tuple[Optional[SigmaRule], Optional[str]]]] = None,
    ) -> Tuple[List[SigmaRule], List[str]]:
        """Build every proposed rule, keeping the reason each rejection failed."""
        rules: List[SigmaRule] = []
        rejected: List[str] = []
        for raw in raw_rules or []:
            raw_key = json.dumps(raw, sort_keys=True) if built_rules is not None else ""
            if built_rules is not None and raw_key in built_rules:
                rule, problem = built_rules[raw_key]
            else:
                rule, problem = self._build_rule(raw, input_data)
            if rule is None:
                rejected.append(problem or "unknown validation failure")
            else:
                rules.append(rule)
        return rules, rejected

    # --- Rule construction -----------------------------------------------------

    def _build_rule(self, raw: Any, input_data: SigmaGenerationInput) -> Tuple[Optional[SigmaRule], Optional[str]]:
        """Validate one model-proposed rule and render it to YAML.

        Returns ``(None, reason)`` for anything that fails, so the caller can
        report exactly what was dropped rather than emitting a rule an
        operator would have to debug at conversion time.
        """
        if not isinstance(raw, dict):
            return None, "rule is not an object"

        category = str(raw.get("logsource_category", "")).strip().lower()
        if category not in VALID_LOGSOURCE_CATEGORIES:
            return None, f"unknown logsource_category {category!r}"

        title = str(raw.get("title", "")).strip()
        if not title:
            return None, f"{category}: title is empty"

        detection, problem = self._normalise_detection(raw)
        if problem:
            return None, f"{category}: {problem}"
        detection = _anchor_bare_filenames(_strip_empty_filters(detection))
        detection = _complete_indicator_lists(detection, input_data.indicators)
        detection, _ = repair_sigma_semantics(detection)
        problem = self._validate_detection(detection)
        if problem:
            return None, f"{category}: {problem}"
        literals = input_data.query_literals()
        # Each check sees a structurally valid rule; the first to object wins.
        checks = (
            lambda d: _placeholder_problem(d, input_data.indicators),
            lambda d: _invented_ip_problem(d, input_data.indicators, input_data.observables),
            lambda d: _invented_hash_problem(d, input_data.indicators),
            lambda d: _invented_domain_problem(
                d,
                input_data.indicators,
                [
                    input_data.hypothesis,
                    input_data.justification,
                    *input_data.observables,
                    *input_data.references,
                ],
            ),
            lambda d: _partial_indicator_problem(d, input_data.indicators, category),
            lambda d: _self_defeating_filter_problem(d, input_data.hypothesis),
            lambda d: _excluded_threat_problem(d, input_data.indicators),
            _modifier_in_value_problem,
            _impossible_modifier_problem,
            lambda d: _library_as_process_problem(d, category),
            _field_type_problem,
            _breadth_problem,
            _or_branch_breadth_problem,
            lambda d: _hash_role_problem(d, input_data.indicator_records, category),
            lambda d: _network_role_problem(d, input_data.indicator_records),
            lambda d: _literal_problem(d, literals),
            lambda d: _reversed_guidance_chain_problem(d, input_data.detection_guidance),
            lambda d: _unobservable_auth_claim_problem(d, f"{title}. {raw.get('description', '')}"),
            lambda d: _outbound_to_target_port_problem(d, category, input_data.source_artifacts),
            lambda d: semantic_problem(
                d,
                category,
                f"{title}. {raw.get('description', '')}",
                [
                    *input_data.observables,
                    *(v for values in input_data.indicators.values() for v in values),
                    *(str(r.get("value", "")) for r in input_data.indicator_records),
                ],
            ),
        )
        for check in checks:
            problem = check(detection)
            if problem:
                return None, f"{category}: {problem}"

        level = str(raw.get("level", "medium")).strip().lower()
        if level not in VALID_LEVELS:
            level = "medium"

        techniques = self._rule_techniques(raw, input_data, category)
        rule_platform: Optional[str] = raw.get("logsource_product")
        if not rule_platform:
            for _, block in blocks(detection):
                for k, v in block.items():
                    if base_field(k).lower() in ("image", "parentimage", "commandline"):
                        raw_vals = v if isinstance(v, list) else [v]
                        if any(
                            str(x).startswith("/") or any(u in str(x) for u in ("/bin/", "/usr/", "nsenter", "bpftool"))
                            for x in raw_vals
                        ):
                            rule_platform = "linux"
                            break
                if rule_platform:
                    break

        document: Dict[str, Any] = {
            "title": title[:120],
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": str(raw.get("description", "")).strip()
            or f"Auto-drafted for hunt {input_data.hunt_id or '(unassigned)'}.",
            "references": list(input_data.references),
            "author": "hecate (auto-generated draft - requires analyst review)",
            "date": date.today().isoformat(),
            "tags": [f"attack.{t.lower()}" for t in techniques],
            "logsource": self._logsource_block(category, input_data.platforms, rule_platform=rule_platform),
            "detection": detection,
            "falsepositives": self._falsepositives(raw),
            "level": level,
        }
        provenance = rule_provenance(detection, input_data)
        if provenance:
            document["hecate_provenance"] = provenance
        if input_data.hunt_id:
            # Not Sigma's `related:`. That field relates a rule to *other Sigma
            # rules* and its `id` must be a UUID, so putting a hunt id there
            # made every rule we emitted fail to parse -- all 17 in the corpus,
            # with `SigmaRelatedError: Sigma related identifier must be an
            # UUID`. A custom key carries the same link and stays valid.
            document["hunt_id"] = input_data.hunt_id

        rule_yaml = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=100)

        # Last gate, on the rendered rule rather than the model's JSON: this is
        # the artifact an operator would actually run.
        problem = _pysigma_problem(rule_yaml)
        if problem:
            return None, f"{category}: {problem}"

        return (
            SigmaRule(
                logsource_category=category,
                title=title[:120],
                rule_yaml=rule_yaml,
                techniques=techniques,
                level=level,
            ),
            None,
        )

    @staticmethod
    def _normalise_detection(raw: Dict[str, Any]) -> Tuple[Any, Optional[str]]:
        """Repair the two placements models get wrong, and only those.

        Observed on every rule of a real run: the model emits
        ``detection: {selection: {...}}`` and omits ``condition`` entirely.
        With exactly one selection block the intended condition has one
        possible value -- its name -- so inferring it is reading the rule as
        written, not guessing. With two or more blocks the operator (and/or/
        not) genuinely is unknown, so those are still rejected rather than
        silently wired up as an AND that nobody wrote.

        A ``condition`` placed at the rule's top level instead of inside
        ``detection`` is likewise moved rather than discarded -- the content
        is right, the nesting is not.
        """
        detection = raw.get("detection")
        if not isinstance(detection, dict):
            return detection, None  # let _validate_detection report the shape

        detection = dict(detection)
        for k, v in list(detection.items()):
            if k != "condition" and isinstance(v, dict) and "condition" in v:
                cond = v.pop("condition")
                if not detection.get("condition") and isinstance(cond, str) and cond.strip():
                    detection["condition"] = cond.strip()

        if not detection.get("condition"):
            top_level = raw.get("condition")
            if isinstance(top_level, str) and top_level.strip():
                detection["condition"] = top_level.strip()
            else:
                blocks = [k for k in detection if k != "condition"]
                if len(blocks) == 1:
                    detection["condition"] = blocks[0]
                elif len(blocks) > 1:
                    return detection, (
                        "detection omits 'condition' and defines "
                        f"{len(blocks)} selection blocks, so the intended "
                        "operator between them is unknowable"
                    )
        detection, repairs = repair_sigma_semantics(detection)
        if repairs:
            logger.info("Repaired Sigma detection semantics: %s", "; ".join(repairs))
        return detection, None

    @staticmethod
    def _validate_detection(detection: Any) -> Optional[str]:
        """Check the one part of a Sigma rule that silently misbehaves.

        A condition naming a selection that was never defined is still valid
        YAML and still looks like a rule; pySigma rejects it much later, by
        which time the hunt has been reviewed and approved around it.
        """
        if not isinstance(detection, dict):
            return "detection must be an object"
        condition = detection.get("condition")
        if not isinstance(condition, str) or not condition.strip():
            return "detection.condition must be a non-empty string"

        selections = [k for k in detection if k != "condition"]
        if not selections:
            return "detection defines no selection blocks"
        for name in selections:
            if not isinstance(detection[name], (dict, list)):
                return f"selection {name!r} must be a mapping or list"

        return SigmaGeneratorAgent._unresolved_condition_token(condition, selections)

    @staticmethod
    def _unresolved_condition_token(condition: str, selections: List[str]) -> Optional[str]:
        """Report the first condition token that names no defined block.

        A Sigma condition may carry an aggregation after a pipe:
        ``selection | count() by TargetUserName > 25``. Everything right of
        the pipe is aggregation grammar, not selection names, and splitting
        the whole string on whitespace read ``count()``, ``>`` and ``25`` as
        undefined selections -- so every volume-based rule the model produced
        was discarded before pySigma ever saw it. Volume is how Sigma
        expresses "an unusual number of", which is exactly what a
        credential-stuffing or brute-force hunt needs.
        """
        search, pipe, aggregation = condition.partition("|")
        problem = SigmaGeneratorAgent._unresolved_search_token(search, selections)
        if problem:
            return problem
        if pipe:
            return SigmaGeneratorAgent._aggregation_problem(aggregation, selections)
        return None

    @staticmethod
    def _unresolved_search_token(search: str, selections: List[str]) -> Optional[str]:
        """Validate the search half of a condition against the defined blocks."""
        keywords = {"and", "or", "not", "of", "them", "all", "1", "any", "selection"}
        tokens = {token.strip("()") for token in search.replace("(", " ").replace(")", " ").split()}
        for token in tokens:
            if not token or token in keywords or token.isdigit():
                continue
            if token.endswith("*"):
                if not any(sel.startswith(token[:-1]) for sel in selections):
                    return f"condition references undefined selection pattern {token!r}"
                continue
            if token not in selections:
                return f"condition references undefined selection {token!r}"
        return None

    @staticmethod
    def _aggregation_problem(aggregation: str, selections: List[str]) -> Optional[str]:
        """Validate the aggregation half of a condition.

        Checked rather than waved through: a malformed aggregation is still
        valid YAML and still looks like a threshold, so it would reach a
        reviewer as though it counted something.
        """
        text = aggregation.strip()
        if not text:
            return "condition ends in '|' with no aggregation"

        # `near` takes a search expression, not a numeric comparison.
        if text.startswith("near "):
            return SigmaGeneratorAgent._unresolved_search_token(text[len("near ") :], selections)

        match = _AGGREGATION_RE.match(text)
        if not match:
            return (
                f"aggregation {text!r} is not a Sigma aggregation; expected e.g. "
                "'count() > 25' or 'count(DestinationIp) by User > 10'"
            )
        return None

    @staticmethod
    def _logsource_block(category: str, platforms: List[str], rule_platform: Optional[str] = None) -> Dict[str, str]:
        block: Dict[str, str] = {"category": category}
        if category in ("proxy", "webserver", "cloud_audit", "identity_audit"):
            return block  # network-appliance and cloud control-plane logs have no endpoint OS product
        if category == "container_runtime":
            block["product"] = "docker"
            return block
        if rule_platform in ("linux", "unix"):
            block["product"] = "linux"
            return block
        if rule_platform == "windows":
            block["product"] = "windows"
            return block
        # Sigma's `product` is an OS, not a vendor. Only set it when the hunt
        # is genuinely single-OS; a multi-platform hunt pinned to one product
        # would silently stop matching the others. "Containers" is not an OS:
        # a Containers + Linux hunt is a Linux hunt, and leaving the product
        # unset there lets the transpiler default it to Windows.
        oses = {p.lower() for p in platforms} - {"containers"}
        if len(oses) == 1 and next(iter(oses)) in ("windows", "linux", "macos"):
            block["product"] = next(iter(oses))
        return block

    @staticmethod
    def _falsepositives(raw: Dict[str, Any]) -> List[str]:
        values = raw.get("falsepositives")
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not values:
            return ["Unknown - analyst must establish a baseline before use"]
        return [str(v).strip() for v in values if str(v).strip()][:6]

    @staticmethod
    def _rule_techniques(raw: Dict[str, Any], input_data: SigmaGenerationInput, category: str = "") -> List[str]:
        """Prefer the techniques the CTI actually asserted.

        A model asked to tag its own rule tends to restate the one technique
        it wrote prose about. Intersecting against the hunt's technique list
        keeps sub-technique precision (T1059.003, not T1059) when the source
        supplied it.
        """
        declared = raw.get("techniques") or raw.get("tags") or []
        if isinstance(declared, str):
            declared = [declared]
        cleaned = []
        for item in declared:
            token = str(item).upper().replace("ATTACK.", "").strip()
            if token.startswith("T") and token[1:2].isdigit():
                cleaned.append(token)

        # Keep only techniques the source actually asserted. A real run tagged
        # a rule "T1047.002", which does not exist -- T1047 has no such
        # sub-technique. Intersecting against the supplied list makes an
        # invented ID impossible without needing the ATT&CK matrix here.
        supplied = {t.upper() for t in input_data.techniques}
        if not supplied:
            # Nothing to intersect against, so the model's tags are its own
            # unchecked guesses. H-0014 had no techniques and its rule came
            # back tagged T1059.003 (Windows Command Shell) on a Linux hunt.
            # Untagged is honest; a guessed tag reads as a mapping.
            return []

        grounded = [t for t in cleaned if t in supplied]
        if grounded:
            return sorted(set(grounded))

        # Nothing the model proposed survived. Falling back to every supplied
        # technique tagged a DLL side-loading rule with all fifteen the event
        # carried, exfiltration and registry persistence included. Narrow to
        # the ones actually observable in this rule's own log source.
        if category:
            relevant = sorted(
                t
                for t in supplied
                if any(t.startswith(prefix) and category in sources for prefix, sources in _TECHNIQUE_LOGSOURCES.items())
            )
            if relevant:
                return relevant
        return sorted(supplied)

    # --- Prompt ----------------------------------------------------------------

    def _relevant_techniques_for_prompt(self, techniques: list[str], logsource: str) -> list[str]:
        relevant = []
        for t in techniques:
            norm = t.upper().strip()
            for prefix, sources in _TECHNIQUE_LOGSOURCES.items():
                if norm.startswith(prefix) and logsource in sources:
                    relevant.append(t)
                    break
        return relevant or techniques

    @staticmethod
    def _render_modifier_restrictions(logsource: str) -> str:
        if logsource == "network_connection":
            return (
                "\nMODIFIER RESTRICTIONS & EXAMPLES:\n"
                "- NEVER append `|all` to single-value scalar fields (such as DestinationIp, SourceIp, DestinationPort, SourcePort). "
                "A single connection event only has one destination IP or port at a time; requiring all of them simultaneously is mathematically impossible.\n"
                "  - WRONG (DO NOT USE): `DestinationIp|all: '198.51.100.1'`\n"
                "  - WRONG (DO NOT USE): `DestinationIp|all: ['198.51.100.1', '203.0.113.5']`\n"
                "  - CORRECT: `DestinationIp: '198.51.100.1'`\n"
                "  - CORRECT: `DestinationIp: ['198.51.100.1', '203.0.113.5']` (in Sigma, a list on a scalar field matches ANY element via OR)\n"
            )
        elif logsource == "process_creation":
            return (
                "\nMODIFIER RESTRICTIONS & EXAMPLES:\n"
                "- NEVER append `|all` to scalar fields without substring modifiers (e.g. `Image|all` is invalid).\n"
                "- `|all` is ONLY valid when combined with substring modifiers on multi-match text fields, e.g. `CommandLine|contains|all: ['-enc', 'bypass']`.\n"
            )
        elif logsource == "dns_query":
            return (
                "\nMODIFIER RESTRICTIONS & EXAMPLES:\n"
                "- NEVER append `|all` to scalar fields (such as QueryName).\n"
                "  - WRONG (DO NOT USE): `QueryName|all: 'example.com'`\n"
                "  - CORRECT: `QueryName: 'example.com'` or `QueryName: ['example.com', 'test.com']`\n"
            )
        elif logsource == "file_event":
            return (
                "\nMODIFIER RESTRICTIONS & EXAMPLES:\n"
                "- NEVER append `|all` to scalar fields (such as TargetFilename).\n"
                "  - WRONG (DO NOT USE): `TargetFilename|all: 'c:\\test.exe'`\n"
                "  - CORRECT: `TargetFilename: 'c:\\test.exe'` or `TargetFilename|endswith: '.tmp'`\n"
            )
        elif logsource == "registry_event":
            return (
                "\nMODIFIER RESTRICTIONS & EXAMPLES:\n"
                "- NEVER append `|all` to scalar fields (such as TargetObject).\n"
                "  - WRONG (DO NOT USE): `TargetObject|all: 'HKLM\\...'`\n"
                "  - CORRECT: `TargetObject: 'HKLM\\...'`\n"
            )
        else:
            return (
                "\nMODIFIER RESTRICTIONS & EXAMPLES:\n"
                "- NEVER append `|all` to single-value scalar fields. A single event only has one value for that field.\n"
                "- A list of values on a scalar field matches any element via logical OR.\n"
            )

    def _build_prompt(self, input_data: SigmaGenerationInput, logsource: str) -> str:
        indicator_block = self._render_indicators(input_data.indicators)
        observable_block = "\n".join(f"  - {o}" for o in input_data.observables[:10]) or "(none)"
        literals = input_data.query_literals()
        if literals:
            from hecate_agent.core.query_literals import render_literals

            # Two-pass generation: the values were extracted and verified first;
            # the rule only maps them onto fields. Model-written observables
            # are left out, since they are where invented strings came from.
            literal_block = (
                "EXACT VALUES FROM THE SOURCE (verified against the report; the ONLY file, process, command-line "
                "and registry values you may match, whole or in part, besides standard system binaries such as "
                "\\cmd.exe):\n" + render_literals(literals) + "\n"
            )
        else:
            literal_block = (
                "OBSERVABLES THE HUNT DRAFT NAMED (from research; unverified, use where they fit):\n" + observable_block + "\n"
            )
        techniques = ", ".join(self._relevant_techniques_for_prompt(input_data.techniques, logsource)) or "(none supplied)"
        platforms = ", ".join(input_data.platforms) or "(unspecified)"
        fields = _LOGSOURCE_FIELDS.get(logsource, "(use the standard Sigma fields for this category)")
        covered = [
            str(c.get("title", "")) for c in input_data.observed_commands if c.get("category", "process_creation") == logsource
        ]
        already_covered = ""
        if covered:
            already_covered = (
                f"\nNOTE: Deterministic rules already cover these specific actions for {logsource}: "
                f"{', '.join(covered)}. Do NOT duplicate them. Focus on other distinct behaviors, "
                f"scripting hosts (e.g. wscript, cscript), or process relationships described in the intelligence and hypothesis.\n"
            )

        threat_intel_block = ""
        if input_data.threat_intel:
            intel_text = input_data.threat_intel.strip()
            if len(intel_text) > 2000:
                intel_text = intel_text[:2000].rsplit("\n", 1)[0] + "\n..."
            threat_intel_block = f"\nSOURCE INTELLIGENCE SUMMARY / TRADECRAFT:\n{intel_text}\n"

        return f"""You are a detection engineer drafting one Sigma rule for a threat hunt.

HUNT HYPOTHESIS:
{input_data.hypothesis}

JUSTIFICATION:
{input_data.justification or "(none supplied)"}
{threat_intel_block}
ATT&CK TECHNIQUES: {techniques}
PLATFORMS: {platforms}

INDICATORS FROM THE SOURCE INTELLIGENCE:
{indicator_block}

{literal_block}
{self._render_guidance(input_data)}{self._render_telemetry_examples(input_data)}{already_covered}
Write EXACTLY ONE rule, for this Sigma log source category and no other:
    {logsource}

Fields available in {logsource}: {fields}
Standard Sigma Modifiers: `|contains`, `|endswith`, `|startswith`, `|all`, `|re`, `|cidr`. Do NOT invent modifiers like `|in` or `|regex`.
{self._render_modifier_restrictions(logsource)}
RULES OF THE TASK:
Telemetry values must describe what the sensor records. Endpoint paths normally contain expanded directories, not literal %APPDATA% or %TEMP% variables; use an appropriate stable path fragment. Registry value modification is not CreateKey. Titles and descriptions must describe the actual selection: do not promise obfuscation, a named task, or a download when those properties are not tested.
1. Return JSON only. Do NOT write YAML - the caller renders it.
2. IRONCLAD DETECTION LOGIC: Never use placeholder paths or exact threat tracking names inside registry keys or execution paths. Malware developers do not name their artifacts after their industry marketing names. Do NOT invent strings.
3. STRICT LOG SOURCE MAPPING: File events are ONLY for disk writes. Do NOT put process arguments in file events. Process creation events are for executions. Do not mix them.
4. Use only field names that exist in {logsource}. Match the value to the field's type: an address field takes an IP or CIDR, never a hostname, and a port field takes a number. Never place a file hash into a command-line or filename field; hashes belong ONLY in a `Hashes` field. Never use `|all` on scalar fields. If your only indicator is a domain and this log source has no name field for it, write a behavioural rule instead.
5. Prioritize BEHAVIORAL rules (relationships and sequences) over simple indicator matches.
   For example, a rule that looks for `ParentImage|endswith: \\winword.exe` spawning
   `Image|endswith: \\cmd.exe` is a high-quality, generic behavioral rule that works
   everywhere. Using no indicator at all is completely fine, and often preferred,
   when the behaviour itself is the better rule.
6. If you DO use a specific indicator, reproduce it WHOLE in one match value. Never
   split one into fragments: "bad.example.net" written as `|endswith: .net` plus
   `|contains: bad` matches every .net domain, loses the evidence, and is rejected.
   A selection that matches only a file extension (`|endswith: .exe`) or a wildcard
   matches every file of that type and is rejected.
7. Every `detection` MUST contain a `condition` key. It is not optional, and
   it may only name selection blocks you defined in the same rule. If you
   define both a selection and a filter, say so explicitly, e.g.
   "selection and not filter".
8. When the hypothesis is about an unusual *number* of events -- brute force,
   credential stuffing, password spraying, beaconing, mass enumeration -- put
   the threshold in the condition with an aggregation, or the rule fires on a
   single ordinary event. Sigma writes it as
   "selection | count() > 25" or "selection | count(IpAddress) by TargetUserName > 10".
   Only use one when volume is what makes the behaviour suspicious.
9. A `filter` must never exclude the attack path the hypothesis describes.
   On a hunt about malware delivered through the browser, excluding the
   browser as the parent process removes the very thing being hunted. An
   empty filter block is rejected: omit it instead.
10. Give realistic falsepositives. "None" is never a correct answer.
11. The JSON below shows the *shape* only. Its values are placeholders, not
   examples to copy: "FieldName", "value" and "known-good" must never appear
   in what you return, and a rule matching on them is rejected. Neither may
   invented stand-ins of your own -- "bad_command", "malicious.exe",
   "evil.com" or anything under example.com. Every value you emit must be an
   indicator from above, or a real path, process or registry key.
12. HYPOTHESIS AND ATTACK CHAIN ALIGNMENT: Your detection logic MUST hunt for the specific behaviors described in the HUNT HYPOTHESIS, ATT&CK TECHNIQUES, or the broader attack lifecycle in the SOURCE INTELLIGENCE (e.g. initial access, container breakouts, defense evasion, privilege escalation, execution, lateral movement, or exfiltration). Do not invent unrelated TTPs not present in the intelligence or techniques list. If neither the hypothesis, techniques, nor intelligence contain observable behaviors for {logsource}, return an empty rules array: {{"rules": []}}.
13. PREVENT TTP CONFLATION: If the hypothesis or intelligence mentions multiple distinct behaviors (e.g., Scheduled Tasks AND Registry Run Keys), ensure your rule focuses ONLY on the behavior that matches the current log source category. Do not mix the names, titles, or logic of distinct TTPs into a single rule.
14. STRICT PLATFORM ALIGNMENT: Your detection rule MUST target ONLY the platform(s) listed in PLATFORMS: {platforms}. If PLATFORMS is strictly Windows, you MUST NOT emit Linux/Unix paths (/bin/sh, /usr/bin, /tmp) or product: linux rules. If PLATFORMS is strictly non-Windows, you MUST NOT use Windows paths (like C:\\ or System32) or .exe names. Ensure your conditions fit the actual OS.
15. HANDLING ELISIONS: If the source intelligence gives you a partial or redacted string (e.g., `powershell -e JAB...`, `[REDACTED]`, or `C:\\temp\\...\\malware.exe`), DO NOT include the literal ellipsis `...` or `[REDACTED]` in your match value. Instead, use a substring match modifier (like `|contains` or `|startswith`) on the specific known portion of the string.
16. NO EXTERNAL THREAT-ACTOR KNOWLEDGE: Do NOT use or extrapolate from pre-trained knowledge about named threat groups, campaigns, or malware families (e.g., "SocGholish", "APT28"). You must strictly restrict detection logic to behaviors, mechanisms, and indicators explicitly given in the HUNT HYPOTHESIS, INDICATORS, and SOURCE PASSAGES. If a behavior, domain, IP, or file artifact is not explicitly stated in the prompt, assume it does not exist.
17. DUAL-USE CLOUD/SAAS DESTINATIONS: If writing a network connection or DNS query rule involving public cloud storage or SaaS endpoints (e.g. AWS S3 amazonaws.com, Azure Blob blob.core.windows.net, Google Drive, Discord, Telegram), NEVER match the destination as a bare standalone indicator: it causes severe alert storms in enterprise environments. You MUST bind the network connection to the specific initiating process or utility (e.g., Image|endswith: \\svchost_sync.exe or \\rclone.exe) using a combined condition: "(1 of selection_dest_*) and selection_process", or filter legitimate software/browsers.
18. SPOOFED AND IMPERSONATED DOMAINS: If matching a domain or host that mimics legitimate brands, services, or companies (e.g. `hub.zoom.com.kg`, `login.microsoft.com.attacker.top`), NEVER use `|contains` on the impersonated brand name (e.g., `DestinationHostname|contains: zoom.com` or `microsoft.com`). Doing so matches all legitimate enterprise traffic to that brand and will be rejected. You MUST match the attacker's indicator using exact match (`DestinationHostname: hub.zoom.com.kg`) or suffix match on the actual malicious registrable domain (`DestinationHostname|endswith: .zoom.com.kg`).
Return JSON with a single entry in "rules", or an empty list if this log source category has no supporting evidence in the hypothesis or intelligence:
{{
  "rules": [
    {{
      "logsource_category": "{logsource}",
      "title": "Short specific title",
      "description": "What this detects and why it matters",
      "techniques": ["T1059.003"],
      "detection": {{
        "selection": {{"FieldName|endswith": "value"}},
        "filter": {{"FieldName|contains": "known-good"}},
        "condition": "selection and not filter"
      }},
      "falsepositives": ["Administrative scripting"],
      "level": "medium"
    }}
  ]
}}
If no behavior or indicator matches {logsource}, return:
{{"rules": []}}"""

    @staticmethod
    def _render_telemetry_examples(input_data: SigmaGenerationInput) -> str:
        """A3: where the internals this hunt names really appear, on its platforms."""
        from hecate_agent.core.telemetry_examples import render_examples

        text = "\n".join(
            [
                input_data.hypothesis,
                input_data.justification,
                *(str(g.get("text", "")) for g in input_data.detection_guidance),
                *(str(a.get("evidence", "")) for a in input_data.source_artifacts),
            ]
        )
        return render_examples(text, input_data.platforms)

    @staticmethod
    def _render_guidance(input_data: SigmaGenerationInput) -> str:
        """The source's detection guidance, so a model rule agrees with it (chain direction above all)."""
        lines = [f'  - "{str(g.get("text", ""))[:240]}"' for g in input_data.detection_guidance if g.get("route") == "sigma"]
        if not lines:
            return ""
        return (
            "THE SOURCE'S OWN DETECTION GUIDANCE (rules implementing it are already drafted; write a rule for "
            "something else, and never contradict it, e.g. by reversing a parent/child chain):\n" + "\n".join(lines) + "\n"
        )

    @staticmethod
    def _render_indicators(indicators: Dict[str, List[str]]) -> str:
        if not indicators:
            return "(none supplied - generalise from the hypothesis and techniques)"
        lines = []
        for itype in sorted(indicators):
            values = [str(v) for v in indicators[itype]][:10]
            if values:
                lines.append(f"  {itype}: {', '.join(values)}")
        return "\n".join(lines) or "(none supplied)"
