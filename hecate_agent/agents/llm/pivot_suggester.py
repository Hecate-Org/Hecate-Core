"""Pivot suggester agent — LLM-powered next-step pivot suggestions for hunt findings."""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from hecate_agent.agents.base import AgentResult, LLMAgent
from hecate_agent.core.hunting_knowledge import EVIDENCE_RULES, load_environment_context, load_stage_guidance


@dataclass
class PivotInput:
    """Input for pivot suggestion."""

    finding: str  # JSON string or plain-text description of a suspicious finding
    hunt_id: Optional[str] = None  # Current hunt (loads context if provided)
    technique: Optional[str] = None  # Known MITRE technique if already identified


@dataclass
class PivotSuggestion:
    """A single suggested pivot query."""

    query: str  # Concrete, actionable query or investigation step
    rationale: str  # Why this pivot is valuable given the finding
    data_source: str  # Data source to target
    priority: int = 1  # 1 = highest priority
    technique_hint: str = ""  # ATT&CK technique this targets (optional)


@dataclass
class PivotOutput:
    """Output from pivot suggestion."""

    finding_summary: str  # 1-2 sentence characterization of the finding
    technique_matches: List[str] = field(default_factory=list)  # ATT&CK techniques
    pivots: List[PivotSuggestion] = field(default_factory=list)  # Suggested pivots (3-5)
    past_hunt_references: List[str] = field(default_factory=list)  # Related hunt IDs


#: Field names each pivot rule will accept, across the schemas findings arrive
#: in (raw EDR, OCSF-ish, Windows event log).
_FIELD_ALIASES: Dict[str, set] = {
    "process": {"process", "process_name", "image", "process.name", "ProcessName"},
    "parent": {"parent", "parent_process", "parent_image", "parent.process.name", "ParentProcessName"},
    "user": {"user", "user.name", "username", "User", "SubjectUserName"},
    "host": {"host", "hostname", "ComputerName", "host.name"},
    "ip": {"dst_ip", "DestinationIp", "remote_ip", "dest_ip"},
}

#: (field, suppressed_by, pivots). Order is the priority order of the output.
#: ``suppressed_by`` names a field whose presence makes this rule redundant --
#: a whole-host timeline adds little once process-level pivots exist.
_PIVOT_RULES: tuple = (
    (
        "process",
        None,
        (
            (
                "Find all network connections initiated by {value} across the environment",
                "Processes involved in malicious activity often reach out to C2 or exfil data. "
                "Scope to all hosts, not just the one where this was observed.",
                "EDR / network proxy logs",
                "T1071",
            ),
            (
                "Find all child processes spawned by {value} — look for scripting engines, LOLBins, and unusual binaries",
                "Determine whether this process has been used as a launch pad for further execution.",
                "EDR process creation logs",
                "T1059",
            ),
        ),
    ),
    (
        "parent",
        None,
        (
            (
                "Find all child processes spawned by {value} across all hosts in the last 7 days",
                "{value} spawning unexpected children is often a sign of phishing or exploitation. "
                "Check scope beyond the single observed event.",
                "EDR process creation logs",
                "T1566",
            ),
        ),
    ),
    (
        "user",
        None,
        (
            (
                "Check authentication logs for {value} — source IPs, login times, "
                "logon types (esp. type 3 network, type 10 remote)",
                "If this account is compromised, there will likely be anomalous authentication "
                "activity — logins from unusual IPs or at unusual hours.",
                "Windows Security Event Log (4624, 4625, 4648)",
                "T1078",
            ),
        ),
    ),
    (
        "ip",
        None,
        (
            (
                "Check all hosts that have communicated with {value} in the last 30 days",
                "A C2 or exfil IP is rarely seen by only one host. Lateral scope reveals the true blast radius.",
                "Network firewall / proxy logs",
                "T1041",
            ),
        ),
    ),
    (
        "host",
        "process",
        (
            (
                "Pull a full timeline of activity on {value} for the surrounding 24 hours",
                "Context around the event is essential. What happened immediately before and after?",
                "EDR process and network logs",
                "",
            ),
        ),
    ),
)


def _finding_fields(finding: str) -> Dict[str, str]:
    """Pull the recognised fields out of a JSON finding.

    A non-JSON finding yields nothing, which is what sends the caller to its
    generic fallback pivots.
    """
    if not finding.strip().startswith("{"):
        return {}
    try:
        data = json.loads(finding)
    except json.JSONDecodeError:
        return {}

    found: Dict[str, str] = {}
    for name, aliases in _FIELD_ALIASES.items():
        for key in aliases:
            if key in data:
                found[name] = str(data[key])
                break
    return found


def _pivots_for_finding(finding: str) -> List[PivotSuggestion]:
    """Build the heuristic pivot list from whatever fields the finding names.

    Table-driven rather than a branch per field: the five branches this
    replaced were the same shape five times over, and adding a sixth field
    meant copying the shape again. The rules table is now the thing to edit.
    """
    values = _finding_fields(finding)
    pivots: List[PivotSuggestion] = []

    for name, suppressed_by, templates in _PIVOT_RULES:
        value = values.get(name)
        if not value or (suppressed_by and values.get(suppressed_by)):
            continue
        for query, rationale, data_source, technique_hint in templates:
            pivots.append(
                PivotSuggestion(
                    query=query.format(value=value),
                    rationale=rationale.format(value=value),
                    data_source=data_source,
                    priority=len(pivots) + 1,
                    technique_hint=technique_hint,
                )
            )

    return pivots or _generic_pivots(finding)


def _generic_pivots(finding: str) -> List[PivotSuggestion]:
    """Fallback when the finding names no field this heuristic recognises."""
    return [
        PivotSuggestion(
            query=f"Search across all hosts for events matching: {finding[:120]}",
            rationale="Scope the finding — determine whether this is isolated or widespread.",
            data_source="EDR / SIEM",
            priority=1,
        ),
        PivotSuggestion(
            query="Check network proxy/firewall logs for external connections from the affected host in the surrounding window",
            rationale="Host-side suspicious activity frequently correlates with C2 or exfiltration traffic.",
            data_source="Network logs",
            priority=2,
        ),
        PivotSuggestion(
            query="Review authentication logs for the user or host involved — look for account compromise indicators",
            rationale="Credential abuse often accompanies process-level or network-level anomalies.",
            data_source="Windows Event Logs / identity provider",
            priority=3,
        ),
    ]


class PivotSuggesterAgent(LLMAgent[PivotInput, PivotOutput]):
    """Suggests next pivot queries given a hunt finding.

    Given a suspicious finding (JSON dict, JSON string, or plain text), this agent:
    1. Characterises what the finding represents
    2. Maps it to MITRE ATT&CK techniques
    3. Consults past hunts and environment context
    4. Suggests 3-5 concrete next pivot queries with rationale and priority

    Falls back to deterministic heuristic pivots when LLM is disabled.
    """

    def execute(self, input_data: PivotInput) -> AgentResult[PivotOutput]:
        start = time.monotonic()

        past_hunts = self._load_past_hunts(input_data.finding)
        hunt_context = self._load_hunt_context(input_data.hunt_id)
        environment = self._load_environment()

        if not self.llm_enabled:
            result = self._heuristic_pivots(input_data, past_hunts)
            result.metadata["duration_ms"] = int((time.monotonic() - start) * 1000)
            return result

        try:
            prompt = self._build_prompt(input_data, past_hunts, hunt_context, environment)

            def validate(text: str) -> Optional[str]:
                try:
                    self._parse_json_response(text)
                    return None
                except ValueError as e:
                    return str(e)

            output_text = self._call_llm_with_retry(prompt, validate, max_retries=2, capability="pivot_suggest")
            data = self._parse_json_response(output_text)

            pivots = [
                PivotSuggestion(
                    query=p.get("query", ""),
                    rationale=p.get("rationale", ""),
                    data_source=p.get("data_source", ""),
                    priority=p.get("priority", idx + 1),
                    technique_hint=p.get("technique_hint", ""),
                )
                for idx, p in enumerate(data.get("pivots", []))
            ]

            output = PivotOutput(
                finding_summary=data.get("finding_summary", ""),
                technique_matches=data.get("technique_matches", []),
                pivots=pivots,
                past_hunt_references=data.get("past_hunt_references", []),
            )

            elapsed_ms = int((time.monotonic() - start) * 1000)
            return AgentResult(
                success=True,
                data=output,
                metadata={"duration_ms": elapsed_ms, "past_hunts_loaded": len(past_hunts)},
            )

        except Exception as e:
            return AgentResult(
                success=False,
                data=None,
                error=str(e),
                metadata={"duration_ms": int((time.monotonic() - start) * 1000)},
            )

    # ------------------------------------------------------------------
    # Context loaders
    # ------------------------------------------------------------------

    def _load_past_hunts(self, query: str) -> List[Dict[str, Any]]:
        """Search past hunts relevant to the finding."""
        try:
            from hecate_agent.core.hunt_manager import HuntManager

            manager = HuntManager()
            terms: List[str] = []
            if query.strip().startswith("{"):
                try:
                    parsed = json.loads(query)
                    terms = [str(v) for v in list(parsed.values())[:3] if v]
                except json.JSONDecodeError:
                    terms = [query[:60]]
            else:
                terms = [query[:60]]

            seen: set = set()
            results: List[Dict[str, Any]] = []
            for term in terms:
                if term:
                    for h in manager.search_hunts(term):
                        hid = h.get("hunt_id")
                        if hid and hid not in seen:
                            seen.add(hid)
                            results.append(h)
            return results[:5]
        except Exception:
            return []

    def _load_hunt_context(self, hunt_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """Load specific hunt data if hunt_id was provided."""
        if not hunt_id:
            return None
        try:
            from hecate_agent.core.hunt_manager import HuntManager

            return HuntManager().get_hunt(hunt_id)
        except Exception:
            return None

    def _load_environment(self) -> str:
        """Load knowledge/environment.md if available."""
        return load_environment_context()

    # ------------------------------------------------------------------
    # Prompt builder
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        input_data: PivotInput,
        past_hunts: List[Dict[str, Any]],
        hunt_context: Optional[Dict[str, Any]],
        environment: str,
    ) -> str:
        past_section = ""
        if past_hunts:
            past_section = "\n\nRELATED PAST HUNTS:\n" + "\n".join(
                f"- {h.get('hunt_id')}: {h.get('title')} (status: {h.get('status')})" for h in past_hunts
            )

        hunt_section = ""
        if hunt_context:
            fm = hunt_context.get("frontmatter", {})
            hunt_section = (
                "\n\nCURRENT HUNT CONTEXT:\n"
                f"Hunt: {fm.get('hunt_id')} - {fm.get('title')}\n"
                f"Technique: {', '.join(fm.get('techniques', []))}\n"
                f"Tactic: {', '.join(fm.get('tactics', []))}\n"
                f"Platform: {', '.join(fm.get('platform', []))}"
            )

        env_section = f"\n\nENVIRONMENT:\n{environment}" if environment else ""
        tech_hint = f"\nKnown technique: {input_data.technique}" if input_data.technique else ""

        return (
            "You are an expert threat hunter. A hunter has found something suspicious "
            "and needs your help deciding what to investigate next.\n\n"
            f"EVIDENCE RULES:\n{EVIDENCE_RULES}\n{load_stage_guidance('pivot')}\n\n"
            f"FINDING:\n{input_data.finding}{tech_hint}{hunt_section}{past_section}{env_section}\n\n"
            "Based on this finding, suggest 3-5 concrete next pivot queries or investigation steps. "
            "Each pivot should:\n"
            "1. Be a specific, actionable query (not vague advice like 'investigate further')\n"
            "2. Target a concrete data source\n"
            "3. Explain WHY this pivot is valuable given the finding\n"
            "4. Be ordered by priority (1 = most important first)\n\n"
            "Consider these pivot dimensions:\n"
            "- Scope: Does this process/user/host appear elsewhere? (lateral host scope)\n"
            "- Temporal: What happened before and after this event?\n"
            "- Behavioural: What else did this entity do? (network, files, registry, child processes)\n"
            "- ATT&CK adjacency: What follow-on or precursor techniques typically accompany this?\n\n"
            "Return ONLY a JSON object with this exact structure (no prose before or after):\n"
            "{\n"
            '  "finding_summary": "1-2 sentence characterisation of what the finding represents",\n'
            '  "technique_matches": ["T1059.001"],\n'
            '  "pivots": [\n'
            "    {\n"
            '      "priority": 1,\n'
            '      "query": "specific actionable query or investigation step",\n'
            '      "rationale": "why this pivot is valuable",\n'
            '      "data_source": "e.g. EDR process logs, Windows Event Logs 4624, network proxy",\n'
            '      "technique_hint": "T1059.001"\n'
            "    }\n"
            "  ],\n"
            '  "past_hunt_references": []\n'
            "}"
        )

    # ------------------------------------------------------------------
    # Heuristic fallback (no LLM)
    # ------------------------------------------------------------------

    def _heuristic_pivots(self, input_data: PivotInput, past_hunts: List[Dict[str, Any]]) -> AgentResult[PivotOutput]:
        """Deterministic pivots derived from field names present in the finding."""
        pivots = _pivots_for_finding(input_data.finding)

        past_refs = [str(h["hunt_id"]) for h in past_hunts if h.get("hunt_id")]

        return AgentResult(
            success=True,
            data=PivotOutput(
                finding_summary=f"Finding: {input_data.finding[:200]}",
                technique_matches=[input_data.technique] if input_data.technique else [],
                pivots=pivots,
                past_hunt_references=past_refs,
            ),
            metadata={"mode": "heuristic", "past_hunts_loaded": len(past_hunts)},
        )
