"""AI agent MCP tools (hypothesis generation, research)."""

import logging
from typing import Optional

from hecate_agent.core.envelope import build_envelope
from hecate_agent.mcp.server import _json_result, get_workspace

logger = logging.getLogger(__name__)


# noqa C901: mccabe folds every nested @mcp.tool body into this
# function's score, so the number tracks how many tools are registered
# rather than how branchy the registration is. There is no control flow
# here to simplify -- splitting it would lower the metric and nothing else.
def register_agent_tools(mcp: "FastMCP") -> None:  # type: ignore[name-defined]  # noqa: F821, C901
    """Register AI agent MCP tools."""

    @mcp.tool(
        name="hecate_agent_run_hypothesis",
        description=(
            "Generate a threat hunting hypothesis from threat intelligence. "
            "Uses an LLM to produce a structured hypothesis with MITRE techniques, "
            "data sources, and ABLE framework scoping. "
            "When research_id is supplied, the hypothesis is appended to that "
            "research document (R-XXXX) under a ## Generated Hypothesis section "
            "and the response shrinks to a preview-only payload (id, file_path, "
            "techniques, sources, ~200-char preview) to keep agent context lean. "
            "Without research_id, behavior is unchanged: the full hypothesis is "
            "returned inline. Requires an LLM provider (falls back to "
            "template-based output without one)."
        ),
    )
    def agent_run_hypothesis(
        threat_intel: str,
        research_id: Optional[str] = None,
        use_llm: bool = True,
    ) -> str:
        from hecate_agent.agents.llm.hypothesis_generator import HypothesisGenerationInput, HypothesisGeneratorAgent
        from hecate_agent.core.research_manager import ResearchManager

        workspace = get_workspace()

        rm = ResearchManager(research_dir=workspace / "research")

        # Load research context if provided
        research = None
        if research_id:
            doc = rm.get_research(research_id)
            if doc:
                research = rm.extract_research_context(doc)

        # Load past hunts and environment context from workspace
        from hecate_agent.core.hunt_manager import HuntManager

        manager = HuntManager(hunts_dir=workspace / "hunts")
        past_hunts = manager.list_hunts()

        from hecate_agent.core.hunting_knowledge import load_environment_context

        environment = {"environment_md": load_environment_context(workspace=workspace)}

        agent = HypothesisGeneratorAgent(llm_enabled=use_llm)
        input_data = HypothesisGenerationInput(
            threat_intel=threat_intel,
            past_hunts=past_hunts,
            environment=environment,
            research=research,
            workspace=workspace,
        )

        result = agent.execute(input_data)
        if not result.success:
            return _json_result({"error": result.error or "Hypothesis generation failed"})

        output = result.data
        if output is None:
            return _json_result({"error": "No output from hypothesis generator"})

        if research_id and research is not None:
            file_path = rm.append_hypothesis(
                research_id=research_id,
                hypothesis=output.hypothesis,
                mitre_techniques=output.mitre_techniques,
                data_sources=output.data_sources,
                justification=output.justification,
                expected_observables=output.expected_observables,
                known_false_positives=output.known_false_positives,
                time_range_suggestion=output.time_range_suggestion,
            )

            if file_path is not None:
                preview = output.hypothesis.strip()
                if len(preview) > 200:
                    preview = preview[:197].rstrip() + "..."

                envelope = build_envelope(
                    payload=output.hypothesis,
                    parent_artifact=research_id,
                    path=str(file_path),
                    preview=preview,
                    metadata=result.metadata,
                )

                # Existing PR #30 shape (research_id, file_path, hypothesis_preview,
                # mitre_techniques, data_sources, persisted, metadata) is preserved
                # verbatim; the contract's core fields (preview, path, persisted,
                # byte_count, metadata) are layered on as a superset. Existing
                # consumers reading file_path/hypothesis_preview keep working;
                # contract-aware consumers read path/preview.
                return _json_result(
                    {
                        "research_id": research_id,
                        "file_path": str(file_path),
                        "hypothesis_preview": preview,
                        "mitre_techniques": output.mitre_techniques,
                        "data_sources": output.data_sources,
                        "persisted": True,
                        "preview": envelope["preview"],
                        "path": envelope["path"],
                        "byte_count": envelope["byte_count"],
                        "metadata": result.metadata,
                    }
                )

            return _json_result(
                {
                    "research_id": research_id,
                    "persisted": False,
                    "error": "persistence_failed",
                    "mitre_techniques": output.mitre_techniques,
                    "data_sources": output.data_sources,
                    "metadata": result.metadata,
                }
            )

        return _json_result(
            {
                "hypothesis": output.hypothesis,
                "mitre_techniques": output.mitre_techniques,
                "data_sources": output.data_sources,
                "justification": output.justification,
                "persisted": False,
                "metadata": result.metadata,
            }
        )

    @mcp.tool(
        name="hecate_agent_run_researcher",
        description=(
            "Conduct deep pre-hunt research on a topic using the 5-skill methodology: "
            "System Internals, Adversary Tradecraft, Telemetry Mapping, Historical Analysis, "
            "and Synthesis. Uses web search (Tavily) and LLM analysis. "
            "Creates a research document (R-XXXX.md) in the workspace."
        ),
    )
    def agent_run_researcher(
        topic: str,
        technique: Optional[str] = None,
        depth: str = "advanced",
        use_web_search: bool = True,
        use_llm: bool = True,
    ) -> str:
        import os

        from hecate_agent.agents.llm.hunt_researcher import HuntResearcherAgent, ResearchInput

        workspace = get_workspace()

        tavily_key = os.environ.get("TAVILY_API_KEY") if use_web_search else None

        agent = HuntResearcherAgent(llm_enabled=use_llm, tavily_api_key=tavily_key)
        input_data = ResearchInput(
            topic=topic,
            mitre_technique=technique,
            depth=depth,
            web_search_enabled=use_web_search,
        )

        result = agent.execute(input_data)
        if not result.success:
            return _json_result({"error": result.error or "Research failed"})

        output = result.data
        if output is None:
            return _json_result({"error": "No output from researcher"})

        # Build a report from the skill outputs
        report_parts = [
            f"# {topic} Research\n",
            f"## System Research\n{output.system_research.summary}\n",
            f"## Adversary Tradecraft\n{output.adversary_tradecraft.summary}\n",
            f"## Telemetry Mapping\n{output.telemetry_mapping.summary}\n",
            f"## Related Work\n{output.related_work.summary}\n",
            f"## Synthesis\n{output.synthesis.summary}\n",
        ]
        if output.recommended_hypothesis:
            report_parts.append(f"## Recommended Hypothesis\n{output.recommended_hypothesis}\n")

        full_report = "\n".join(report_parts)

        # Save research file — use agent's research_id if available, else generate
        from hecate_agent.core.research_manager import ResearchManager

        rm = ResearchManager(research_dir=workspace / "research")
        rid = getattr(output, "research_id", None) or rm.get_next_research_id()

        frontmatter = {
            "research_id": rid,
            "title": f"{topic} Research",
            "topic": topic,
            "technique": technique or "",
            "depth": depth,
            "status": "completed",
        }

        file_path = rm.create_research_file(
            research_id=rid,
            topic=topic,
            content=full_report,
            frontmatter=frontmatter,
        )

        return _json_result(
            {
                "research_id": rid,
                "file_path": str(file_path),
                "topic": topic,
                "depth": depth,
                "recommended_hypothesis": output.recommended_hypothesis,
                "gaps_identified": output.gaps_identified,
                "metadata": result.metadata,
            }
        )
