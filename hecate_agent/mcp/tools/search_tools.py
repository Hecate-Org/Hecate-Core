"""Search and context MCP tools (similar, context)."""

import logging
from typing import Any, Dict, Optional

from hecate_agent.mcp.server import _json_result, get_workspace

logger = logging.getLogger(__name__)


# noqa C901: mccabe folds every nested @mcp.tool body into this
# function's score, so the number tracks how many tools are registered
# rather than how branchy the registration is. There is no control flow
# here to simplify -- splitting it would lower the metric and nothing else.
def register_search_tools(mcp: "FastMCP") -> None:  # type: ignore[name-defined]  # noqa: F821, C901
    """Register search-related MCP tools."""

    @mcp.tool(
        name="hecate_similar",
        description=(
            "Find hunts semantically similar to a query or to an existing hunt. "
            "Uses TF-IDF + cosine similarity. Scores: >=0.50 very similar, "
            "0.30-0.49 related, <0.30 weak match. "
            "IMPORTANT: Use this before creating new hunts to avoid duplicates."
        ),
    )
    def similar(
        query: Optional[str] = None,
        hunt_id: Optional[str] = None,
        limit: int = 10,
        threshold: float = 0.1,
    ) -> str:
        if not query and not hunt_id:
            return _json_result({"error": "Provide either 'query' text or 'hunt_id' to search."})

        # Delegates to the same TF-IDF similarity search `hecate-agent similar` (the
        # CLI) and the hunt-researcher agent's related-work skill both use,
        # rather than maintaining a second, independently-drifted
        # implementation here. The version that used to live in this file
        # directly was missing session-text folding (a hunt's linked session
        # decisions/findings, which the canonical version weights into the
        # corpus) and never excluded the query hunt itself from its own
        # corpus when searching by hunt_id -- trivially matching itself at
        # ~1.0 similarity and crowding out real matches.
        #
        # Passes workspace explicitly rather than os.chdir()-ing into it for
        # the call's duration: chdir is process-wide, and if this server
        # ever runs sync tool calls on separate threads (as e.g. FastMCP's
        # asyncio.to_thread dispatch would), two concurrent hecate_similar
        # calls chdir-ing into place could race each other's cwd.
        workspace = get_workspace()
        from hecate_agent.commands.similar import (
            SimilarityUnavailable,
            _find_similar_hunts,
            _get_hunt_text,
        )

        if hunt_id:
            query_text = _get_hunt_text(hunt_id, workspace=workspace)
            if query_text is None:
                return _json_result({"error": f"Hunt not found: {hunt_id}"})
        else:
            query_text = query or ""

        try:
            results = _find_similar_hunts(
                query_text,
                limit=limit,
                threshold=threshold,
                exclude_hunt=hunt_id,
                workspace=workspace,
            )
        except SimilarityUnavailable as exc:
            # A missing optional dependency degrades to a normal JSON error
            # response here rather than escaping as an exception with no
            # meaning outside a Click app.
            return _json_result({"error": str(exc)})

        return _json_result({"count": len(results), "results": results})

    @mcp.tool(
        name="hecate_context",
        description=(
            "Load AI-optimized context bundle for a hunt, tactic, or platform. "
            "Combines environment.md, past hunts, and domain knowledge into one structured output. "
            "Use this before generating queries or hypotheses to reduce context-loading overhead."
        ),
    )
    def context(
        hunt_id: Optional[str] = None,
        tactic: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> str:
        if not hunt_id and not tactic and not platform:
            return _json_result({"error": "Provide at least one filter: hunt_id, tactic, or platform."})

        workspace = get_workspace()
        result: Dict[str, Any] = {}

        # Load environment.md
        env_file = workspace / "knowledge" / "environment.md"
        if env_file.exists():
            result["environment"] = env_file.read_text(encoding="utf-8")

        # Load hunts matching filters
        from hecate_agent.core.hunt_manager import HuntManager

        manager = HuntManager(hunts_dir=workspace / "hunts")

        if hunt_id:
            hunt = manager.get_hunt(hunt_id)
            if hunt:
                result["hunt"] = hunt
            else:
                result["hunt_error"] = f"Hunt not found: {hunt_id}"
        else:
            hunts = manager.list_hunts(tactic=tactic, platform=platform)
            result["hunts"] = hunts
            result["hunt_count"] = len(hunts)

        # Load domain knowledge if tactic specified. Reuses the CLI's own
        # tactic->file mapping (hecate-agent context --tactic ...) rather than
        # maintaining a second implementation here -- the substring match
        # this used to do (`tactic.replace("-", " ") in f.stem.replace("-", " ")`)
        # never actually matched anything for a real tactic against this
        # project's documented domain-file naming convention (e.g.
        # "credential access" is never a substring of "iam-security"), so it
        # silently returned no domain_knowledge for every real call -- a
        # second, correct implementation already existed in
        # hecate_agent/commands/context.py and had simply drifted out of sync.
        if tactic:
            from hecate_agent.commands.context import _get_relevant_domain_files

            for domain_file in _get_relevant_domain_files(tactic, workspace=workspace):
                if domain_file.exists() and domain_file.name != "hunting-knowledge.md":
                    result.setdefault("domain_knowledge", {})[domain_file.stem] = domain_file.read_text(encoding="utf-8")

        return _json_result(result)
