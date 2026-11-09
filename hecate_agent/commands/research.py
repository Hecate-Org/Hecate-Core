"""Research management commands - thorough pre-hunt investigation."""

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from hecate_agent.core.research_manager import ResearchManager

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from datetime import datetime
from hecate_agent.agents.llm.hunt_researcher import ResearchOutput, research_grounding
from hecate_agent.core.cost_tracker import format_cost

console = Console()

RESEARCH_EPILOG = """
\b
Examples:
  # Start new research (15-20 minute deep dive)
  hecate-agent research new --topic "LSASS memory dumping"

  # Quick research (5 minutes)
  hecate-agent research new --topic "Pass-the-Hash" --depth basic

  # Research with specific technique
  hecate-agent research new --topic "Credential Access" --technique T1003.001

  # List all research
  hecate-agent research list

  # View specific research
  hecate-agent research view R-0001

  # Create hunt from research
  hecate-agent hunt new --research R-0001

\b
Research Skills (5-skill methodology):
  1. System Research - How does this technology normally work?
  2. Adversary Tradecraft - How do adversaries abuse it? (web search)
  3. Telemetry Mapping - What OCSF fields capture this?
  4. Related Work - What past hunts are relevant?
  5. Research Synthesis - Key findings, gaps, focus areas
"""


def _write_offline_research_template(
    manager: "ResearchManager",
    research_id: str,
    topic: str,
    technique: Optional[str],
) -> Path:
    """Generate a blank research template file in offline mode."""
    frontmatter = {
        "research_id": research_id,
        "topic": topic,
        "mitre_techniques": [technique] if technique else [],
        "status": "draft",
        "created_date": datetime.now().strftime("%Y-%m-%d"),
    }
    technique_line = f"**MITRE ATT&CK:** {technique}\n" if technique else ""
    content = f"""# {research_id}: {topic} Research

**Topic:** {topic}
{technique_line}
---

## 1. System Research: How It Works

### Summary
<!-- Describe how this system or component functions normally -->

### Key Findings
- <!-- Normal process names, paths, permissions, and architectural details -->

---

## 2. Adversary Tradecraft: Abuse Techniques

### Summary
<!-- Describe how adversaries abuse this technology or feature -->

### Key Findings
- <!-- Attack methods, tools, LOLBins, and evasion techniques -->

---

## 3. Telemetry Mapping

### Telemetry Sources
- <!-- Relevant Event IDs, EDR events, network logs, and OCSF fields -->

---

## 4. Related Work
- <!-- References to past hunts or related research in this workspace -->

---

## 5. Research Synthesis: Actionable Insights
- <!-- Core hypothesis recommendation, data source availability, and hunt scope -->
"""
    return manager.create_research_file(
        research_id=research_id,
        topic=topic,
        content=content,
        frontmatter=frontmatter,
    )


@click.group(epilog=RESEARCH_EPILOG)
def research() -> None:
    """Conduct thorough research before hunting.

    \b
    The research command helps you:
    * Understand normal system behavior
    * Discover adversary tradecraft via web search
    * Map attacks to available telemetry
    * Find related past work
    * Synthesize actionable insights

    \b
    Research creates R-XXXX documents that can be linked to hunts.
    """
    pass


@research.command()
@click.option("--topic", required=True, help="Research topic (e.g., 'LSASS dumping')")
@click.option("--technique", help="MITRE ATT&CK technique (e.g., T1003.001)")
@click.option(
    "--depth",
    type=click.Choice(["basic", "advanced"]),
    default="advanced",
    help="Research depth: basic (5 min) or advanced (15-20 min)",
)
@click.option("--no-web-search", is_flag=True, help="Skip web search (offline mode)")
@click.option("--output", "output_format", type=click.Choice(["table", "json"]), default="table")
def new(
    topic: str,
    technique: Optional[str],
    depth: str,
    no_web_search: bool,
    output_format: str,
) -> None:
    """Create new research document with thorough analysis.

    \b
    Performs 5-skill research methodology:
    1. System Research - How does this normally work?
    2. Adversary Tradecraft - Attack techniques (web search)
    3. Telemetry Mapping - OCSF field mapping
    4. Related Work - Past hunts correlation
    5. Synthesis - Key findings and gaps

    \b
    Examples:
      hecate-agent research new --topic "LSASS dumping"
      hecate-agent research new --topic "Pass-the-Hash" --technique T1003.002 --depth basic
    """
    from hecate_agent.agents.llm.hunt_researcher import HuntResearcherAgent, ResearchInput
    from hecate_agent.core.research_manager import ResearchManager

    # Get next research ID
    manager = ResearchManager()
    research_id = manager.get_next_research_id()

    console.print(f"\n[bold cyan]Starting Research: {research_id}[/bold cyan]")
    console.print(f"[bold]Topic:[/bold] {topic}")
    console.print(f"[bold]Depth:[/bold] {depth} ({'~5 min' if depth == 'basic' else '~15-20 min'})")
    if technique:
        console.print(f"[bold]Technique:[/bold] {technique}")
    console.print()

    # Initialize agent
    agent = HuntResearcherAgent(llm_enabled=True)

    # In unmocked execution, check that an LLM provider is configured
    from unittest.mock import Mock

    if not isinstance(agent, Mock):
        try:
            from hecate_agent.core.llm_provider import create_provider

            create_provider()
        except Exception:
            _write_offline_research_template(manager, research_id, topic, technique)
            console.print(
                f"[yellow]AI features are not configured; you can manually fill in the research template at research/{research_id}.md[/yellow]"
            )
            console.print(
                "[dim]To enable AI-assisted research, configure a provider via:[/dim] [cyan]hecate-agent config ai[/cyan]\n"
            )
            return

    # Show progress for each skill
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Conducting research...", total=None)

        # Execute research
        result = agent.execute(
            ResearchInput(
                topic=topic,
                mitre_technique=technique,
                depth=depth,
                include_past_hunts=True,
                include_telemetry_mapping=True,
                web_search_enabled=not no_web_search,
                # Reuse the ID printed in the banner above rather than letting
                # the agent allocate a second one -- allocation is persistent,
                # so a discarded ID both leaves a gap and makes the banner name
                # a document that is never written.
                research_id=research_id,
            )
        )

    if not result.success:
        err = result.error or ""
        if "no llm provider" in err.lower() or "no provider could be determined" in err.lower():
            _write_offline_research_template(manager, research_id, topic, technique)
            console.print(
                f"[yellow]AI features are not configured; you can manually fill in the research template at research/{research_id}.md[/yellow]"
            )
            console.print(
                "[dim]To enable AI-assisted research, configure a provider via:[/dim] [cyan]hecate-agent config ai[/cyan]\n"
            )
            return

        console.print(f"[red]Research failed: {result.error}[/red]")
        raise click.Abort()

    output = result.data
    if output is None:
        console.print("[red]Research failed: No output data[/red]")
        raise click.Abort()

    # Generate markdown content
    markdown_content = _generate_research_markdown(output)

    # Related-work sources are keyed "hunts/H-XXXX.md" (see
    # HuntResearcherAgent._skill_4_related_work) -- pull the hunt IDs back out
    # so a research doc that found related hunts actually says so in its own
    # frontmatter instead of always reporting linked_hunts: [].
    linked_hunts = []
    for source in output.related_work.sources:
        match = re.match(r"hunts/(H-\d+)\.md$", source.get("url", ""))
        if match:
            linked_hunts.append(match.group(1))

    # Create research file
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
        "threat_actors": [p["id"] for p in getattr(output, "threat_actor_profiles", []) if p.get("id")],
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

    # Display results
    if output_format == "json":
        _display_json_output(output)
    else:
        _display_research_summary(output, file_path)


@research.command(name="list")
@click.option("--status", help="Filter by status (draft, in_progress, completed)")
@click.option("--technique", help="Filter by MITRE technique")
@click.option("--output", "output_format", type=click.Choice(["table", "json"]), default="table")
def list_research(
    status: Optional[str],
    technique: Optional[str],
    output_format: str,
) -> None:
    """List all research documents."""
    from hecate_agent.core.research_manager import ResearchManager

    manager = ResearchManager()
    research_list = manager.list_research(status=status, technique=technique)

    if not research_list:
        console.print("[yellow]No research documents found[/yellow]")
        return

    if output_format == "json":
        console.print(json.dumps(research_list, indent=2), soft_wrap=True)
        return

    # Table output
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Topic", style="white")
    table.add_column("Status", style="yellow")
    table.add_column("Techniques", style="dim")
    table.add_column("Hunts", style="green")
    table.add_column("Cost", style="dim")

    for r in research_list:
        techniques = ", ".join(r.get("mitre_techniques", [])[:2])
        if len(r.get("mitre_techniques", [])) > 2:
            techniques += "..."

        linked_hunts = len(r.get("linked_hunts", []))
        # ResearchManager.list_research() stores total_cost_usd as None (key
        # present, not omitted) for a doc whose frontmatter lacks the field,
        # so `.get(..., 0)`'s default never fires -- `or 0` is needed too,
        # same defensive pattern calculate_stats() already uses for the same
        # field.
        # None (or an older document without the field) is unknown, not free.
        value = r.get("total_cost_usd")
        cost = "n/a" if value is None else f"${value:.3f}"

        table.add_row(
            r.get("research_id", ""),
            r.get("topic", "")[:40],
            r.get("status", ""),
            techniques,
            str(linked_hunts) if linked_hunts > 0 else "-",
            cost,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(research_list)} research documents[/dim]")


@research.command()
@click.argument("research_id")
@click.option("--output", "output_format", type=click.Choice(["markdown", "json"]), default="markdown")
def view(research_id: str, output_format: str) -> None:
    """View a specific research document."""
    from hecate_agent.core.research_manager import ResearchManager

    manager = ResearchManager()
    research_data = manager.get_research(research_id)

    if not research_data:
        console.print(f"[red]Research {research_id} not found[/red]")
        raise click.Abort()

    if output_format == "json":
        console.print(json.dumps(research_data, indent=2, default=str), soft_wrap=True)
        return

    # Display markdown content
    file_path = research_data.get("file_path")
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        console.print(content)
    else:
        console.print("[red]Research file not found[/red]")


@research.command()
@click.argument("research_id")
@click.option("--hunt", "hunt_id", required=True, help="Hunt ID to link (e.g. H-0612)")
def link(research_id: str, hunt_id: str) -> None:
    """Link a hunt to its source research document.

    `hecate-agent hunt new --research R-XXXX` already does this as part of creating a
    hunt. This exposes the same operation on its own, for a caller that
    generated the hunt itself and still owes the research document its
    back-link -- without which a research doc reports linked_hunts: [] even
    though a hunt names it in `spawned_from`.

    Idempotent: linking an already-linked hunt succeeds and changes nothing.
    """
    from hecate_agent.core.research_manager import ResearchManager

    manager = ResearchManager()
    if not manager.link_hunt_to_research(research_id, hunt_id):
        console.print(f"[red]Could not link {hunt_id} to {research_id}[/red] (is the research ID correct?)")
        raise click.Abort()
    console.print(f"[green]Linked {hunt_id} to {research_id}[/green]")


@research.command()
@click.argument("query")
@click.option("--output", "output_format", type=click.Choice(["table", "json"]), default="table")
def search(query: str, output_format: str) -> None:
    """Search across research documents."""
    from hecate_agent.core.research_manager import ResearchManager

    manager = ResearchManager()
    results = manager.search_research(query)

    if not results:
        console.print(f"[yellow]No research documents found matching '{query}'[/yellow]")
        return

    if output_format == "json":
        console.print(json.dumps(results, indent=2), soft_wrap=True)
        return

    # Table output
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Topic", style="white")
    table.add_column("Status", style="yellow")

    for r in results:
        table.add_row(
            r.get("research_id", ""),
            r.get("topic", "")[:50],
            r.get("status", ""),
        )

    console.print(f"\n[bold]Search results for '{query}':[/bold]")
    console.print(table)


@research.command()
@click.option("--output", "output_format", type=click.Choice(["table", "json"]), default="table")
def stats(output_format: str) -> None:
    """Show research program statistics."""
    from hecate_agent.core.research_manager import ResearchManager

    manager = ResearchManager()
    statistics = manager.calculate_stats()

    if output_format == "json":
        console.print(json.dumps(statistics, indent=2), soft_wrap=True)
        return

    # Display stats
    console.print("\n[bold cyan]Research Program Statistics[/bold cyan]")
    console.print(f"Total Research: {statistics['total_research']}")
    console.print(f"Completed: {statistics['completed_research']}")
    unpriced = statistics.get("unpriced_research", 0)
    console.print(
        f"Total Cost: ${statistics['total_cost_usd']:.4f}"
        + (f" ({unpriced} document(s) not priced, not counted)" if unpriced else "")
    )
    console.print(f"Total Duration: {statistics['total_duration_minutes']} min")
    console.print(f"Avg Duration: {statistics['avg_duration_minutes']:.1f} min")
    console.print(f"Linked Hunts: {statistics['total_linked_hunts']}")

    if statistics["by_status"]:
        console.print("\n[bold]By Status:[/bold]")
        for status, count in statistics["by_status"].items():
            console.print(f"  {status}: {count}")


def _generate_research_markdown(output: ResearchOutput) -> str:  # noqa: C901
    """Generate markdown content from research output."""
    lines = []

    # Title
    lines.append(f"# {output.research_id}: {output.topic} Research")
    lines.append("")
    lines.append(f"**Topic:** {output.topic}")
    if output.mitre_techniques:
        lines.append(f"**MITRE ATT&CK:** {', '.join(output.mitre_techniques)}")
    lines.append(f"**Duration:** {output.total_duration_ms / 60000:.1f} minutes")
    lines.append("")
    if research_grounding(output.web_searches_performed) == "source-only":
        reason = f" ({output.web_search_note})" if output.web_search_note else ""
        lines.append(
            f"> **Source-only synthesis{reason}.** No independent web research was performed. "
            "Every finding below restates the source item; nothing here corroborates it."
        )
        lines.append("")
    lines.append("---")
    lines.append("")

    # Skill 1: System Research
    skill = output.system_research
    lines.append("## 1. System Research: How It Works")
    lines.append("")
    lines.append("### Summary")
    lines.append(skill.summary)
    lines.append("")
    lines.append("### Key Findings")
    for finding in skill.key_findings:
        lines.append(f"- {finding}")
    lines.append("")
    if skill.sources:
        lines.append("### Sources")
        for source in skill.sources:
            lines.append(f"- [{source['title']}]({source['url']})")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Skill 2: Adversary Tradecraft
    skill = output.adversary_tradecraft
    lines.append("## 2. Adversary Tradecraft: Attack Techniques")
    lines.append("")
    lines.append("### Summary")
    lines.append(skill.summary)
    lines.append("")
    actor_profiles = getattr(output, "threat_actor_profiles", [])
    if actor_profiles:
        lines.append("### Threat Actor Profiles (MITRE ATT&CK STIX)")
        lines.append("")
        for profile in actor_profiles:
            p_name = profile.get("name", "Unknown Group")
            p_id = profile.get("id", "")
            lines.append(f"#### {p_name} ({p_id})")
            lines.append("")
            aliases = profile.get("aliases", [])
            if aliases:
                lines.append(f"- **Aliases:** {', '.join(aliases)}")
            if profile.get("url"):
                lines.append(f"- **ATT&CK Reference:** [{p_id}]({profile.get('url')})")
            desc = (profile.get("description") or "").strip()
            if desc:
                lines.append(f"- **Profile:** {desc}")
            lines.append("")
            soft = profile.get("software", [])
            if soft:
                lines.append("##### Known Associated Toolkits & Malware")
                for s in soft[:10]:
                    s_desc = f": {s['description']}" if s.get("description") else ""
                    lines.append(f"- **{s.get('name')}** ({s.get('type', 'software').title()} - {s.get('id')}){s_desc}")
                lines.append("")
            techs = profile.get("techniques", [])
            if techs:
                lines.append("##### Key Observed Techniques")
                for t in techs[:15]:
                    lines.append(f"- `{t.get('id')}` - {t.get('name')}")
                lines.append("")
    lines.append("### Key Findings")
    for finding in skill.key_findings:
        lines.append(f"- {finding}")
    lines.append("")
    if skill.sources:
        lines.append("### Sources")
        for source in skill.sources:
            lines.append(f"- [{source['title']}]({source['url']})")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Skill 3: Telemetry Mapping
    skill = output.telemetry_mapping
    lines.append("## 3. Telemetry Mapping: OCSF Fields")
    lines.append("")
    lines.append("### Summary")
    lines.append(skill.summary)
    lines.append("")
    lines.append("### Key Fields")
    lines.append("")
    lines.append("OCSF path → the event field `knowledge/environment.md` documents for it.")
    lines.append("")
    for finding in skill.key_findings:
        lines.append(f"- {finding}")
    removed = getattr(skill, "removed_fields", None) or []
    if removed:
        lines.append("")
        lines.append("### Fields Removed (not in the OCSF reference)")
        lines.append("")
        for name in removed:
            lines.append(f"- {name}")
    lines.append("")
    lines.append("### Data Source Availability")
    lines.append("")
    documented = getattr(output, "data_source_basis", "") != "mapping"
    for data_source, available in output.data_source_availability.items():
        if documented:
            status = (
                "Documented in the environment profile" if available else "Unknown: not documented in the environment profile"
            )
        else:
            status = (
                "Needed by the mapping (no environment profile)" if available else "Not discussed (no environment profile)"
            )
        lines.append(f"- {data_source.replace('_', ' ').title()}: {status}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Skill 4: Related Work
    skill = output.related_work
    lines.append("## 4. Related Work: Past Hunts")
    lines.append("")
    lines.append("### Summary")
    lines.append(skill.summary)
    lines.append("")
    if skill.key_findings:
        lines.append("### Related Hunts")
        for finding in skill.key_findings:
            lines.append(f"- {finding}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Skill 5: Synthesis
    skill = output.synthesis
    lines.append("## 5. Research Synthesis")
    lines.append("")
    lines.append("### Executive Summary")
    lines.append(skill.summary)
    lines.append("")
    if output.recommended_hypothesis:
        lines.append("### Recommended Hypothesis")
        lines.append(f"> {output.recommended_hypothesis}")
        lines.append("")
    if output.gaps_identified:
        lines.append("### Gaps Identified")
        for gap in output.gaps_identified:
            lines.append(f"- {gap}")
        lines.append("")
    lines.append("### Key Findings")
    for finding in skill.key_findings:
        lines.append(f"- {finding}")
    lines.append("")
    lines.append("### Hunt Complexity Assessment")
    lines.append(f"**Estimated Complexity:** {output.estimated_hunt_complexity.title()}")
    lines.append("")

    # Appendix: Cost Tracking
    lines.append("---")
    lines.append("")
    lines.append("## Appendix: Research Metrics")
    lines.append("")
    lines.append(f"- Web Searches: {output.web_searches_performed}")
    lines.append(f"- LLM Calls: {output.llm_calls}")
    input_total = f"{output.input_tokens:,}" if output.input_token_samples in (None, output.llm_calls) else "unavailable"
    output_total = f"{output.output_tokens:,}" if output.output_tokens or not output.llm_calls else "unavailable"
    lines.append(f"- Tokens: {input_total} input, {output_total} output")
    peak = f"{output.max_input_tokens:,}" if output.max_input_tokens is not None else "unavailable"
    coverage = (
        f"{output.input_token_samples}/{output.llm_calls} calls reporting input usage"
        if output.input_token_samples is not None else "reporting coverage unavailable"
    )
    lines.append(f"- Largest Reported Prompt: {peak} tokens ({coverage})")
    lines.append(f"- Total Cost: {format_cost(output.total_cost_usd, output.cost_basis)}")
    lines.append(f"- Duration: {output.total_duration_ms / 1000:.1f} seconds")
    lines.append("")

    return "\n".join(lines)


def _display_research_summary(output: ResearchOutput, file_path: Path) -> None:
    """Display research summary in rich format."""
    # Success panel
    console.print()
    console.print(
        Panel(
            f"[bold green]Research Complete: {output.research_id}[/bold green]\n\n"
            f"[bold]Topic:[/bold] {output.topic}\n"
            f"[bold]Duration:[/bold] {output.total_duration_ms / 1000:.1f} seconds\n"
            f"[bold]Cost:[/bold] {format_cost(output.total_cost_usd, output.cost_basis)}\n"
            f"[bold]File:[/bold] {file_path}",
            title="Research Complete",
            border_style="green",
        )
    )

    # Summary of findings
    console.print("\n[bold cyan]Key Findings Summary[/bold cyan]")

    # System Research
    console.print(f"\n[bold]1. System Research:[/bold] {output.system_research.summary[:100]}...")

    # Adversary Tradecraft
    console.print(f"\n[bold]2. Adversary Tradecraft:[/bold] {output.adversary_tradecraft.summary[:100]}...")

    # Recommended Hypothesis
    if output.recommended_hypothesis:
        console.print("\n[bold green]Recommended Hypothesis:[/bold green]")
        console.print(f"  {output.recommended_hypothesis}")

    # Gaps
    if output.gaps_identified:
        console.print("\n[bold yellow]Gaps Identified:[/bold yellow]")
        for gap in output.gaps_identified[:3]:
            console.print(f"  - {gap}")

    # Next steps
    console.print("\n[bold]Next Steps:[/bold]")
    console.print(f"  1. Review full research: hecate-agent research view {output.research_id}")
    console.print("  2. Generate hypothesis: hecate-agent agent run hypothesis-generator")
    console.print(f"  3. Create hunt: hecate-agent hunt new --research {output.research_id}")


def _display_json_output(output: ResearchOutput) -> None:
    """Display research output as JSON."""
    data = {
        "research_id": output.research_id,
        "topic": output.topic,
        "mitre_techniques": output.mitre_techniques,
        "system_research": {
            "summary": output.system_research.summary,
            "key_findings": output.system_research.key_findings,
            "sources": output.system_research.sources,
        },
        "adversary_tradecraft": {
            "summary": output.adversary_tradecraft.summary,
            "key_findings": output.adversary_tradecraft.key_findings,
            "sources": output.adversary_tradecraft.sources,
        },
        "telemetry_mapping": {
            "summary": output.telemetry_mapping.summary,
            "key_findings": output.telemetry_mapping.key_findings,
        },
        "related_work": {
            "summary": output.related_work.summary,
            "key_findings": output.related_work.key_findings,
            "sources": output.related_work.sources,
        },
        "synthesis": {
            "summary": output.synthesis.summary,
            "key_findings": output.synthesis.key_findings,
        },
        "recommended_hypothesis": output.recommended_hypothesis,
        "data_source_availability": output.data_source_availability,
        "estimated_hunt_complexity": output.estimated_hunt_complexity,
        "gaps_identified": output.gaps_identified,
        "metrics": {
            "duration_ms": output.total_duration_ms,
            "web_searches": output.web_searches_performed,
            "grounding": research_grounding(output.web_searches_performed),
            **({"web_search_note": output.web_search_note} if output.web_search_note else {}),
            "llm_calls": output.llm_calls,
            "input_tokens": output.input_tokens if output.input_token_samples in (None, output.llm_calls) else None,
            "output_tokens": output.output_tokens,
            "max_input_tokens": output.max_input_tokens,
            "input_token_samples": output.input_token_samples,
            "cost_usd": output.total_cost_usd,
            "cost_basis": output.cost_basis,
        },
    }
    console.print(json.dumps(data, indent=2), soft_wrap=True)
