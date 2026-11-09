"""Agent management commands."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
from rich.console import Console

from hecate_agent.core.cost_tracker import format_cost

# soft_wrap=True: this file's human-readable agent output (bulleted
# techniques/observables/false-positives, prose fields) is line-parsed by
# downstream consumers like hecate-runner's HecateClient. Without it, rich's
# default wrap at the fallback 80-column width (there's no real TTY under a
# captured subprocess) silently truncates long bullets — the parser only
# recognises a new bullet, so the wrapped continuation line is dropped
# rather than appended. Matches the same soft_wrap=True already used for
# research.py's --output json path, same reasoning.
console = Console(soft_wrap=True)

# Single source of truth for agent metadata.  Add an entry here when a new
# agent is added to hecate_agent.agents.llm — the list/info/run commands below all
# derive their output from this dict.
_AGENT_REGISTRY: Dict[str, dict] = {
    "hypothesis-generator": {
        "type": "LLM (auto-detect)",
        "description": "Generates creative hunt hypotheses using threat intelligence",
        "capabilities": [
            "LOCK format generation",
            "ATT&CK mapping",
            "Environment validation",
            "Past hunt deduplication",
            "Fallback to template generation",
            "Cost tracking",
            "Multi-provider support (Claude, GPT, Gemini, Ollama)",
        ],
        "usage": [
            'hecate-agent agent run hypothesis-generator --threat-intel "APT29 targeting SaaS"',
            'hecate-agent agent run hypothesis-generator --threat-intel "..." --research R-0001',
        ],
    },
    "sigma-generator": {
        "type": "LLM (auto-detect)",
        "description": "Drafts portable Sigma detection rules for a hunt, before operator review",
        "capabilities": [
            "One rule per applicable Sigma log source",
            "Log sources derived from ATT&CK techniques + CTI indicator types",
            "Grounds rules in the concrete indicators the CTI carried",
            "Model emits JSON; YAML is rendered here, so malformed rules are impossible",
            "Rejects rules whose condition names an undefined selection",
            "Multi-provider support (Claude, GPT, Gemini, Ollama)",
        ],
        "usage": [
            "hecate-agent agent run sigma-generator --input-json in.json --out-dir queries/H-0612",
        ],
    },
    "pivot-suggester": {
        "type": "LLM (auto-detect)",
        "description": "Suggests next pivot queries given a suspicious finding",
        "capabilities": [
            "Finding characterisation and ATT&CK technique mapping",
            "3-5 prioritised, actionable next pivot queries",
            "Rationale grounded in adversary behaviour patterns",
            "Past hunt cross-reference via full-text search",
            "Environment context from knowledge/environment.md",
            "Heuristic fallback mode (no LLM required)",
            "Multi-provider support (Claude, GPT, Gemini, Ollama)",
        ],
        "usage": [
            'hecate-agent agent run pivot-suggester --finding \'{"process": "powershell.exe", "parent": "winword.exe"}\'',
            'hecate-agent agent run pivot-suggester --finding "suspicious outbound DNS to rare domain" --hunt H-0042',
            'hecate-agent agent run pivot-suggester --finding \'{"user": "svc_backup", "dst_ip": "10.0.0.99"}\' --technique T1078',
            "hecate-agent agent run pivot-suggester --finding '...' --no-llm  # offline heuristic mode",
        ],
    },
    "hunt-researcher": {
        "type": "LLM (auto-detect)",
        "description": "Conducts thorough pre-hunt research using 5-skill methodology",
        "capabilities": [
            "System internals research (how it normally works)",
            "Adversary tradecraft research via web search",
            "Telemetry mapping to OCSF fields",
            "Related past hunt discovery",
            "Research synthesis with gaps identification",
            "Recommended hypothesis generation",
            "Cost tracking and metrics",
        ],
        "research_skills": [
            "1. System Research - How technology normally works",
            "2. Adversary Tradecraft - Attack techniques (web search)",
            "3. Telemetry Mapping - OCSF field availability",
            "4. Related Work - Past hunt correlation",
            "5. Synthesis - Key findings and gaps",
        ],
        "usage": [
            'hecate-agent agent run hunt-researcher --topic "LSASS dumping"',
            'hecate-agent agent run hunt-researcher --topic "Pass-the-Hash" --technique T1003.002 --depth basic',
        ],
    },
}

AGENT_EPILOG = """
\b
Examples:
  # List all available agents
  hecate-agent agent list

  # Get information about an agent
  hecate-agent agent info hypothesis-generator

  # Run hypothesis generator agent
  hecate-agent agent run hypothesis-generator --threat-intel "APT29 targeting SaaS applications"

\b
Agent Types:
  • LLM Agents - AI-powered agents (supports Claude, GPT, Gemini, Ollama, etc.)

\b
Why Agents:
  • Standardized interfaces for hunt operations
  • Composable building blocks for workflows
  • Consistent error handling and result formats
  • Foundation for AI orchestration
"""


@click.group(epilog=AGENT_EPILOG)
def agent() -> None:
    """Manage Hecate agents.

    Agents provide modular capabilities for threat hunting operations.
    LLM agents support multiple providers (Claude, GPT, Gemini, Ollama, etc.).

    \b
    Agent Execution Mode:
    • INTERACTIVE (default): Step-by-step execution with user approval
    """
    pass


@agent.command()
def list() -> None:
    """List all available agents.

    Displays registered agents with their type, status, and description.
    """
    from rich.table import Table

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Agent Name", style="cyan", no_wrap=True)
    table.add_column("Type", style="yellow", no_wrap=True, width=15)
    table.add_column("Status", style="green", no_wrap=True, width=12)
    table.add_column("Description", style="white")

    for name, meta in _AGENT_REGISTRY.items():
        table.add_row(name, meta["type"], "✅ available", meta["description"])

    console.print("\n[bold]Available Agents:[/bold]\n")
    console.print(table)
    console.print()


@agent.command()
@click.argument("agent_name")
def info(agent_name: str) -> None:
    """Show detailed information about an agent.

    \b
    Example:
      hecate-agent agent info hypothesis-generator
      hecate-agent agent info hunt-researcher
    """
    meta = _AGENT_REGISTRY.get(agent_name)
    if meta is None:
        console.print(f"[red]Error: Agent '{agent_name}' not found[/red]")
        console.print("\n[dim]Available agents:[/dim]")
        for name in _AGENT_REGISTRY:
            console.print(f"  • {name}")
        raise click.Abort()

    console.print(f"\n[bold cyan]Agent:[/bold cyan] {agent_name}")
    console.print(f"[bold]Type:[/bold] {meta['type']}")
    console.print("[bold]Status:[/bold] available")
    console.print(f"\n[bold]Description:[/bold]\n  {meta['description']}")

    console.print("\n[bold]Capabilities:[/bold]")
    for cap in meta["capabilities"]:
        console.print(f"  • {cap}")

    if "research_skills" in meta:
        console.print("\n[bold]Research Skills:[/bold]")
        for skill in meta["research_skills"]:
            console.print(f"  {skill}")

    console.print("\n[bold]Usage:[/bold]")
    for example in meta["usage"]:
        console.print(f"  {example}")
    console.print()


def _run_sigma_generator(
    input_json: Optional[str],
    out_dir: Optional[str],
    hunt_id: Optional[str],
    llm: bool,
    output_format: str,
) -> None:
    """Generate Sigma rules and, when asked, write them to disk.

    Rules are written as separate files rather than inlined into the hunt so
    they stay convertible: `sigma convert` takes a path, and an operator who
    edits one during review is editing the artifact itself, not a copy that
    has to be synced back.
    """
    import json as _json

    from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent

    if not input_json:
        console.print("[red]Error: --input-json required for sigma-generator[/red]")
        raise click.Abort()

    payload = _json.loads(Path(input_json).read_text())
    known = set(SigmaGenerationInput.__dataclass_fields__)
    agent_input = SigmaGenerationInput(**{k: v for k, v in payload.items() if k in known})
    if hunt_id and not agent_input.hunt_id:
        agent_input.hunt_id = hunt_id

    result = SigmaGeneratorAgent(llm_enabled=llm).execute(agent_input)

    written: List[str] = []
    if result.data and out_dir:
        target = Path(out_dir)
        target.mkdir(parents=True, exist_ok=True)
        from hecate_agent.agents.llm.sigma_generator import rule_filenames

        for rule, filename in zip(result.data.rules, rule_filenames(result.data.rules)):
            path = target / filename
            path.write_text(rule.rule_yaml)
            written.append(str(path))

    if output_format == "json":
        console.print_json(
            _json.dumps(
                {
                    "success": result.success,
                    "error": result.error,
                    "warnings": result.warnings,
                    "logsources_considered": result.data.logsources_considered if result.data else [],
                    "rejected": result.data.rejected if result.data else [],
                    "files": written,
                    "rules": [
                        {
                            "logsource_category": r.logsource_category,
                            "title": r.title,
                            "level": r.level,
                            "techniques": r.techniques,
                            "rule_yaml": r.rule_yaml,
                        }
                        for r in (result.data.rules if result.data else [])
                    ],
                }
            )
        )
        return

    if not result.success or result.data is None:
        console.print(f"[red]Sigma generation failed:[/red] {result.error}")
        raise click.Abort()

    console.print(f"[green]Generated {len(result.data.rules)} Sigma rule(s)[/green]")
    for rule in result.data.rules:
        console.print(f"  [{rule.level}] {rule.logsource_category}: {rule.title}")
    for written_path in written:
        console.print(f"  wrote {written_path}")
    for warning in result.warnings:
        console.print(f"  [yellow]! {warning}[/yellow]")


@agent.command()
@click.argument("agent_name")
@click.option("--threat-intel", help="Threat intelligence context (for hypothesis-generator)")
@click.option("--research", help="Research document ID (e.g., R-0001) to load context from")
@click.option("--topic", help="Research topic (for hunt-researcher)")
@click.option("--technique", help="MITRE ATT&CK technique (for hunt-researcher / pivot-suggester)")
@click.option(
    "--depth",
    type=click.Choice(["basic", "advanced"]),
    default="advanced",
    help="Research depth: basic (5 min) or advanced (15-20 min) (for hunt-researcher)",
)
@click.option("--no-web-search", is_flag=True, help="Skip web search - offline mode (for hunt-researcher)")
@click.option(
    "--indicators-only",
    is_flag=True,
    help=(
        "Threat intel is a bare indicator list with no narrative (e.g. a "
        "ThreatFox/Maltrail feed dump) - keeps the hypothesis to indicator "
        "presence instead of inferring delivery, actor or technique "
        "(for hypothesis-generator)"
    ),
)
@click.option("--tactic", help="MITRE tactic filter")
@click.option("--finding", help="Suspicious finding as JSON or plain text (for pivot-suggester)")
@click.option("--hunt", "hunt_id", help="Current hunt ID for context (for pivot-suggester)")
@click.option(
    "--input-json",
    "input_json",
    type=click.Path(exists=True, dir_okay=False),
    help=(
        "Path to a JSON file of SigmaGenerationInput fields (hypothesis, "
        "techniques, indicators, platforms, references) (for sigma-generator). "
        "A file rather than a dozen flags because the indicator map is nested "
        "and can be long."
    ),
)
@click.option(
    "--out-dir",
    "out_dir",
    type=click.Path(file_okay=False),
    help="Directory to write generated .yml rules into (for sigma-generator)",
)
@click.option("--llm/--no-llm", default=True, help="Enable/disable LLM (default: enabled)")
@click.option(
    "--output-format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def run(  # noqa: C901
    agent_name: str,
    threat_intel: Optional[str],
    research: Optional[str],
    topic: Optional[str],
    technique: Optional[str],
    depth: str,
    no_web_search: bool,
    indicators_only: bool,
    tactic: Optional[str],
    finding: Optional[str],
    hunt_id: Optional[str],
    input_json: Optional[str],
    out_dir: Optional[str],
    llm: bool,
    output_format: str,
) -> None:
    """Run an agent.

    LLM agents auto-detect your provider (Claude, GPT, Gemini, Ollama). Use --no-llm for fallback mode.

    \b
    Examples:
      # Hypothesis Generator
      hecate-agent agent run hypothesis-generator --threat-intel "APT29 targeting SaaS applications"
      hecate-agent agent run hypothesis-generator --threat-intel "Insider threat data exfiltration" --tactic collection
      hecate-agent agent run hypothesis-generator --threat-intel "Credential dumping" --research R-0001

      # Hunt Researcher
      hecate-agent agent run hunt-researcher --topic "LSASS dumping"
      hecate-agent agent run hunt-researcher --topic "Pass-the-Hash" --technique T1003.002 --depth basic
      hecate-agent agent run hunt-researcher --topic "Credential Access" --no-web-search

      # Fallback mode (no LLM)
      hecate-agent agent run hypothesis-generator --threat-intel "..." --no-llm
    """
    if agent_name == "sigma-generator":
        _run_sigma_generator(input_json, out_dir, hunt_id, llm, output_format)
        return

    if agent_name == "hypothesis-generator":
        if not threat_intel:
            console.print("[red]Error: --threat-intel required for hypothesis-generator[/red]")
            raise click.Abort()

        try:
            # Import LLM agents
            from hecate_agent.agents.llm import HypothesisGenerationInput, HypothesisGeneratorAgent

            hypothesis_agent = HypothesisGeneratorAgent(llm_enabled=llm)

            # Load context for hypothesis generation
            # Try to load past hunts and environment data if available
            past_hunts: List[dict[str, Any]] = []
            environment = {}
            research_ctx = None

            # Load research context (explicit ID or auto-discover by technique)
            try:
                from pathlib import Path

                from hecate_agent.core.research_manager import ResearchManager

                research_mgr = ResearchManager(Path.cwd())

                if research:
                    research_doc = research_mgr.get_research(research)
                    if research_doc:
                        research_ctx = research_mgr.extract_research_context(research_doc)
                        console.print(f"[green]✓ Loaded research context from {research}[/green]\n")
                    else:
                        console.print(f"[yellow]⚠ Research document {research} not found[/yellow]\n")
                elif technique:
                    research_doc = research_mgr.find_by_technique(technique)
                    if research_doc:
                        rid = research_doc.get("frontmatter", {}).get("research_id", technique)
                        research_ctx = research_mgr.extract_research_context(research_doc)
                        console.print(f"[green]✓ Auto-discovered research {rid} for {technique}[/green]\n")
            except Exception as e:
                console.print(f"[yellow]⚠ Could not load research context: {e}[/yellow]\n")

            # Load environment.md content if it exists
            try:
                from hecate_agent.core.hunting_knowledge import load_environment_context

                environment = {"environment_md": load_environment_context()}
            except Exception:
                environment = {}

            # Execute agent
            hypothesis_result = hypothesis_agent.execute(
                HypothesisGenerationInput(
                    threat_intel=threat_intel,
                    past_hunts=past_hunts,
                    environment=environment,
                    research=research_ctx,
                    intel_is_indicator_only=indicators_only,
                )
            )

            # Extract and display duration
            duration_ms = hypothesis_result.metadata.get("duration_ms", 0)
            duration_min = round(duration_ms / 60000, 1)

            if output_format == "json":
                console.print(json.dumps(hypothesis_result.metadata, indent=2), soft_wrap=True)
            else:
                _display_hypothesis_generator_result(hypothesis_result)
                if duration_ms > 0:
                    # stderr, not stdout: this is an interactive-use hint, not
                    # part of the structured output. A caller line-parsing
                    # stdout for the ABLE fields above (Evidence is the last
                    # section _display_hypothesis_generator_result prints, and
                    # its prose accumulator has no way to know where the
                    # section actually ends other than the next recognized
                    # header) would otherwise have this text silently
                    # appended onto Evidence's value.
                    hint_console = Console(stderr=True)
                    hint_console.print(f"[dim]Hypothesis generated in {duration_min} minutes[/dim]")
                    hint_console.print(f"[dim]Use: hecate-agent hunt new --hypothesis-duration {duration_min} ...[/dim]\n")

        except ImportError as e:
            console.print(f"[red]Error loading agent: {e}[/red]")
            console.print("\n[dim]Install an LLM provider:[/dim]")
            console.print(r"  pip install -e '.\[litellm]'   # All providers via LiteLLM")
            console.print(r"  pip install -e '.\[openai]'    # OpenAI/GPT")
            console.print(r"  pip install -e '.\[bedrock]'   # AWS Bedrock")
            raise click.Abort()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            raise click.Abort()

    elif agent_name == "hunt-researcher":
        if not topic:
            console.print("[red]Error: --topic required for hunt-researcher[/red]")
            raise click.Abort()

        try:
            from rich.progress import Progress, SpinnerColumn, TextColumn

            from hecate_agent.agents.llm.hunt_researcher import HuntResearcherAgent, ResearchInput

            console.print("\n[bold cyan]Starting Research[/bold cyan]")
            console.print(f"[bold]Topic:[/bold] {topic}")
            console.print(f"[bold]Depth:[/bold] {depth} ({'~5 min' if depth == 'basic' else '~15-20 min'})")
            if technique:
                console.print(f"[bold]Technique:[/bold] {technique}")
            console.print()

            research_agent = HuntResearcherAgent(llm_enabled=llm)

            # Show progress
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task("Conducting research...", total=None)

                research_result = research_agent.execute(
                    ResearchInput(
                        topic=topic,
                        mitre_technique=technique,
                        depth=depth,
                        include_past_hunts=True,
                        include_telemetry_mapping=True,
                        web_search_enabled=not no_web_search,
                    )
                )

            if not research_result.is_success:
                console.print(f"[red]✗ Research failed: {research_result.error}[/red]")
                raise click.Abort()

            if output_format == "json":
                console.print(json.dumps(research_result.metadata, indent=2), soft_wrap=True)
            else:
                _display_research_result(research_result)

        except ImportError as e:
            console.print(f"[red]Error loading agent: {e}[/red]")
            console.print("\n[dim]Install an LLM provider:[/dim]")
            console.print(r"  pip install -e '.\[litellm]'   # All providers via LiteLLM")
            console.print("  pip install tavily-python      # Web search (optional)")
            raise click.Abort()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            raise click.Abort()

    elif agent_name == "pivot-suggester":
        if not finding:
            console.print("[red]Error: --finding required for pivot-suggester[/red]")
            console.print('[dim]Example: --finding \'{"process": "powershell.exe", "parent": "winword.exe"}\'[/dim]')
            raise click.Abort()

        try:
            from hecate_agent.agents.llm.pivot_suggester import PivotInput, PivotSuggesterAgent

            agent_instance = PivotSuggesterAgent(llm_enabled=llm)
            result = agent_instance.execute(
                PivotInput(
                    finding=finding,
                    hunt_id=hunt_id,
                    technique=technique,
                )
            )

            if not result.is_success or result.data is None:
                console.print(f"[red]Error: {result.error}[/red]")
                raise click.Abort()

            if output_format == "json":
                import dataclasses

                console.print(json.dumps(dataclasses.asdict(result.data), indent=2), soft_wrap=True)
            else:
                _display_pivot_result(result)

        except ImportError as e:
            console.print(f"[red]Error loading agent: {e}[/red]")
            console.print("\n[dim]Install an LLM provider:[/dim]")
            console.print(r"  pip install -e '.\[litellm]'   # All providers via LiteLLM")
            raise click.Abort()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            raise click.Abort()

    else:
        console.print(f"[red]Error: Unknown agent: {agent_name}[/red]")
        console.print("\n[dim]Available agents:[/dim]")
        for name in _AGENT_REGISTRY:
            console.print(f"  • {name}")
        raise click.Abort()


def _display_hypothesis_generator_result(result: Any) -> None:  # noqa: C901
    """Display hypothesis generator result."""
    if not result.is_success:
        console.print(f"[red]✗ Agent Error: {result.error}[/red]\n")
        return

    data = result.data

    console.print("[green]✓ Hypothesis generated successfully[/green]\n")

    console.print("[bold cyan]Hypothesis:[/bold cyan]")
    console.print(f"  {data.hypothesis}\n")

    console.print("[bold cyan]Justification:[/bold cyan]")
    console.print(f"  {data.justification}\n")

    if data.mitre_techniques:
        console.print("[bold cyan]MITRE ATT&CK Techniques:[/bold cyan]")
        for technique in data.mitre_techniques:
            console.print(f"  • {technique}")
        console.print()

    if data.data_sources:
        console.print("[bold cyan]Data Sources:[/bold cyan]")
        for source in data.data_sources:
            console.print(f"  • {source}")
        console.print()

    if data.expected_observables:
        console.print("[bold cyan]Expected Observables:[/bold cyan]")
        for observable in data.expected_observables:
            console.print(f"  • {observable}")
        console.print()

    if data.known_false_positives:
        console.print("[bold cyan]Known False Positives:[/bold cyan]")
        for fp in data.known_false_positives:
            console.print(f"  • {fp}")
        console.print()

    console.print(f"[bold cyan]Time Range:[/bold cyan] {data.time_range_suggestion}\n")

    # ABLE scoping — each field gets its own top-level header (rather than
    # nesting all four under one "ABLE Scoping:" block) so it parses the
    # same way Hypothesis/Justification above already do: a header line
    # followed by an indented value. A caller parsing this console output
    # line-by-line (see sec7669's _parse_hypothesis_output) has no other way
    # to tell four sibling fields apart from one nested block without
    # bespoke parsing just for this section.
    if data.actor:
        console.print("[bold cyan]Actor:[/bold cyan]")
        console.print(f"  {data.actor}\n")

    if data.behavior:
        console.print("[bold cyan]Behavior:[/bold cyan]")
        console.print(f"  {data.behavior}\n")

    if data.location:
        console.print("[bold cyan]Location:[/bold cyan]")
        console.print(f"  {data.location}\n")

    if data.evidence:
        console.print("[bold cyan]Evidence:[/bold cyan]")
        console.print(f"  {data.evidence}\n")

    if data.expected_malicious:
        console.print("[bold cyan]Expected Malicious:[/bold cyan]")
        console.print(f"  {data.expected_malicious}\n")

    if data.expected_benign:
        console.print("[bold cyan]Expected Benign Baseline:[/bold cyan]")
        console.print(f"  {data.expected_benign}\n")

    if data.falsification_criteria:
        console.print("[bold cyan]Falsification Criteria:[/bold cyan]")
        console.print(f"  {data.falsification_criteria}\n")

    if data.rubric_score:
        score = data.rubric_score
        verdict = score.get("verdict", "N/A")
        total = score.get("total", 0)
        verdict_color = "green" if verdict == "GO" else ("yellow" if verdict == "CONDITIONAL" else "red")
        console.print(
            f"[bold cyan]Hypothesis Quality Rubric:[/bold cyan] [{verdict_color}]{verdict} ({total}/15)[/{verdict_color}]"
        )
        console.print(
            f"  • Specificity: {score.get('specificity', 0)}/3 | Testability: {score.get('testability', 0)}/3 | "
            f"Falsifiability: {score.get('falsifiability', 0)}/3 | Relevance: {score.get('relevance', 0)}/3 | "
            f"Pyramid Level: {score.get('pyramid_level', 0)}/3\n"
        )

    if not data.is_threat_report:
        # No emoji/decoration in the header text itself, same as every
        # other header above -- a caller line-parsing this output (see
        # sec7669's _parse_hypothesis_output) matches on the exact header
        # string, and an emoji is a literal character rich's markup
        # stripping won't remove, unlike the [bold red] tags.
        console.print("[bold red]Low Confidence Source:[/bold red]")
        console.print(f"  {data.low_confidence_reason or 'Source does not appear to describe observed adversary behavior.'}\n")

    if data.is_indicator_only:
        # Same plain-header convention as "Low Confidence Source:" above --
        # a caller line-parsing this output matches the exact header string.
        console.print("[bold yellow]Indicator-Only Source:[/bold yellow]")
        console.print(
            "  Source is a bare indicator list with no narrative; the hypothesis "
            "describes indicator presence, not adversary behavior.\n"
        )

    if result.warnings:
        console.print("[bold yellow]Warnings:[/bold yellow]")
        for warning in result.warnings:
            console.print(f"  • {warning}")
        console.print()

    if result.metadata:
        if "cost_usd" in result.metadata:
            console.print(
                f"[dim]Cost: {format_cost(result.metadata['cost_usd'], result.metadata.get('cost_basis', ''))}[/dim]"
            )
        if "prompt_tokens" in result.metadata:
            console.print(
                f"[dim]Tokens: {result.metadata['prompt_tokens']} input + {result.metadata['completion_tokens']} output[/dim]"
            )
        console.print()


def _display_pivot_result(result: Any) -> None:
    """Display pivot suggester result."""
    if not result.is_success:
        console.print(f"[red]Error: {result.error}[/red]\n")
        return

    data = result.data
    mode = result.metadata.get("mode", "llm")

    console.print("\n[bold cyan]Pivot Analysis[/bold cyan]\n")
    console.print(f"[bold]Finding:[/bold] {data.finding_summary}\n")

    if data.technique_matches:
        console.print(f"[bold]ATT&CK Techniques:[/bold] {', '.join(data.technique_matches)}\n")

    if data.past_hunt_references:
        console.print(f"[bold]Related Past Hunts:[/bold] {', '.join(data.past_hunt_references)}\n")

    console.print("[bold cyan]Suggested Pivots[/bold cyan]")
    console.print("─" * 60 + "\n")

    for pivot in sorted(data.pivots, key=lambda p: p.priority):
        hint = f" [{pivot.technique_hint}]" if pivot.technique_hint else ""
        console.print(f"[bold yellow]{pivot.priority}.[/bold yellow] {pivot.query}{hint}")
        console.print(f"   [dim]Data source:[/dim] {pivot.data_source}")
        console.print(f"   [dim]Why:[/dim] {pivot.rationale}")
        console.print()

    if mode == "heuristic":
        console.print("[dim]Note: Generated in heuristic mode (no LLM). Use --llm for richer suggestions.[/dim]\n")


def _display_research_result(result: Any) -> None:
    """Display research result."""
    from rich.panel import Panel

    if not result.is_success:
        console.print(f"[red]✗ Agent Error: {result.error}[/red]\n")
        return

    output = result.data

    # Success panel
    console.print()
    console.print(
        Panel(
            f"[bold green]Research Complete: {output.research_id}[/bold green]\n\n"
            f"[bold]Topic:[/bold] {output.topic}\n"
            f"[bold]Duration:[/bold] {output.total_duration_ms / 1000:.1f} seconds\n"
            f"[bold]Cost:[/bold] {format_cost(output.total_cost_usd, output.cost_basis)}\n"
            f"[bold]Web Searches:[/bold] {output.web_searches_performed}\n"
            f"[bold]LLM Calls:[/bold] {output.llm_calls}",
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
    console.print("  1. Use standalone command for full research file:")
    console.print(f"     [cyan]hecate-agent research view {output.research_id}[/cyan]")
    console.print("  2. Generate hypothesis: [cyan]hecate-agent agent run hypothesis-generator[/cyan]")
    console.print(f"  3. Create hunt: [cyan]hecate-agent hunt new --research {output.research_id}[/cyan]")
    console.print()
