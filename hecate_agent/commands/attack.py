"""ATT&CK data management commands."""

import json
import re
import time
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional, Tuple

import click
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from hecate_agent.core.attack_matrix import TechniqueInfo

console = Console()


@click.group()
def attack() -> None:
    """Manage MITRE ATT&CK data.

    \b
    Commands for downloading, inspecting, and querying ATT&CK
    technique data via the STIX framework.

    \b
    Quick Start:
      hecate-agent attack update       Download/refresh STIX data
      hecate-agent attack status       Show provider info and cache age
      hecate-agent attack lookup T1003 Look up technique metadata
    """


_STIX_ID_RE = re.compile(r"^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _sanitize_stix_bundle(path: Path) -> None:
    """Fix known-bad fields in the MITRE STIX bundle that cause stix2 validation errors.

    The upstream bundle sometimes ships DataComponent objects with empty
    ``x_mitre_data_source_ref`` values.  The ``stix2`` library rejects
    these because they don't match the STIX identifier format.  We
    strip those invalid entries so ``MitreAttackData`` can load the file.
    """
    with open(path, "r") as f:
        bundle = json.load(f)

    modified = False
    for obj in bundle.get("objects", []):
        ref = obj.get("x_mitre_data_source_ref")
        if ref is not None and not _STIX_ID_RE.match(ref):
            del obj["x_mitre_data_source_ref"]
            modified = True

    if modified:
        with open(path, "w") as f:
            json.dump(bundle, f)


@attack.command()
@click.option("--force", is_flag=True, help="Re-download even if cache exists")
def update(force: bool) -> None:
    """Download or refresh ATT&CK STIX data.

    Downloads the Enterprise ATT&CK STIX bundle from the official
    MITRE repository and caches it locally.

    \b
    Examples:
      hecate-agent attack update
      hecate-agent attack update --force
    """
    try:
        from mitreattack.stix20 import MitreAttackData  # noqa: F401
    except ImportError:
        console.print("[red]Error: mitreattack-python is not installed.[/red]")
        console.print("[dim]Install it with: pip install -e '.[attack]'[/dim]")
        raise click.Abort()

    from hecate_agent.core.attack_matrix import _get_stix_file_path, reset_provider

    stix_path = _get_stix_file_path()

    if stix_path.exists() and not force:
        age_days = int((time.time() - stix_path.stat().st_mtime) / 86400)
        console.print(f"[yellow]STIX data already exists (age: {age_days}d).[/yellow]")
        console.print("[dim]Use --force to re-download.[/dim]")
        return

    # Ensure cache directory exists
    stix_path.parent.mkdir(parents=True, exist_ok=True)

    console.print("[cyan]Downloading ATT&CK Enterprise STIX data...[/cyan]")
    console.print(f"[dim]Cache location: {stix_path}[/dim]")

    _STIX_URL = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data" "/master/enterprise-attack/enterprise-attack.json"
    )

    try:
        urllib.request.urlretrieve(_STIX_URL, str(stix_path))
        _sanitize_stix_bundle(stix_path)
        from hecate_agent.core.attack_matrix import compile_stix_to_sqlite

        try:
            compile_stix_to_sqlite(stix_path)
        except Exception as exc:
            console.print(f"[yellow]Warning: Could not compile SQLite cache ({exc}); will use direct JSON.[/yellow]")
        # Reset provider so it picks up the new data
        reset_provider()
        console.print("[green]ATT&CK STIX data downloaded successfully.[/green]")

        # Show summary
        from hecate_agent.core.attack_matrix import get_attack_version, is_using_stix

        if is_using_stix():
            console.print(f"[dim]Version: {get_attack_version()}[/dim]")
    except Exception as e:
        console.print(f"[red]Error downloading STIX data: {e}[/red]")
        raise click.Abort()


@attack.command()
def status() -> None:
    """Show ATT&CK data provider status.

    Displays the active provider type, ATT&CK version,
    technique counts, and cache file details.

    \b
    Example:
      hecate-agent attack status
    """
    from hecate_agent.core.attack_matrix import _resolve_stix_file, get_attack_version, get_sorted_tactics, is_using_stix

    console.print("\n[bold]ATT&CK Data Status[/bold]\n")

    provider_type = "STIX (mitreattack-python)" if is_using_stix() else "Fallback (hardcoded v14)"
    console.print(f"  [cyan]Provider:[/cyan]  {provider_type}")
    console.print(f"  [cyan]Version:[/cyan]   {get_attack_version()}")
    console.print(f"  [cyan]Tactics:[/cyan]   {len(get_sorted_tactics())}")

    # Show cache info
    stix_path = _resolve_stix_file()
    if stix_path.exists():
        size_mb = stix_path.stat().st_size / (1024 * 1024)
        age_days = int((time.time() - stix_path.stat().st_mtime) / 86400)
        console.print(f"  [cyan]Cache:[/cyan]     {stix_path}")
        console.print(f"  [cyan]Size:[/cyan]      {size_mb:.1f} MB")
        console.print(f"  [cyan]Age:[/cyan]       {age_days} days")
    else:
        console.print(f"  [cyan]Cache:[/cyan]     Not found ({stix_path})")
        console.print("[dim]  Run 'hecate-agent attack update' to download STIX data.[/dim]")

    # Check if mitreattack-python is installed
    try:
        import mitreattack  # noqa: F401

        console.print("  [cyan]Library:[/cyan]   mitreattack-python installed")
    except ImportError:
        console.print("  [cyan]Library:[/cyan]   [yellow]mitreattack-python not installed[/yellow]")
        console.print("[dim]  Install with: pip install -e '.[attack]'[/dim]")

    console.print()


def _display_technique_fields(tech: "TechniqueInfo") -> None:
    """Print technique metadata fields to the console."""
    if tech.get("url"):
        console.print(f"  [cyan]URL:[/cyan]           {tech['url']}")
    if tech.get("platforms"):
        console.print(f"  [cyan]Platforms:[/cyan]     {', '.join(tech['platforms'])}")
    if tech.get("tactic_shortnames"):
        console.print(f"  [cyan]Tactics:[/cyan]       {', '.join(tech['tactic_shortnames'])}")
    if tech.get("data_sources"):
        console.print(f"  [cyan]Data Sources:[/cyan]  {', '.join(tech['data_sources'][:5])}")
        if len(tech.get("data_sources", [])) > 5:
            console.print(f"                 [dim]... and {len(tech['data_sources']) - 5} more[/dim]")
    is_sub = tech.get("is_subtechnique", False)
    console.print(f"  [cyan]Type:[/cyan]          {'Sub-technique' if is_sub else 'Technique'}")
    if is_sub and tech.get("parent_id"):
        console.print(f"  [cyan]Parent:[/cyan]        {tech['parent_id']}")
    if tech.get("description"):
        desc = tech["description"]
        if len(desc) > 300:
            desc = desc[:300] + "..."
        console.print(f"\n  [dim]{desc}[/dim]")


def _follow_revocation(
    technique_id: str,
    tech: Optional["TechniqueInfo"],
    get_superseding_technique_id: Callable[[str], Optional[str]],
    get_technique: Callable[[str], Optional["TechniqueInfo"]],
) -> Tuple[Optional[str], Optional["TechniqueInfo"]]:
    """Resolve a revoked technique ID to its replacement.

    Returns ``(superseded_from, technique)``; ``superseded_from`` is None when
    no remap happened, so a caller can tell "found it" from "found what it
    became". Takes its lookups as arguments because the command imports them
    lazily -- attack_matrix pulls in STIX parsing that a bare `hecate-agent --help`
    should not pay for.
    """
    if tech is not None:
        return None, tech
    successor = get_superseding_technique_id(technique_id)
    if not successor:
        return None, None
    replacement = get_technique(successor)
    if replacement is None:
        return None, None
    return technique_id.upper(), replacement


@attack.command()
@click.argument("technique_id")
@click.option("--json", "as_json", is_flag=True, help="Print technique metadata as JSON instead of a formatted table.")
def lookup(technique_id: str, as_json: bool) -> None:
    """Look up an ATT&CK technique by ID.

    Shows technique metadata including name, platforms,
    data sources, tactics, and sub-techniques.

    \b
    Examples:
      hecate-agent attack lookup T1003
      hecate-agent attack lookup T1003.001
      hecate-agent attack lookup T1003.001 --json
    """
    from hecate_agent.core.attack_matrix import get_sub_techniques, get_superseding_technique_id, get_technique, is_using_stix

    if not is_using_stix():
        if as_json:
            print(json.dumps({"error": "stix_unavailable", "technique_id": technique_id}))
        else:
            console.print("[yellow]STIX data not available. Technique lookup requires STIX.[/yellow]")
            console.print("[dim]Install and update: pip install -e '.[attack]' && hecate-agent attack update[/dim]")
        return

    tech = get_technique(technique_id)

    # A revoked ID is not an unknown one. ATT&CK merges techniques (T1574.002
    # "DLL Side-Loading" was folded into T1574.001 "DLL"), and CTI keeps
    # emitting the old identifier long afterwards -- the MISP ATT&CK galaxy
    # still tags events with T1574.002. Returning "not_found" made callers
    # silently drop that technique's tactics and platforms, so a hunt lost
    # scoping signal for a technique its source had actually asserted.
    # hypothesis_generator already followed revocations; this makes the CLI
    # agree with it.
    superseded_from, tech = _follow_revocation(technique_id, tech, get_superseding_technique_id, get_technique)

    if tech is None:
        if as_json:
            print(json.dumps({"error": "not_found", "technique_id": technique_id}))
        else:
            console.print(f"[yellow]Technique {technique_id} not found.[/yellow]")
        return

    if as_json:
        print(
            json.dumps(
                {
                    "id": tech.get("id", ""),
                    "name": tech.get("name", ""),
                    "tactics": tech.get("tactic_shortnames", []),
                    "platforms": tech.get("platforms", []),
                    "is_subtechnique": tech.get("is_subtechnique", False),
                    "parent_id": tech.get("parent_id"),
                    # Present only on a remap, so a caller can record that the
                    # source's identifier is stale rather than silently
                    # showing a different ID than it asked for.
                    **({"superseded_from": superseded_from} if superseded_from else {}),
                }
            )
        )
        return

    if superseded_from:
        console.print(f"\n[yellow]{superseded_from} was revoked by ATT&CK; showing its replacement.[/yellow]")
    console.print(f"\n[bold]{tech.get('id', '')} - {tech.get('name', '')}[/bold]\n")
    _display_technique_fields(tech)

    # Show sub-techniques if this is a parent
    if not tech.get("is_subtechnique", False):
        subs = get_sub_techniques(technique_id)
        if subs:
            console.print(f"\n  [bold]Sub-techniques ({len(subs)}):[/bold]")
            for sub in subs:
                console.print(f"    {sub.get('id', '')} - {sub.get('name', '')}")

    console.print()


def _generate_gap_hunts(gaps: list, limit: int) -> None:
    """Generate draft hunt files for uncovered ATT&CK techniques.

    Iterates up to *limit* gap entries, feeds each into HypothesisGeneratorAgent
    (heuristic mode — no LLM required), and writes a draft hunt file via
    render_hunt_template().  Prints a summary of created files.
    """
    from pathlib import Path

    from hecate_agent.agents.llm.hypothesis_generator import HypothesisGenerationInput, HypothesisGeneratorAgent
    from hecate_agent.core.hunt_manager import HuntManager
    from hecate_agent.core.template_engine import render_hunt_template

    manager = HuntManager()
    agent = HypothesisGeneratorAgent(llm_enabled=False)

    # Read environment context if available
    env_file = Path("knowledge/environment.md")
    env_text = env_file.read_text(encoding="utf-8")[:3000] if env_file.exists() else ""

    targets = gaps[:limit]
    console.print(f"\n[bold cyan]Generating {len(targets)} draft hunt file(s)…[/bold cyan]\n")

    created: list = []
    for entry in targets:
        tech_id = entry["id"]
        tech_name = entry["name"]
        tactic_key = entry["tactic"]

        threat_intel = (
            f"ATT&CK technique {tech_id} — {tech_name} "
            f"(tactic: {tactic_key}) has no existing hunt coverage. "
            f"Platforms: {', '.join(entry.get('platforms', []) or ['unknown'])}."
        )

        result = agent.execute(
            HypothesisGenerationInput(
                threat_intel=threat_intel,
                past_hunts=[],
                environment={"environment_summary": env_text[:500]} if env_text else {},
            )
        )

        if not result.is_success or result.data is None:
            console.print(f"  [yellow]⚠ Skipped {tech_id}: agent error[/yellow]")
            continue

        out = result.data
        hunt_id = manager.allocate_hunt_id()

        hunt_content = render_hunt_template(
            hunt_id=hunt_id,
            title=f"Hunt {tech_id}: {tech_name}",
            technique=tech_id,
            tactics=[tactic_key],
            platform=entry.get("platforms") or [],
            data_sources=out.data_sources,
            hypothesis=out.hypothesis,
            threat_context=f"Gap-generated from ATT&CK coverage analysis. {out.justification}",
            actor=out.actor or "",
            behavior=out.behavior or "",
            location=out.location or "",
            evidence=out.evidence or "",
        )

        hunt_dir = Path("hunts")
        hunt_dir.mkdir(parents=True, exist_ok=True)
        hunt_file = hunt_dir / f"{hunt_id}.md"
        hunt_file.write_text(hunt_content, encoding="utf-8")
        created.append((hunt_id, tech_id, tech_name))
        console.print(f"  [green]✓[/green] {hunt_id} — {tech_id}: {tech_name}")

    if created:
        console.print(f"\n[bold]Created {len(created)} draft hunt file(s).[/bold]")
        console.print("[dim]Edit each file to add queries and complete the LOCK section.[/dim]\n")
    else:
        console.print("[yellow]No hunt files were created.[/yellow]\n")


def _collect_gaps(
    tactics: list,
    covered: set,
    get_techniques_for_tactic: Callable[[str], list],
    no_subs: bool,
    platform_filter: Optional[str],
) -> list:
    """Uncovered techniques across the requested tactics, filtered.

    Takes its ATT&CK lookup as an argument because the caller imports it
    lazily -- attack_matrix pulls in STIX parsing that a bare `hecate-agent --help`
    should not pay for.
    """
    gaps: list = []
    for tactic_key in tactics:
        for tech in get_techniques_for_tactic(tactic_key) or []:
            tid = tech.get("id", "")
            if not tid or tid in covered:
                continue
            if no_subs and tech.get("is_subtechnique", False):
                continue
            if platform_filter and platform_filter.lower() not in [p.lower() for p in tech.get("platforms", [])]:
                continue
            gaps.append(
                {
                    "tactic": tactic_key,
                    "id": tid,
                    "name": tech.get("name", ""),
                    "is_subtechnique": tech.get("is_subtechnique", False),
                    "platforms": tech.get("platforms", []),
                }
            )
    return gaps


def _print_gap_table(gaps: list) -> None:
    """Render the uncovered-technique table."""
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Tactic", style="cyan", width=22)
    table.add_column("ID", style="yellow", width=12)
    table.add_column("Name", style="white")
    table.add_column("Sub?", style="dim", width=4)

    for gap_entry in gaps:
        table.add_row(
            gap_entry["tactic"],
            gap_entry["id"],
            gap_entry["name"],
            "Yes" if gap_entry["is_subtechnique"] else "",
        )

    console.print(table)
    console.print()


@attack.command()
@click.option("--tactic", "tactic_filter", help="Limit to one tactic (e.g., credential-access)")
@click.option("--platform", "platform_filter", help="Only show techniques for this platform")
@click.option("--no-subtechniques", "no_subs", is_flag=True, help="Exclude sub-techniques")
@click.option("--output", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option(
    "--generate",
    is_flag=True,
    help="Generate draft hunt files for each uncovered technique via hypothesis-generator agent.",
)
@click.option(
    "--limit",
    type=int,
    default=5,
    show_default=True,
    help="Maximum number of hunt files to generate (used with --generate).",
)
def gap(
    tactic_filter: Optional[str],
    platform_filter: Optional[str],
    no_subs: bool,
    output_format: str,
    generate: bool,
    limit: int,
) -> None:
    """Show ATT&CK techniques not yet covered by any hunt.

    Requires STIX data (run 'hecate-agent attack update' first).

    \b
    Examples:
      # Show all uncovered techniques
      hecate-agent attack gap

      # Limit to one tactic
      hecate-agent attack gap --tactic credential-access

      # Filter by platform
      hecate-agent attack gap --tactic persistence --platform Windows

      # JSON output for scripting
      hecate-agent attack gap --output json

      # Generate draft hunt files for top 5 uncovered techniques
      hecate-agent attack gap --tactic credential-access --generate

      # Generate up to 10 draft hunts
      hecate-agent attack gap --generate --limit 10
    """
    from hecate_agent.core.attack_matrix import get_sorted_tactics, get_techniques_for_tactic, is_using_stix
    from hecate_agent.core.hunt_manager import HuntManager

    if not is_using_stix():
        console.print("[yellow]STIX data not available. Gap analysis requires STIX.[/yellow]")
        console.print("[dim]Install and update: pip install -e '.[attack]' && hecate-agent attack update[/dim]")
        return

    # Build set of covered technique IDs from the hunt corpus
    manager = HuntManager()
    coverage_data = manager.calculate_attack_coverage()
    covered: set = set()
    for tactic_data in coverage_data.get("by_tactic", {}).values():
        covered.update(tactic_data.get("techniques", {}).keys())

    # Determine which tactics to inspect
    tactics = [tactic_filter] if tactic_filter else get_sorted_tactics()

    gaps = _collect_gaps(tactics, covered, get_techniques_for_tactic, no_subs, platform_filter)

    if not gaps:
        console.print("[green]No gaps found — all techniques are covered![/green]")
        return

    if output_format == "json":
        click.echo(json.dumps(gaps, indent=2))
        return

    console.print(f"\n[bold]ATT&CK Coverage Gaps ({len(gaps)} uncovered techniques)[/bold]\n")

    _print_gap_table(gaps)

    if generate:
        _generate_gap_hunts(gaps, limit)


@attack.command()
@click.argument("tactic_key")
def techniques(tactic_key: str) -> None:
    """List techniques for a tactic.

    Shows all techniques mapped to the specified tactic key
    (e.g., credential-access, lateral-movement).

    \b
    Examples:
      hecate-agent attack techniques credential-access
      hecate-agent attack techniques lateral-movement
    """
    from hecate_agent.core.attack_matrix import get_tactic_display_name, get_techniques_for_tactic, is_using_stix

    if not is_using_stix():
        console.print("[yellow]STIX data not available. Technique listing requires STIX.[/yellow]")
        console.print("[dim]Install and update: pip install -e '.[attack]' && hecate-agent attack update[/dim]")
        return

    techs = get_techniques_for_tactic(tactic_key)
    if not techs:
        console.print(f"[yellow]No techniques found for tactic '{tactic_key}'.[/yellow]")
        console.print("[dim]Use a tactic shortname like: credential-access, lateral-movement[/dim]")
        return

    display_name = get_tactic_display_name(tactic_key)
    console.print(f"\n[bold]{display_name}[/bold] ({len(techs)} techniques)\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("ID", style="white", width=12)
    table.add_column("Name", style="white")
    table.add_column("Sub?", style="dim", width=4)
    table.add_column("Platforms", style="dim")

    for tech in techs:
        is_sub = "Yes" if tech.get("is_subtechnique", False) else ""
        platforms = ", ".join(tech.get("platforms", [])[:3])
        if len(tech.get("platforms", [])) > 3:
            platforms += "..."
        table.add_row(
            tech.get("id", ""),
            tech.get("name", ""),
            is_sub,
            platforms,
        )

    console.print(table)
    console.print()


@attack.command("export-layer")
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, writable=True),
    help="Output JSON file path. If omitted, prints JSON to stdout.",
)
@click.option(
    "--name",
    "layer_name",
    default="Hecate Detection Coverage",
    show_default=True,
    help="Layer title displayed in ATT&CK Navigator.",
)
@click.option(
    "--description",
    "description",
    default=None,
    help="Layer description or summary.",
)
@click.option(
    "--score-by",
    type=click.Choice(["hunts", "queries", "binary"]),
    default="hunts",
    show_default=True,
    help="Scoring metric: 'hunts' (hunt count), 'queries' (query/rule count), 'binary' (1/0).",
)
@click.option(
    "--tactic",
    "tactic_filter",
    help="Limit export to a single tactic (e.g. execution, initial-access).",
)
@click.option(
    "--platform",
    "platform_filter",
    help="Limit export to techniques matching a platform (e.g. Windows, Linux).",
)
@click.option(
    "--include-uncovered/--only-covered",
    "include_uncovered",
    default=False,
    show_default=True,
    help="Include all uncovered techniques with a score of 0.",
)
@click.option(
    "--min-score",
    type=float,
    default=None,
    help="Minimum score required for a technique to be included.",
)
@click.option(
    "--hunts-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Path to directory containing hunt markdown files (defaults to ./hunts).",
)
@click.option(
    "--queries-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Path to directory containing query folders (defaults to ./queries).",
)
def export_layer(
    output_path: Optional[str],
    layer_name: str,
    description: Optional[str],
    score_by: str,
    tactic_filter: Optional[str],
    platform_filter: Optional[str],
    include_uncovered: bool,
    min_score: Optional[float],
    hunts_dir: Optional[str],
    queries_dir: Optional[str],
) -> None:
    """Export MITRE ATT&CK Navigator JSON layer for visualization.

    Generates a layer file adhering to the MITRE ATT&CK Navigator schema (v4.5/v5.0),
    mapping your hunts and Sigma detection queries to techniques.

    \b
    Examples:
      # Export to stdout (pipeable to jq)
      hecate-agent attack export-layer

      # Save to a JSON file
      hecate-agent attack export-layer -o attack_layer.json

      # Score by detection query volume
      hecate-agent attack export-layer --score-by queries -o query_layer.json

      # Include all ATT&CK techniques (heatmap including gaps)
      hecate-agent attack export-layer --include-uncovered -o full_heatmap.json

      # Focus on Windows execution techniques
      hecate-agent attack export-layer --platform Windows --tactic execution -o win_exec.json
    """
    from hecate_agent.core.attack_matrix import is_using_stix
    from hecate_agent.core.attack_navigator import NavigatorExporter

    if not is_using_stix():
        click.echo("Warning: STIX data not available; exporting with fallback ATT&CK matrix.", err=True)

    exporter = NavigatorExporter(
        hunts_dir=Path(hunts_dir) if hunts_dir else None,
        queries_dir=Path(queries_dir) if queries_dir else None,
    )

    layer_dict = exporter.build_layer(
        name=layer_name,
        description=description,
        score_by=score_by,
        tactic_filter=tactic_filter,
        platform_filter=platform_filter,
        include_uncovered=include_uncovered,
        min_score=min_score,
    )

    if output_path:
        out = exporter.export_to_file(output_path=output_path, layer_dict=layer_dict)
        console.print(f"[green]✓ Exported ATT&CK Navigator layer to:[/green] {out}")
        console.print(f"[dim]Techniques included: {len(layer_dict.get('techniques', []))}[/dim]")
        console.print(
            "[dim]Open in https://mitre-attack.github.io/attack-navigator/ via 'Open Existing Layer' -> 'Upload from local'[/dim]"
        )
    else:
        click.echo(json.dumps(layer_dict, indent=2))


# Alias command 'layer'
attack.add_command(export_layer, name="layer")
