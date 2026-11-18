"""Hunt query/display commands: list, validate, stats, search, coverage, coffee."""

import json
import random
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import click
import yaml
from rich import box
from rich.console import Console
from rich.table import Table

from hecate_agent.core.hunt_manager import HuntManager
from hecate_agent.core.hunt_parser import validate_hunt_file_with_warnings
from hecate_agent.utils.validation import validate_hunt_id

console = Console()


def _validate_single_hunt(hunt_file: Path) -> tuple:
    """Validate a single hunt file and display results.

    Returns:
        (is_valid, errors) — callers use this to avoid a second parse.
    """
    console.print(f"\n[bold]Validating {hunt_file.name}...[/bold]\n")

    is_valid, errors, warnings = validate_hunt_file_with_warnings(hunt_file)

    if is_valid:
        console.print("[green]Hunt is valid![/green]")
    else:
        console.print("[red]Hunt has validation errors:[/red]\n")
        for error in errors:
            console.print(f"  - {error}")

    # Warnings never change is_valid (and so never fail the command): an
    # auto-generated draft awaiting review is legitimately incomplete. They
    # are surfaced because "Hunt is valid!" on a hunt with empty tactics and
    # platform reads as a clean bill of health while the hunt is invisible to
    # `hecate-agent hunt coverage`.
    if warnings:
        console.print("\n[yellow]Metadata gaps:[/yellow]\n")
        for warning in warnings:
            console.print(f"  - {warning}")
        console.print(
            "\n[dim]Fix with: hecate-agent hunt update <ID> --technique T1234 --tactic execution --platform Windows[/dim]"
        )

    return is_valid, errors


def _render_progress_bar(covered: int, total: int, width: int = 20) -> str:
    """Render a visual progress bar with filled and empty blocks.

    Args:
        covered: Number of covered techniques
        total: Total number of techniques
        width: Width of the progress bar in characters

    Returns:
        ASCII progress bar string using simple characters
    """
    if total == 0:
        return "·" * width

    # Cap percentage at 100% for visual display
    percentage = min(covered / total, 1.0)
    filled = int(percentage * width)
    empty = width - filled

    # Use simple characters that render reliably
    filled_char = "■"
    empty_char = "·"

    return filled_char * filled + empty_char * empty


@click.command(name="list")
@click.option("--status", help="Filter by status (planning, active, in_review, completed)")
@click.option("--tactic", help="Filter by MITRE tactic")
@click.option("--technique", help="Filter by MITRE technique (e.g., T1003.001)")
@click.option("--platform", help="Filter by platform")
@click.option("--directory", type=click.Choice(["test", "production"]), help="Filter by environment directory")
@click.option(
    "--type", "hunt_type", type=click.Choice(["hypothesis-driven", "baseline", "model-assisted"]), help="Filter by hunt type"
)
@click.option("--assignee", help="Filter by assigned team member")
@click.option(
    "--format",
    "-f",
    "--output",
    "output",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format (table, json, yaml)",
)
def list_hunts(
    status: str, tactic: str, technique: str, platform: str, directory: str, hunt_type: str, assignee: str, output: str
) -> None:
    """List all hunts with filtering and formatting options.

    \b
    Displays hunt catalog with:
    • Hunt ID and title
    • Current status
    • Environment directory (test/production)
    • MITRE ATT&CK techniques
    • True/False positive counts

    \b
    Examples:
      # List all hunts
      hecate-agent hunt list

      # Show only completed hunts
      hecate-agent hunt list --status completed

      # Filter by tactic
      hecate-agent hunt list --tactic credential-access

      # Filter by environment directory
      hecate-agent hunt list --directory test

      # Combine filters
      hecate-agent hunt list --tactic persistence --platform Linux --directory production

      # JSON output for scripting
      hecate-agent hunt list --output json

      # Show only baseline (EDA) hunts
      hecate-agent hunt list --type baseline

    \b
    Output formats:
      • table (default): Human-readable table with colors
      • json: Machine-readable for scripts and automation
      • yaml: Structured format for configuration management

    Note: --format and --output can be used interchangeably.
    """
    manager = HuntManager()
    hunts = manager.list_hunts(
        status=status,
        tactic=tactic,
        technique=technique,
        platform=platform,
        directory=directory,
        hunt_type=hunt_type,
        assignee=assignee,
    )

    if not hunts:
        if output == "json":
            click.echo("[]")
            return
        if output == "yaml":
            click.echo("[]")
            return
        console.print("[yellow]No hunts found.[/yellow]")
        console.print("\nCreate your first hunt: [cyan]hecate-agent hunt new[/cyan]")
        return

    if output == "json":
        click.echo(json.dumps(hunts, indent=2))
        return

    if output == "yaml":
        click.echo(yaml.dump(hunts, default_flow_style=False))
        return

    # Table format
    console.print(f"\n[bold]📋 Hunt Catalog ({len(hunts)} total)[/bold]\n")

    table = Table(box=box.ROUNDED)
    table.add_column("Hunt ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="white", no_wrap=True, max_width=30)
    table.add_column("Date", style="dim", no_wrap=True)
    table.add_column("Status", style="yellow", no_wrap=True)
    table.add_column("Assignee", style="dim", no_wrap=True)
    table.add_column("Env", style="blue", no_wrap=True)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Technique", style="magenta", no_wrap=True)
    table.add_column("Findings", style="green", no_wrap=True)

    for hunt in hunts:
        hunt_id = hunt.get("hunt_id", "")
        title_full = hunt.get("title") or ""
        title = title_full[:30] + ("..." if len(title_full) > 30 else "")
        date_val = hunt.get("date") or "-"
        date_str = str(date_val) if date_val != "-" else "-"
        status_val = hunt.get("status", "")
        assignee_val = hunt.get("assignee") or "-"
        environment = hunt.get("environment", "-")
        env_display = environment if environment else "-"
        # Only non-hypothesis-driven types stand out here -- hypothesis-driven
        # is the overwhelmingly common case, so keep the column quiet for it.
        _ht = hunt.get("hunt_type")
        type_display = "baseline" if _ht == "baseline" else ("model-asst" if _ht == "model-assisted" else "-")
        techniques = hunt.get("techniques", [])
        technique_str = techniques[0] if techniques else "-"

        tp = hunt.get("true_positives", 0)
        fp = hunt.get("false_positives", 0)
        findings_str = f"{tp + fp} ({tp} TP)" if (tp + fp) > 0 else "-"

        table.add_row(
            hunt_id, title, date_str, status_val, assignee_val, env_display, type_display, technique_str, findings_str
        )

    console.print(table)
    console.print()


def _resolve_hunt_for_validation(hunt_id: str) -> Optional[Path]:
    """Find a hunt file by ID, or explain why it cannot be validated.

    Falls back to a recursive search because hunts moved from a flat
    directory into hunts/{year}/{quarter}/ and older workspaces still have
    both shapes.
    """
    if not validate_hunt_id(hunt_id):
        console.print(f"[red]Error: Invalid hunt ID format: {hunt_id}[/red]")
        console.print("[yellow]Expected format: H-0001[/yellow]")
        return None

    hunts_dir = HuntManager().hunts_dir
    hunt_file = hunts_dir / f"{hunt_id}.md"
    if not hunt_file.exists():
        matching_files = list(hunts_dir.rglob(f"{hunt_id}.md"))
        if not matching_files:
            console.print(f"[red]Hunt not found: {hunt_id}[/red]")
            return None
        hunt_file = matching_files[0]

    # Containment check: a crafted ID must not reach outside hunts/.
    try:
        hunt_file.resolve().relative_to(hunts_dir.resolve())
    except (ValueError, OSError):
        console.print("[red]Error: Invalid hunt file path[/red]")
        return None

    return hunt_file


def _report_validation(hunt_files: List[Path]) -> Tuple[int, int, int]:
    """Print one line per hunt and return (valid, invalid, warned) counts."""
    valid_count = invalid_count = warned_count = 0

    for hunt_file in hunt_files:
        is_valid, errors, warnings = validate_hunt_file_with_warnings(hunt_file)

        if is_valid:
            valid_count += 1
            marker = "[yellow]![/yellow]" if warnings else "[green]✓[/green]"
            console.print(f"{marker} {hunt_file.name}")
        else:
            invalid_count += 1
            console.print(f"[red]✗[/red] {hunt_file.name}")
            for error in errors:
                console.print(f"    - {error}")

        if warnings:
            warned_count += 1
            for warning in warnings:
                console.print(f"    [yellow]-[/yellow] {warning}")

    return valid_count, invalid_count, warned_count


@click.command()
@click.argument("hunt_id", required=False)
def validate(hunt_id: str) -> None:
    """Validate hunt file structure and metadata.

    \b
    Validates:
    • YAML frontmatter syntax
    • Required metadata fields
    • LOCK section structure
    • MITRE ATT&CK technique format
    • File naming conventions

    \b
    Examples:
      # Validate specific hunt
      hecate-agent hunt validate H-0042

      # Validate all hunts (exits 1 if invalid)
      hecate-agent hunt validate
    \b
    Use this to:
    • Catch formatting errors before committing
    • Ensure consistency across hunt documentation
    • Verify hunt files are AI-assistant readable
    """
    if hunt_id:
        hunt_file = _resolve_hunt_for_validation(hunt_id)
        if hunt_file is None:
            import sys
            sys.exit(1)

        is_valid, _ = _validate_single_hunt(hunt_file)
        if not is_valid:
            import sys
            sys.exit(1)
    else:
        # Validate all hunts
        console.print("\n[bold]🔍 Validating all hunts...[/bold]\n")

        manager = HuntManager()
        hunts_dir = manager.hunts_dir
        if not hunts_dir.exists():
            console.print("[yellow]No hunts directory found.[/yellow]")
            return

        hunt_files = manager.find_all_hunt_files()

        if not hunt_files:
            console.print("[yellow]No hunt files found.[/yellow]")
            return

        valid_count, invalid_count, warned_count = _report_validation(hunt_files)

        summary = f"\n[bold]Results:[/bold] {valid_count} valid, {invalid_count} invalid"
        if warned_count:
            summary += f", {warned_count} with metadata gaps"
        console.print(summary)
        if invalid_count > 0:
            import sys
            sys.exit(1)


def _show_trend(manager: HuntManager) -> None:
    """Print a quarterly breakdown of hunt activity."""
    from collections import defaultdict

    hunts = manager.list_hunts()
    if not hunts:
        return

    quarters: dict = defaultdict(lambda: {"total": 0, "completed": 0, "true_positives": 0})

    for hunt in hunts:
        date_val = hunt.get("date")
        if not date_val:
            continue
        try:
            if hasattr(date_val, "year"):
                year, month = date_val.year, date_val.month
            else:
                parsed = datetime.strptime(str(date_val)[:10], "%Y-%m-%d")
                year, month = parsed.year, parsed.month
            quarter = f"{year} Q{(month - 1) // 3 + 1}"
        except (ValueError, AttributeError):
            continue

        quarters[quarter]["total"] += 1
        if hunt.get("status") == "completed":
            quarters[quarter]["completed"] += 1
        quarters[quarter]["true_positives"] += hunt.get("true_positives", 0)

    if not quarters:
        return

    console.print("[bold cyan]📈 Quarterly Trend[/bold cyan]\n")
    trend_table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    trend_table.add_column("Quarter", style="cyan")
    trend_table.add_column("Total", justify="right")
    trend_table.add_column("Completed", justify="right")
    trend_table.add_column("True Positives", justify="right")

    for quarter in sorted(quarters.keys()):
        q = quarters[quarter]
        trend_table.add_row(quarter, str(q["total"]), str(q["completed"]), str(q["true_positives"]))

    console.print(trend_table)
    console.print()


def _save_hunt_context(stats_data: dict, manager: HuntManager) -> None:
    """Write a structured hunt-program metrics block to knowledge/environment.md.

    Appends (or replaces) a ``## Hunt Program Metrics`` section so agent runs
    inherit up-to-date context about what has been hunted, success rates, and
    covered tactics.
    """
    from hecate_agent.core.attack_matrix import get_sorted_tactics

    # Collect tactic coverage summary
    coverage_data = manager.calculate_attack_coverage()
    by_tactic = coverage_data.get("by_tactic", {})
    covered_tactics = [t for t in get_sorted_tactics() if by_tactic.get(t, {}).get("hunt_count", 0) > 0]

    # Build the metrics block
    now_str = datetime.now().strftime("%Y-%m-%d")
    tp_fp = stats_data.get("tp_fp_ratio", "N/A")
    tp_fp_str = str(tp_fp) if tp_fp != float("inf") else "∞"

    block_lines = [
        "",
        "## Hunt Program Metrics",
        "",
        f"_Auto-generated by `hecate-agent hunt stats --save-context` on {now_str}._",
        "",
        f"- **Total Hunts:** {stats_data['total_hunts']}",
        f"- **Completed Hunts:** {stats_data['completed_hunts']}",
        f"- **Baseline Hunts:** {stats_data['baseline_hunts']}",
        f"- **Model-Assisted Hunts:** {stats_data['model_assisted_hunts']}",
        f"- **True Positives:** {stats_data['true_positives']}",
        f"- **False Positives:** {stats_data['false_positives']}",
        f"- **Success Rate (hypothesis-driven):** {stats_data['success_rate']}%",
        f"- **TP/FP Ratio:** {tp_fp_str}",
        "",
        "**Covered ATT&CK Tactics:**",
    ]
    if covered_tactics:
        for t in covered_tactics:
            hunt_count = by_tactic[t].get("hunt_count", 0)
            tech_count = by_tactic[t].get("techniques_covered", 0)
            block_lines.append(f"- {t}: {hunt_count} hunt(s), {tech_count} technique(s)")
    else:
        block_lines.append("- No tactic coverage yet.")

    summary = coverage_data.get("summary", {})
    unique = summary.get("unique_techniques", 0)
    total = summary.get("total_techniques", 0)
    pct = summary.get("overall_coverage_pct", 0.0)
    block_lines.append("")
    block_lines.append(f"**Overall Technique Coverage:** {unique}/{total} ({pct:.0f}%)")
    block_lines.append("")

    metrics_block = "\n".join(block_lines)

    env_path = Path("knowledge/environment.md")
    env_path.parent.mkdir(parents=True, exist_ok=True)

    if env_path.exists():
        existing = env_path.read_text(encoding="utf-8")
        # Replace existing metrics block if present
        import re

        existing = re.sub(
            r"\n## Hunt Program Metrics\b.*?(?=\n## |\Z)",
            "",
            existing,
            flags=re.DOTALL,
        ).rstrip()
        new_content = existing + metrics_block
    else:
        new_content = f"# Environment Profile\n{metrics_block}"

    env_path.write_text(new_content, encoding="utf-8")
    console.print(f"[green]Hunt program context saved to {env_path}[/green]")


@click.command()
@click.option("--trend", is_flag=True, help="Show quarterly breakdown of hunt activity")
@click.option(
    "--save-context",
    is_flag=True,
    help="Append a hunt-program metrics block to knowledge/environment.md for agent context.",
)
def stats(trend: bool, save_context: bool) -> None:
    """Show hunt program statistics and success metrics.

    \b
    Calculates and displays:
    • Total hunts vs completed hunts
    • Total findings (True Positives + False Positives)
    • Success rate (hunts with TPs / completed hunts)
    • TP/FP ratio (quality of detections)
    • Hunt velocity metrics

    \b
    Examples:
      hecate-agent hunt stats
      hecate-agent hunt stats --trend

    \b
    Use this to:
    • Track hunting program effectiveness over time
    • Identify areas for improvement
    • Demonstrate hunting value to leadership
    • Set quarterly goals and OKRs
    """
    manager = HuntManager()
    stats_data = manager.calculate_stats()

    console.print("\n[bold cyan]📊 Hunt Program Statistics[/bold cyan]\n")

    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white", justify="right")

    table.add_row("Total Hunts", str(stats_data["total_hunts"]))
    table.add_row("Completed Hunts", str(stats_data["completed_hunts"]))
    table.add_row("Baseline Hunts", str(stats_data["baseline_hunts"]))
    table.add_row("Model-Assisted Hunts", str(stats_data["model_assisted_hunts"]))
    table.add_row("Total Findings", str(stats_data["total_findings"]))
    table.add_row("True Positives", str(stats_data["true_positives"]))
    table.add_row("False Positives", str(stats_data["false_positives"]))
    table.add_row("Success Rate (hypothesis-driven)", f"{stats_data['success_rate']}%")
    table.add_row("TP/FP Ratio", str(stats_data["tp_fp_ratio"]))

    console.print(table)
    console.print()

    # Easter egg: First True Positive milestone
    if stats_data["true_positives"] == 1 and stats_data["completed_hunts"] > 0:
        console.print("[bold yellow]🎯 First True Positive Detected![/bold yellow]\n")
        console.print(
            "[italic]Every expert threat hunter started here. This confirms your hypothesis was testable, your data was sufficient, and your analytical instincts were sound. Document what worked.[/italic]\n"
        )

    if trend:
        _show_trend(manager)

    if save_context:
        _save_hunt_context(stats_data, manager)


@click.command()
@click.argument("query")
@click.option("--directory", type=click.Choice(["test", "production"]), help="Filter by environment directory")
def search(query: str, directory: str) -> None:
    """Full-text search across all hunt files.

    \b
    Searches through:
    • Hunt titles and descriptions
    • YAML frontmatter metadata
    • LOCK section content
    • Lessons learned
    • Query comments

    \b
    Examples:
      # Search for specific TTP
      hecate-agent hunt search "kerberoasting"

      # Search for technology
      hecate-agent hunt search "powershell"

      # Search by hunt ID
      hecate-agent hunt search "H-0042"

      # Search for data source
      hecate-agent hunt search "sysmon"

      # Filter by environment directory
      hecate-agent hunt search "credential" --directory test

    \b
    Use this to:
    • Avoid duplicate hunts
    • Find related past work
    • Reference lessons learned
    • Check if a TTP has been hunted before
    """
    manager = HuntManager()
    results = manager.search_hunts(query, directory=directory)

    if not results:
        console.print(f"[yellow]No hunts found matching '{query}'[/yellow]")
        return

    console.print(f"\n[bold]🔍 Search results for '{query}' ({len(results)} found)[/bold]\n")

    for result in results:
        environment = result.get("environment", "-")
        env_display = f" | Env: {environment}" if environment else ""
        console.print(f"[cyan]{result['hunt_id']}[/cyan]: {result['title']}")
        console.print(f"  Status: {result['status']}{env_display} | File: {result['file_path']}")
        console.print()


def _tactics_to_display(tactic: Optional[str], attack_tactics: dict, get_sorted_tactics: Callable) -> Optional[List[str]]:
    """Which tactics the report should cover, or None if the filter is invalid.

    ``--tactic all`` is treated as no filter. Takes its ATT&CK data as
    arguments because the caller imports them lazily.
    """
    if not tactic or tactic.lower() == "all":
        return list(get_sorted_tactics())

    if tactic not in attack_tactics:
        console.print(f"[red]Error: Unknown tactic '{tactic}'[/red]")
        console.print("\n[bold]Valid tactics:[/bold]")
        for tactic_key in get_sorted_tactics():
            console.print(f"  • {tactic_key}")
        return None

    return [tactic]


def _print_tactic_summary(tactics: List[str], by_tactic: dict, attack_tactics: dict) -> None:
    """One line per tactic: hunt and technique counts, or "no coverage"."""
    for tactic_key in tactics:
        data = by_tactic.get(tactic_key, {})
        name = attack_tactics[tactic_key]["name"]
        hunt_count = data.get("hunt_count", 0)
        if hunt_count > 0:
            console.print(f"{name:<24} {hunt_count} hunts, {data.get('techniques_covered', 0)} techniques")
        else:
            console.print(f"{name:<24} [dim]no coverage[/dim]")


def _print_detailed_coverage(tactics: List[str], by_tactic: dict, attack_tactics: dict) -> None:
    """Per-technique breakdown, naming the hunts that cover each one.

    Tactics with no hunts are skipped: an empty heading per uncovered tactic
    would bury the ones that do have coverage, which the summary above
    already reports.
    """
    console.print("\n[bold cyan]🔍 Detailed Technique Coverage[/bold cyan]\n")

    for tactic_key in tactics:
        data = by_tactic.get(tactic_key, {})
        if data.get("hunt_count", 0) == 0:
            continue

        name = attack_tactics[tactic_key]["name"]
        console.print(f"\n[bold]{name}[/bold] ({data['hunt_count']} hunts, {len(data['techniques'])} unique techniques)")
        for technique, hunt_ids in sorted(data["techniques"].items()):
            console.print(f"  • [yellow]{technique}[/yellow] - {', '.join(sorted(set(hunt_ids)))}")


@click.command()
@click.option("--tactic", help="Filter by specific tactic (or 'all' for all tactics)")
@click.option("--detailed", is_flag=True, help="Show detailed technique coverage with hunt references")
@click.option(
    "--format",
    "-f",
    "--output",
    "output_format",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format (default: table)",
)
def coverage(tactic: Optional[str], detailed: bool, output_format: str) -> None:
    """Show MITRE ATT&CK technique coverage across hunts.

    \b
    Analyzes and displays:
    • Hunt count per tactic across all 14 ATT&CK tactics
    • Technique count per tactic (with caveats - see note below)
    • Overall unique technique coverage across all hunts
    • Detailed technique-to-hunt mapping (with --detailed)

    \b
    Examples:
      # Show coverage overview for all tactics
      hecate-agent hunt coverage

      # Show all tactics explicitly
      hecate-agent hunt coverage --tactic all

      # Show coverage for a specific tactic
      hecate-agent hunt coverage --tactic credential-access

      # Show detailed technique mapping for execution tactic
      hecate-agent hunt coverage --tactic execution --detailed

    \b
    Note on technique counts:
      Per-tactic technique counts may include duplicates if hunts cover
      multiple tactics. The overall unique technique count (bottom) is accurate.

    \b
    Use this to:
    • Identify blind spots in your hunting program
    • Prioritize future hunt topics
    • Demonstrate coverage to stakeholders
    • Align hunting with threat intelligence priorities
    • Balance hunt portfolio across tactics

    \b
    Pro tip:
      Focus on tactics with no coverage that align with your threat model.
      Use --detailed to see which specific techniques each hunt covers.
    """
    from hecate_agent.core.attack_matrix import ATTACK_TACTICS, get_sorted_tactics

    manager = HuntManager()
    coverage_data = manager.calculate_attack_coverage()

    if not coverage_data or not coverage_data.get("by_tactic"):
        console.print("[yellow]No hunt coverage data available.[/yellow]")
        return

    if output_format == "json":
        console.print(json.dumps(coverage_data, indent=2), soft_wrap=True)
        return

    if output_format == "yaml":
        console.print(yaml.dump(coverage_data, default_flow_style=False))
        return

    summary = coverage_data["summary"]
    by_tactic = coverage_data["by_tactic"]

    tactics_to_display = _tactics_to_display(tactic, ATTACK_TACTICS, get_sorted_tactics)
    if tactics_to_display is None:
        return

    # Display title
    if tactic and tactic.lower() != "all":
        tactic_display_name = ATTACK_TACTICS[tactic]["name"]
        console.print(f"\n[bold]MITRE ATT&CK Coverage - {tactic_display_name}[/bold]")
    else:
        console.print("\n[bold]MITRE ATT&CK Coverage[/bold]")
    console.print("─" * 60 + "\n")

    _print_tactic_summary(tactics_to_display, by_tactic, ATTACK_TACTICS)

    # Display overall coverage only if showing all tactics
    if not tactic or tactic.lower() == "all":
        console.print(
            f"\n[bold]Overall: {summary['unique_techniques']}/{summary['total_techniques']} techniques ({summary['overall_coverage_pct']:.0f}%)[/bold]\n"
        )
    else:
        console.print()

    if detailed:
        _print_detailed_coverage(tactics_to_display, by_tactic, ATTACK_TACTICS)

    console.print()


@click.command(hidden=True)
def coffee() -> None:
    """Check your caffeine levels (critical for threat hunting)."""
    now = datetime.now()
    hour = now.hour

    # Random caffeine level
    caffeine_level = random.randint(0, 100)

    # Time-aware status
    if 3 <= hour < 5:
        status = "Incident Response Mode"
        time_message = "Running on pure incident response adrenaline."
    elif 0 <= hour < 6:
        status = "Night Hunter"
        time_message = "The real threat hunting happens in the dark."
    elif 6 <= hour < 9:
        status = "Early Bird"
        time_message = "Morning hunts catch the adversaries."
    elif 18 <= hour < 24:
        status = "Evening Detective"
        time_message = "Picking up where the day shift left off."
    else:
        status = "Operational"
        time_message = "Sustainable hunting pace detected."

    # Caffeine-level specific recommendations
    if caffeine_level < 30:
        recommendation = "Consider refueling. Even the best hunters need breaks."
    elif caffeine_level > 90:
        recommendation = "Peak operational capacity. Time to chase that hypothesis."
    else:
        recommendation = time_message

    console.print("\n[bold]☕ Threat Hunter Caffeine Check[/bold]\n")
    console.print(f"Current Level: [cyan]{caffeine_level}%[/cyan]")
    console.print(f"Status: [yellow]{status}[/yellow]")
    console.print(f"Recommendation: [italic]{recommendation}[/italic]\n")

    # Random wisdom quote
    wisdom_quotes = [
        "The best hunts are fueled by curiosity, not just caffeine.",
        "Caffeine enables the hunt. Rigor validates the findings.",
        "Stay sharp, stay curious, stay caffeinated.",
        "Coffee: because threat actors don't work business hours.",
        "Fuel your hypotheses with coffee. Validate them with data.",
    ]
    console.print(f"[dim italic]{random.choice(wisdom_quotes)}[/dim italic]\n")
