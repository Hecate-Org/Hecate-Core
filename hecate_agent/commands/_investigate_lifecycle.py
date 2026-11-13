"""Investigation lifecycle command: promote."""

from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

import click
import yaml
from rich.console import Console
from rich.prompt import Prompt

from hecate_agent.core.atomic_write import atomic_write_text
from hecate_agent.core.workspace import workspace_root
from hecate_agent.utils.validation import validate_investigation_id

console = Console()


def _load_investigation(investigation_id: str, parser_cls: type) -> Optional[Tuple[Path, dict, str]]:
    """Resolve, validate and parse an investigation, or explain why not.

    Returns None after printing the reason, which is why every guard lives
    here rather than inline: the caller has one thing to check instead of
    four separate early returns interleaved with its own work.
    """
    if not validate_investigation_id(investigation_id):
        console.print(f"[red]Error: Invalid investigation ID format: {investigation_id}[/red]")
        console.print("[yellow]Expected format: I-0001[/yellow]")
        return None

    investigations_dir = workspace_root() / "investigations"
    investigation_file = investigations_dir / f"{investigation_id}.md"

    # Containment check: a crafted ID must not reach outside investigations/.
    try:
        investigation_file.resolve().relative_to(investigations_dir.resolve())
    except (ValueError, OSError):
        console.print("[red]Error: Invalid investigation file path[/red]")
        return None

    if not investigation_file.exists():
        console.print(f"[red]Error: Investigation file not found: {investigation_file}[/red]")
        return None

    try:
        data = parser_cls(investigation_file).parse()
    except Exception as e:  # noqa: BLE001 - surfaced to the operator, not swallowed
        console.print(f"[red]Error parsing investigation file: {e}[/red]")
        return None

    return investigation_file, data.get("frontmatter", {}), data.get("content", "")


def _gather_hunt_metadata(
    technique: Optional[str],
    tactic: Tuple[str, ...],
    platform: Tuple[str, ...],
    status: str,
    non_interactive: bool,
) -> Optional[Tuple[str, list, list, str]]:
    """Collect the hunt-required fields, by flag or by prompt.

    Returns None when non-interactive mode is missing the one field it cannot
    infer. Interactive mode seeds each prompt with whatever flag was passed,
    so the two paths agree on precedence.
    """
    if non_interactive:
        if not technique:
            console.print("[red]Error: --technique required in non-interactive mode[/red]")
            return None
        return technique, list(tactic), list(platform), status

    console.print("\n[bold]Let's add hunt-required metadata:[/bold]")

    console.print("\n1. MITRE ATT&CK Technique (required for hunts):")
    console.print("   Examples: [cyan]T1003.001, T1059.001, T1078[/cyan]")
    hunt_technique = Prompt.ask("   Technique", default=technique or "")

    console.print("\n2. MITRE Tactics (comma-separated):")
    console.print("   Examples: [cyan]initial-access, execution, persistence, credential-access[/cyan]")
    tactics_input = Prompt.ask("   Tactics", default=",".join(tactic) if tactic else "")

    console.print("\n3. Target Platforms (comma-separated):")
    console.print("   Examples: [cyan]Windows, Linux, macOS, Cloud[/cyan]")
    platforms_input = Prompt.ask("   Platforms", default=",".join(platform) if platform else "")

    console.print("\n4. Hunt Status:")
    hunt_status = Prompt.ask(
        "   Status",
        default=status,
        choices=["planning", "in-progress", "completed", "archived"],
    )

    return (
        hunt_technique,
        [t.strip() for t in tactics_input.split(",")] if tactics_input else [],
        [p.strip() for p in platforms_input.split(",")] if platforms_input else [],
        hunt_status,
    )


def _record_hunt_on_investigation(investigation_file: Path, hunt_id: str) -> None:
    """Add the new hunt to the investigation's related_hunts.

    Best-effort: the hunt file is already written by this point, so failing to
    update the back-reference is a warning rather than a failed promotion.
    """
    try:
        content = investigation_file.read_text(encoding="utf-8")
        parts = content.split("---")
        if len(parts) < 3:
            return

        frontmatter = yaml.safe_load(parts[1])
        # `related_hunts:` with no value parses as None, not an empty list.
        if not frontmatter.get("related_hunts"):
            frontmatter["related_hunts"] = []
        if hunt_id not in frontmatter["related_hunts"]:
            frontmatter["related_hunts"].append(hunt_id)

        updated_yaml = yaml.dump(frontmatter, default_flow_style=False, sort_keys=False)
        atomic_write_text(investigation_file, f"---\n{updated_yaml}---{'---'.join(parts[2:])}")
        console.print(f"[dim]Updated {investigation_file} with hunt reference in related_hunts[/dim]")
    except Exception as e:  # noqa: BLE001 - the promotion itself already succeeded
        console.print(f"[yellow]Warning: Could not update investigation frontmatter: {e}[/yellow]")


@click.command()
@click.argument("investigation_id")
@click.option("--technique", help="MITRE ATT&CK technique (required for hunt)")
@click.option("--tactic", multiple=True, help="MITRE tactics (can specify multiple)")
@click.option("--platform", multiple=True, help="Target platforms (can specify multiple)")
@click.option("--status", default="in-progress", help="Hunt status (default: in-progress)")
@click.option("--non-interactive", is_flag=True, help="Skip interactive prompts")
def promote(
    investigation_id: str,
    technique: Optional[str],
    tactic: Tuple[str, ...],
    platform: Tuple[str, ...],
    status: str,
    non_interactive: bool,
) -> None:
    """Promote investigation to formal hunt.

    \b
    Creates a hunt file (H-XXXX) from an investigation, adding:
    • Hunt-required metadata (tactics, techniques, platform)
    • Hunt status and tracking fields
    • Findings count and TP/FP fields (default: 0)
    • Reference to original investigation (spawned_from)

    \b
    Examples:
      # Interactive promotion (prompts for details)
      hecate-agent investigate promote I-0042

      # Non-interactive with all options
      hecate-agent investigate promote I-0042 \\
        --technique T1059.001 \\
        --tactic execution \\
        --platform Windows \\
        --non-interactive

    \b
    After promotion:
      • Hunt file created in hunts/ directory
      • Investigation remains in investigations/ directory
      • Both files cross-reference each other
    """
    from hecate_agent.core.hunt_manager import HuntManager, get_hunt_directory
    from hecate_agent.core.investigation_parser import InvestigationParser

    console.print("\n[bold cyan]Promoting investigation to hunt[/bold cyan]\n")

    loaded = _load_investigation(investigation_id, InvestigationParser)
    if loaded is None:
        return
    investigation_file, inv_frontmatter, inv_content = loaded

    inv_title = inv_frontmatter.get("title", "Untitled")
    inv_investigator = inv_frontmatter.get("investigator", "Unknown")
    inv_data_sources = inv_frontmatter.get("data_sources", [])
    inv_related_hunts = inv_frontmatter.get("related_hunts", [])
    inv_tags = inv_frontmatter.get("tags", [])

    console.print(f"[bold]Investigation:[/bold] {investigation_id} - {inv_title}")

    metadata = _gather_hunt_metadata(technique, tactic, platform, status, non_interactive)
    if metadata is None:
        return
    hunt_technique, hunt_tactics, hunt_platforms, hunt_status = metadata

    hunt_manager = HuntManager()
    hunt_id = hunt_manager.allocate_hunt_id()

    console.print(f"\n[bold]Hunt ID:[/bold] {hunt_id}")

    today = datetime.now().strftime("%Y-%m-%d")
    hunt_frontmatter = {
        "hunt_id": hunt_id,
        "title": inv_title,
        "status": hunt_status,
        "date": today,
        "hunter": inv_investigator,
        "platform": hunt_platforms,
        "tactics": hunt_tactics,
        "techniques": [hunt_technique],
        "data_sources": inv_data_sources,
        "related_hunts": inv_related_hunts,
        "spawned_from": investigation_id,
        "findings_count": 0,
        "true_positives": 0,
        "false_positives": 0,
        "customer_deliverables": [],
        "tags": inv_tags,
    }

    yaml_content = yaml.dump(hunt_frontmatter, default_flow_style=False, sort_keys=False)

    hunt_content = f"""---
{yaml_content}---

# {hunt_id}: {inv_title}

**Hunt Metadata**

- **Date:** {today}
- **Hunter:** {inv_investigator}
- **Status:** {hunt_status.title()}
- **Promoted From:** {investigation_id}

---

{inv_content}
"""

    hunt_dir = workspace_root() / get_hunt_directory()
    hunt_dir.mkdir(parents=True, exist_ok=True)
    hunt_file = hunt_dir / f"{hunt_id}.md"

    try:
        hunt_file.resolve().relative_to((workspace_root() / "hunts").resolve())
    except (ValueError, OSError):
        console.print("[red]Error: Invalid hunt file path[/red]")
        return

    atomic_write_text(hunt_file, hunt_content)

    console.print(f"\n[bold green]Promoted {investigation_id} to {hunt_id}[/bold green]")

    _record_hunt_on_investigation(investigation_file, hunt_id)

    promotion_note = f"\n\n---\n\n**Promoted to Hunt:** {hunt_id} on {today}\n"
    with open(investigation_file, "a", encoding="utf-8") as f:
        f.write(promotion_note)

    console.print(f"[dim]Added promotion note to {investigation_file}[/dim]")

    console.print("\n[bold]Next steps:[/bold]")
    console.print(f"  1. Edit [cyan]{hunt_file}[/cyan] to refine hunt hypothesis")
    console.print("  2. Add MITRE ATT&CK coverage if needed")
    console.print(f"  3. Validate hunt: [cyan]hecate-agent hunt validate {hunt_id}[/cyan]")
    console.print(f"  4. View hunt: [cyan]hecate-agent hunt list --status {hunt_status}[/cyan]\n")
