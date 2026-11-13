"""Hunt creation commands: new, new-baseline, new-model-assisted."""

from pathlib import Path
from typing import Optional, Tuple

import click
import yaml
from rich.console import Console
from rich.prompt import Prompt

from hecate_agent.core.atomic_write import atomic_write_text
from hecate_agent.core.attack_matrix import get_technique
from hecate_agent.core.hunt_manager import HuntManager, get_hunt_directory
from hecate_agent.core.template_engine import render_baseline_template, render_hunt_template, render_math_template
from hecate_agent.core.workspace import workspace_root
from hecate_agent.utils.validation import validate_research_id

console = Console()


def _default_tactics_for_technique(technique_id: str) -> list:
    """Best-effort tactic auto-derivation from an ATT&CK technique ID."""
    if not technique_id:
        return []
    info = get_technique(technique_id)
    if info:
        return list(info.get("tactic_shortnames") or [])
    return []


def get_config_path() -> Path:
    """Get config file path, checking new location first, then falling back to root."""
    new_location = Path("config/.hecateconfig.yaml")
    old_location = Path(".hecateconfig.yaml")

    if new_location.exists():
        return new_location
    if old_location.exists():
        return old_location
    return new_location  # Default to new location for creation


def _clone_defaults(
    manager: "HuntManager",
    clone_id: str,
    technique: Optional[str],
    tactic: Tuple[str, ...],
    platform: Tuple[str, ...],
    data_source: Tuple[str, ...],
    title: Optional[str],
) -> Optional[Tuple]:
    """Pre-populate options from an existing hunt.

    Explicit flags win over the clone source, so each field is only filled
    where the caller left it empty. Returns None when the source cannot be
    found, which aborts creation -- a "clone" that silently produced an
    unrelated blank hunt would be worse than an error.
    """
    source_file = manager.find_hunt_file(clone_id)
    if not source_file:
        console.print(f"[red]Error: Clone source not found: {clone_id}[/red]")
        return None

    try:
        from hecate_agent.core.hunt_parser import parse_hunt_file_fast

        source_fm = parse_hunt_file_fast(source_file).get("frontmatter", {})
        if not technique and source_fm.get("techniques"):
            technique = source_fm["techniques"][0]
        if not tactic and source_fm.get("tactics"):
            tactic = tuple(source_fm["tactics"])
        if not platform and source_fm.get("platform"):
            platform = tuple(source_fm["platform"])
        if not data_source and source_fm.get("data_sources"):
            data_source = tuple(source_fm["data_sources"])
        if not title and source_fm.get("title"):
            title = f"Clone of {source_fm['title']}"
        console.print(f"[dim]Cloning metadata from {clone_id}...[/dim]")
    except Exception as e:  # noqa: BLE001 - a bad source degrades to a blank hunt
        console.print(f"[yellow]Warning: Could not clone from {clone_id}: {e}[/yellow]")

    return technique, tactic, platform, data_source, title


def _research_link_is_usable(research: str) -> bool:
    """Whether a --research value can be linked.

    A malformed ID stops creation; a well-formed ID whose document is missing
    only warns, because the hunt is still worth having and the link can be
    repaired later.
    """
    if not validate_research_id(research):
        console.print(f"[red]Error: Invalid research ID format: {research}[/red]")
        console.print("[yellow]Expected format: R-0001[/yellow]")
        return False

    research_file = Path("research") / f"{research}.md"
    # Containment check: a crafted ID must not reach outside research/.
    try:
        research_file.resolve().relative_to(Path("research").resolve())
    except (ValueError, OSError):
        console.print("[red]Error: Invalid research path[/red]")
        return False

    if not research_file.exists():
        console.print(f"[yellow]Warning: Research document {research} not found at {research_file}[/yellow]")
        console.print("[yellow]Hunt will still be created, but research link may be broken.[/yellow]\n")

    return True


def _gather_hunt_details(
    non_interactive: bool,
    config: dict,
    title: Optional[str],
    technique: Optional[str],
    tactic: Tuple[str, ...],
    platform: Tuple[str, ...],
    data_source: Tuple[str, ...],
) -> Optional[Tuple[str, str, list, list, list]]:
    """Collect title, technique, tactics, platforms and data sources.

    Returns None when non-interactive mode is missing the one field it cannot
    default. Interactive prompts are seeded from the same flags and defaults
    the non-interactive path would have used, so the two agree.
    """
    if non_interactive:
        if not title:
            console.print("[red]Error: --title required in non-interactive mode[/red]")
            return None
        hunt_technique = technique or "T1005"
        derived = _default_tactics_for_technique(hunt_technique)
        return (
            title,
            hunt_technique,
            list(tactic) if tactic else (derived or ["collection"]),
            list(platform) if platform else ["Windows"],
            list(data_source) if data_source else ["SIEM", "EDR"],
        )

    console.print("\n[bold]🔍 Let's build your hypothesis:[/bold]")
    hunt_technique = Prompt.ask("1. MITRE ATT&CK Technique (e.g., T1003.001)", default=technique or "")
    hunt_title = Prompt.ask("2. Hunt Title", default=title or f"Hunt for {hunt_technique}")

    console.print("\n3. Primary Tactic(s) (comma-separated):")
    console.print("   Common: [cyan]persistence, credential-access, collection, lateral-movement[/cyan]")
    if tactic:
        tactic_default = ",".join(tactic)
    else:
        derived = _default_tactics_for_technique(hunt_technique)
        tactic_default = ",".join(derived) if derived else "collection"
    tactic_input = Prompt.ask("   Tactics", default=tactic_default)

    console.print("\n4. Target Platform(s) (comma-separated):")
    console.print("   Options: [cyan]Windows, Linux, macOS, Cloud, Network[/cyan]")
    platform_input = Prompt.ask("   Platforms", default=",".join(platform) if platform else "Windows")

    console.print("\n5. Data Sources (comma-separated):")
    console.print(f"   Examples: [cyan]{config.get('siem', 'SIEM')}, {config.get('edr', 'EDR')}, Network Logs[/cyan]")
    default_sources = ",".join(data_source) if data_source else f"{config.get('siem', 'SIEM')}, {config.get('edr', 'EDR')}"
    ds_input = Prompt.ask("   Data Sources", default=default_sources)

    return (
        hunt_title,
        hunt_technique,
        [t.strip() for t in tactic_input.split(",")],
        [p.strip() for p in platform_input.split(",")],
        [ds.strip() for ds in ds_input.split(",")],
    )


def _link_back_to_research(research: str, hunt_id: str) -> None:
    """Record the new hunt on its source research document (issue #14).

    Best-effort: the hunt file already exists by this point.
    """
    try:
        from hecate_agent.core.research_manager import ResearchManager

        if ResearchManager().link_hunt_to_research(research, hunt_id):
            console.print(f"[dim]Linked {hunt_id} to research {research}[/dim]")
        else:
            console.print(f"[yellow]Warning: Could not link {hunt_id} to research {research}[/yellow]")
    except Exception as e:  # noqa: BLE001 - the hunt itself already succeeded
        console.print(f"[yellow]Warning: Could not update research document: {e}[/yellow]")


@click.command()
@click.option("--technique", help="MITRE ATT&CK technique (e.g., T1003.001)")
@click.option("--title", help="Hunt title")
@click.option("--tactic", multiple=True, help="MITRE tactics (can specify multiple)")
@click.option("--platform", multiple=True, help="Target platforms (can specify multiple)")
@click.option("--data-source", multiple=True, help="Data sources (can specify multiple)")
@click.option("--test", is_flag=True, help="Create as test hunt (hunts/test/...) instead of production")
@click.option("--non-interactive", is_flag=True, help="Skip interactive prompts")
@click.option("--hypothesis", help="Full hypothesis statement")
@click.option("--threat-context", help="Threat intel or context motivating the hunt")
@click.option("--actor", help="Threat actor (for ABLE framework)")
@click.option("--behavior", help="Behavior description (for ABLE framework)")
@click.option("--location", help="Location/scope (for ABLE framework)")
@click.option("--evidence", help="Evidence description (for ABLE framework)")
@click.option("--hunter", help="Hunter name (default: from config, then 'Analyst')", default=None)
@click.option("--assignee", help="Assign the hunt to a team member", default=None)
@click.option("--clone", "clone_id", help="Clone metadata from an existing hunt (e.g., H-0013)")
@click.option("--research", help="Research document ID (e.g., R-0001) this hunt is based on")
@click.option(
    "--hypothesis-duration",
    type=float,
    default=None,
    help="Hypothesis generation duration in minutes (from hecate-agent agent run output)",
)
def new(
    technique: Optional[str],
    title: Optional[str],
    tactic: Tuple[str, ...],
    platform: Tuple[str, ...],
    data_source: Tuple[str, ...],
    test: bool,
    non_interactive: bool,
    hypothesis: Optional[str],
    threat_context: Optional[str],
    actor: Optional[str],
    behavior: Optional[str],
    location: Optional[str],
    evidence: Optional[str],
    hunter: Optional[str],
    assignee: Optional[str],
    clone_id: Optional[str],
    research: Optional[str],
    hypothesis_duration: Optional[float],
) -> None:
    """Create a new hunt hypothesis with LOCK structure.

    \b
    Creates a hunt file with:
    • Auto-generated hunt ID (H-XXXX format)
    • YAML frontmatter with metadata
    • LOCK pattern sections (Learn, Observe, Check, Keep)
    • MITRE ATT&CK mapping
    • Optional link to research document

    \b
    Interactive mode (default):
      Guides you through hunt creation with prompts and suggestions.
      Example: hecate-agent hunt new

    \b
    Non-interactive mode:
      Provide all details via options for scripting.
      Example: hecate-agent hunt new --technique T1003.001 --title "LSASS Dumping" \\
               --tactic credential-access --platform Windows --non-interactive

    \b
    With research document:
      Link a pre-hunt research document to the hunt.
      Example: hecate-agent hunt new --research R-0001 --title "Hunt Title" --non-interactive

    \b
    After creation:
      1. Edit hunts/H-XXXX.md to flesh out your hypothesis
      2. Create query in queries/H-XXXX.spl
      3. Execute hunt and document in runs/H-XXXX_YYYY-MM-DD.md
    """
    console.print("\n[bold cyan]🎯 Creating new hunt[/bold cyan]\n")

    # Load config
    config_path = get_config_path()
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    else:
        config = {"hunt_prefix": "H-"}

    hunt_prefix = config.get("hunt_prefix", "H-")

    # Resolve hunter: CLI flag > config > fallback
    hunter = hunter or config.get("hunter") or "Analyst"

    manager = HuntManager()

    # --clone: pre-populate metadata from an existing hunt
    if clone_id:
        cloned = _clone_defaults(manager, clone_id, technique, tactic, platform, data_source, title)
        if cloned is None:
            return
        technique, tactic, platform, data_source, title = cloned

    if research and not _research_link_is_usable(research):
        return

    details = _gather_hunt_details(non_interactive, config, title, technique, tactic, platform, data_source)
    if details is None:
        return
    hunt_title, hunt_technique, hunt_tactics, hunt_platforms, hunt_data_sources = details

    # Allocated only now, after every prompt: the ID is reserved in the shared
    # counter, so an abandoned prompt would otherwise spend one.
    hunt_id = manager.allocate_hunt_id(prefix=hunt_prefix)
    console.print(f"[bold]Hunt ID:[/bold] {hunt_id}")

    # Render template
    hunt_content = render_hunt_template(
        hunt_id=hunt_id,
        title=hunt_title,
        technique=hunt_technique,
        tactics=hunt_tactics,
        platform=hunt_platforms,
        data_sources=hunt_data_sources,
        hunter=hunter,
        hypothesis=hypothesis,
        threat_context=threat_context,
        actor=actor,
        behavior=behavior,
        location=location,
        evidence=evidence,
        spawned_from=research,
        hypothesis_duration_minutes=hypothesis_duration,
        assignee=assignee,
    )

    # Write hunt file using hierarchical directory structure
    hunt_dir = workspace_root() / get_hunt_directory(is_test=test)
    hunt_dir.mkdir(parents=True, exist_ok=True)
    hunt_file = hunt_dir / f"{hunt_id}.md"

    # Validate path is within hunts directory (Python 3.8 compatible)
    try:
        hunt_file.resolve().relative_to((workspace_root() / "hunts").resolve())
    except (ValueError, OSError):
        console.print("[red]Error: Invalid hunt file path[/red]")
        return

    atomic_write_text(hunt_file, hunt_content)

    console.print(f"\n[bold green]✅ Created {hunt_id}: {hunt_title}[/bold green]")

    if research:
        _link_back_to_research(research, hunt_id)

    # Easter egg: Hunt #100 milestone
    if hunt_id.endswith("0100"):
        console.print("\n[bold yellow]✨ Milestone Achievement: Hunt #100 ✨[/bold yellow]\n")
        console.print("[italic]You've built serious hunting muscle memory.")
        console.print("This is where threat hunting programs transform from reactive to proactive.")
        console.print("Keep building that institutional knowledge.[/italic]\n")

    console.print("\n[bold]Next steps:[/bold]")
    console.print(f"  1. Edit [cyan]{hunt_file}[/cyan] to flesh out your hypothesis")
    console.print("  2. Document your hunt using the LOCK pattern")
    console.print("  3. View all hunts: [cyan]hecate-agent hunt list[/cyan]")


@click.command(name="new-baseline")
@click.option("--title", help="Baseline hunt title")
@click.option("--dimension", help="Field or behavior being characterized (e.g. 'parent-child process pairs')")
@click.option("--platform", multiple=True, help="Target platforms (can specify multiple)")
@click.option("--data-source", multiple=True, help="Data sources (can specify multiple)")
@click.option("--objective", help="Why this baseline matters / what it's establishing")
@click.option("--hunter", help="Hunter name (default: from config, then 'Analyst')", default=None)
@click.option("--test", is_flag=True, help="Create as test hunt (hunts/test/...) instead of production")
@click.option("--non-interactive", is_flag=True, help="Skip interactive prompts")
def new_baseline(
    title: Optional[str],
    dimension: Optional[str],
    platform: Tuple[str, ...],
    data_source: Tuple[str, ...],
    objective: Optional[str],
    hunter: Optional[str],
    test: bool,
    non_interactive: bool,
) -> None:
    """Create a new baseline (EDA) hunt -- PEAK's hypothesis-free hunt type.

    \b
    Unlike `hunt new`, a baseline hunt has no hypothesis: it characterizes
    "what's normal" for a dimension (a field, a behavior pattern) so
    candidate anomalies can be identified and spun into hypothesis-driven
    follow-up hunts later. Uses the same H-XXXX ID sequence and LOCK section
    headings as regular hunts (so `hunt list`, `hunt validate`, `hunt export`,
    and `hunt brief` all work on it unchanged) -- filter to just this type
    with `hunt list --type baseline`.

    \b
    Examples:
      hecate-agent hunt new-baseline --title "Parent-Child Process Baseline" \\
          --dimension "parent_process -> child_process pairs" \\
          --platform Windows --data-source EDR --non-interactive

    \b
    After creation:
      1. Run frequency/cardinality/rarity queries and document "what's normal"
      2. Record candidate anomalies in the KEEP section
      3. For anomalies worth pursuing: hecate-agent hunt new --hypothesis "..." then
         set spawned_from to this baseline's hunt_id, and add the new hunt's
         ID to this baseline's related_hunts
    """
    console.print("\n[bold cyan]📊 Creating new baseline hunt[/bold cyan]\n")

    config_path = get_config_path()
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    else:
        config = {"hunt_prefix": "H-"}

    hunt_prefix = config.get("hunt_prefix", "H-")

    # Resolve hunter: CLI flag > config > fallback
    hunter = hunter or config.get("hunter") or "Analyst"

    manager = HuntManager()

    if non_interactive:
        if not title:
            console.print("[red]Error: --title required in non-interactive mode[/red]")
            return
        baseline_title = title
        baseline_dimension = dimension
        baseline_platforms = list(platform) if platform else ["Windows"]
        baseline_data_sources = list(data_source) if data_source else ["SIEM", "EDR"]
    else:
        console.print("\n[bold]📊 Let's scope your baseline:[/bold]")

        baseline_dimension = Prompt.ask(
            "1. Dimension being characterized (e.g. 'parent-child process pairs')", default=dimension or ""
        )
        baseline_title = Prompt.ask("2. Baseline Title", default=title or f"Baseline: {baseline_dimension}")

        console.print("\n3. Target Platform(s) (comma-separated):")
        console.print("   Options: [cyan]Windows, Linux, macOS, Cloud, Network[/cyan]")
        platform_input = Prompt.ask("   Platforms", default=",".join(platform) if platform else "Windows")
        baseline_platforms = [p.strip() for p in platform_input.split(",")]

        console.print("\n4. Data Sources (comma-separated):")
        default_sources = ",".join(data_source) if data_source else f"{config.get('siem', 'SIEM')}, {config.get('edr', 'EDR')}"
        ds_input = Prompt.ask("   Data Sources", default=default_sources)
        baseline_data_sources = [ds.strip() for ds in ds_input.split(",")]

    # Allocated only now, after every prompt: the ID is reserved in the shared
    # counter, so an abandoned prompt would otherwise spend one.
    hunt_id = manager.allocate_hunt_id(prefix=hunt_prefix)
    console.print(f"[bold]Hunt ID:[/bold] {hunt_id}")

    baseline_content = render_baseline_template(
        hunt_id=hunt_id,
        title=baseline_title,
        dimension=baseline_dimension,
        platform=baseline_platforms,
        data_sources=baseline_data_sources,
        hunter=hunter,
        objective=objective,
    )

    hunt_dir = workspace_root() / get_hunt_directory(is_test=test)
    hunt_dir.mkdir(parents=True, exist_ok=True)
    hunt_file = hunt_dir / f"{hunt_id}.md"

    try:
        hunt_file.resolve().relative_to((workspace_root() / "hunts").resolve())
    except (ValueError, OSError):
        console.print("[red]Error: Invalid hunt file path[/red]")
        return

    atomic_write_text(hunt_file, baseline_content)

    console.print(f"\n[bold green]✅ Created {hunt_id}: {baseline_title}[/bold green]")
    console.print("\n[bold]Next steps:[/bold]")
    console.print(f"  1. Edit [cyan]{hunt_file}[/cyan] to run baseline queries and document what's normal")
    console.print("  2. Record candidate anomalies in the KEEP section")
    console.print("  3. Spin worthwhile anomalies into hypothesis-driven hunts: [cyan]hecate-agent hunt new[/cyan]")


@click.command(name="new-model-assisted")
@click.option("--title", help="Hunt title")
@click.option(
    "--model-type", "model_type", help="Statistical/ML model type (clustering, z-score, IQR, isolation-forest, other)"
)
@click.option("--features", help="Comma-separated list of fields/dimensions fed into the model")
@click.option("--anomaly-threshold", "anomaly_threshold", help="Anomaly score cutoff value")
@click.option("--dataset", help="Table, index, or data source being modeled")
@click.option("--platform", multiple=True, help="Target platforms (can specify multiple)")
@click.option("--data-source", multiple=True, help="Data sources (can specify multiple)")
@click.option("--objective", help="Why model-assisted over manual EDA")
@click.option("--hunter", help="Hunter name (default: from config, then 'Analyst')", default=None)
@click.option("--test", is_flag=True, help="Create as test hunt (hunts/test/...) instead of production")
@click.option("--non-interactive", is_flag=True, help="Skip interactive prompts")
def new_model_assisted(
    title: Optional[str],
    model_type: Optional[str],
    features: Optional[str],
    anomaly_threshold: Optional[str],
    dataset: Optional[str],
    platform: Tuple[str, ...],
    data_source: Tuple[str, ...],
    objective: Optional[str],
    hunter: Optional[str],
    test: bool,
    non_interactive: bool,
) -> None:
    """Create a new model-assisted (M-ATH) hunt -- PEAK's third Execute-phase hunt type.

    \b
    Unlike hypothesis-driven or baseline hunts, a model-assisted hunt uses
    statistical or ML models (clustering, z-score, IQR, isolation forest) over
    telemetry to surface anomalies at scale -- useful when data volume makes
    manual EDA impractical. Anomalies surfaced here become leads for
    hypothesis-driven follow-up hunts. Uses the same H-XXXX ID sequence and
    LOCK section headings as other hunt types -- filter with
    `hunt list --type model-assisted`.

    \b
    Examples:
      hecate-agent hunt new-model-assisted --title "Process Execution Clustering" \\
          --model-type clustering --features "process.name,parent.process.name,user.name" \\
          --dataset "endpoint_events" --platform Windows --data-source EDR --non-interactive

    \b
    After creation:
      1. Extract feature vectors and run model, document anomaly score distribution
      2. Record candidate leads in the KEEP section
      3. For leads worth pursuing: hecate-agent hunt new --hypothesis "..." then
         set spawned_from to this hunt's ID, and add the new hunt's ID to
         this hunt's related_hunts
    """
    console.print("\n[bold cyan]🤖 Creating new model-assisted hunt[/bold cyan]\n")

    config_path = get_config_path()
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    else:
        config = {"hunt_prefix": "H-"}

    hunt_prefix = config.get("hunt_prefix", "H-")

    # Resolve hunter: CLI flag > config > fallback
    hunter = hunter or config.get("hunter") or "Analyst"

    manager = HuntManager()

    if non_interactive:
        if not title:
            console.print("[red]Error: --title required in non-interactive mode[/red]")
            return
        math_title = title
        math_model_type = model_type
        math_features = [f.strip() for f in features.split(",")] if features else []
        math_anomaly_threshold = anomaly_threshold
        math_dataset = dataset
        math_platforms = list(platform) if platform else ["Windows"]
        math_data_sources = list(data_source) if data_source else ["SIEM", "EDR"]
    else:
        console.print("\n[bold]🤖 Let's scope your model-assisted hunt:[/bold]")

        math_model_type = Prompt.ask(
            "1. Model type (clustering, z-score, IQR, isolation-forest, other)",
            default=model_type or "z-score",
        )
        math_title = Prompt.ask("2. Hunt Title", default=title or f"Model-Assisted: {math_model_type}")

        features_input = Prompt.ask(
            "3. Features/fields to analyze (comma-separated)",
            default=features or "",
        )
        math_features = [f.strip() for f in features_input.split(",") if f.strip()]

        math_dataset = Prompt.ask("4. Dataset/index being modeled", default=dataset or "")
        math_anomaly_threshold = Prompt.ask("5. Anomaly threshold", default=anomaly_threshold or "")

        console.print("\n6. Target Platform(s) (comma-separated):")
        console.print("   Options: [cyan]Windows, Linux, macOS, Cloud, Network[/cyan]")
        platform_input = Prompt.ask("   Platforms", default=",".join(platform) if platform else "Windows")
        math_platforms = [p.strip() for p in platform_input.split(",")]

        console.print("\n7. Data Sources (comma-separated):")
        default_sources = ",".join(data_source) if data_source else f"{config.get('siem', 'SIEM')}, {config.get('edr', 'EDR')}"
        ds_input = Prompt.ask("   Data Sources", default=default_sources)
        math_data_sources = [ds.strip() for ds in ds_input.split(",")]

    # Allocated only now, after every prompt: the ID is reserved in the shared
    # counter, so an abandoned prompt would otherwise spend one.
    hunt_id = manager.allocate_hunt_id(prefix=hunt_prefix)
    console.print(f"[bold]Hunt ID:[/bold] {hunt_id}")

    math_content = render_math_template(
        hunt_id=hunt_id,
        title=math_title,
        model_type=math_model_type,
        features=math_features,
        anomaly_threshold=math_anomaly_threshold,
        dataset=math_dataset,
        platform=math_platforms,
        data_sources=math_data_sources,
        hunter=hunter,
        objective=objective,
    )

    hunt_dir = workspace_root() / get_hunt_directory(is_test=test)
    hunt_dir.mkdir(parents=True, exist_ok=True)
    hunt_file = hunt_dir / f"{hunt_id}.md"

    try:
        hunt_file.resolve().relative_to((workspace_root() / "hunts").resolve())
    except (ValueError, OSError):
        console.print("[red]Error: Invalid hunt file path[/red]")
        return

    atomic_write_text(hunt_file, math_content)

    console.print(f"\n[bold green]✅ Created {hunt_id}: {math_title}[/bold green]")
    console.print("\n[bold]Next steps:[/bold]")
    console.print(f"  1. Edit [cyan]{hunt_file}[/cyan] to run the model and document anomalies surfaced")
    console.print("  2. Record candidate leads in the KEEP section")
    console.print("  3. Spin worthwhile leads into hypothesis-driven hunts: [cyan]hecate-agent hunt new[/cyan]")
