"""Hunt Sigma rule deduplication and AST subsumption command."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from hecate_agent.core.sigma_subsumption import (
    SigmaDeduplicator,
    SigmaRuleAST,
    SubsumptionRelation,
)

console = Console()


def _resolve_query_paths(target_path: Optional[str], hunt_id: Optional[str]) -> List[Path]:
    """Resolve directory paths to scan for Sigma rules."""
    paths: List[Path] = []
    cwd = Path.cwd()

    if target_path:
        p = Path(target_path)
        if not p.is_absolute():
            p = cwd / p
        if p.exists():
            return [p]
        console.print(f"[yellow]Warning: Specified path '{target_path}' does not exist.[/yellow]")

    # Check for hunt-specific directory
    if hunt_id:
        norm_hunt = hunt_id.upper().strip()
        candidates = [
            cwd / "queries" / norm_hunt,
            Path(f"queries/{norm_hunt}"),
            Path(f"/home/chemch/betas/Hecate-Public/queries/{norm_hunt}"),
            Path(f"/home/chemch/betas/Hecate-Workspace/queries/{norm_hunt}"),
        ]
        for c in candidates:
            if c and c.exists() and c.is_dir():
                return [c]

    # Default discovery paths
    candidates = [
        cwd / "queries",
        Path("queries"),
        Path("/home/chemch/betas/Hecate-Public/queries"),
        Path("/home/chemch/betas/Hecate-Workspace/queries"),
    ]
    seen: set[str] = set()
    for c in candidates:
        if c and c.exists() and c.is_dir():
            resolved = str(c.resolve())
            if resolved not in seen:
                seen.add(resolved)
                paths.append(c)

    return paths


DEDUP_EPILOG = """
\b
Examples:
  # Scan default queries directory for duplicates and subsumptions
  hecate-agent hunt dedup

  # Scan a specific directory
  hecate-agent hunt dedup queries/H-0001/

  # Check if a newly drafted Sigma rule is redundant with existing rules
  hecate-agent hunt dedup --check new_rule.yml

  # Filter analysis to a specific hunt ID
  hecate-agent hunt dedup --hunt H-0001

  # Include partial AST overlaps in the report
  hecate-agent hunt dedup --include-overlapping

  # Output as JSON for automated CI/CD pipeline gating
  hecate-agent hunt dedup --format json

\b
Subsumption Relations:
  • EQUIVALENT: Identical detection space (exact duplicate rule).
  • SUBSUMES: Broader rule that completely covers another rule (narrower rule is redundant).
  • SUBSUMED_BY: Narrower rule completely covered by an existing broader rule.
  • OVERLAPPING: Rules sharing common log sources and fields (consolidation candidates).
"""


@click.command(name="dedup", epilog=DEDUP_EPILOG)
@click.argument("path", required=False, type=click.Path())
@click.option("--check", "check_file", type=click.Path(exists=True), help="Check a candidate rule against the corpus")
@click.option("--hunt", "-h", "hunt_id", default=None, help="Filter analysis to a specific hunt ID (e.g., H-0001)")
@click.option("--threshold", default=0.5, type=float, help="Similarity threshold for overlapping rules (default: 0.5)")
@click.option("--include-overlapping", is_flag=True, default=False, help="Show partial overlaps in results")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "yaml"], case_sensitive=False),
    default="table",
    help="Output format (default: table)",
)
def dedup(
    path: Optional[str],
    check_file: Optional[str],
    hunt_id: Optional[str],
    threshold: float,
    include_overlapping: bool,
    output_format: str,
) -> None:
    """Analyze Sigma detection rules for duplicates, subsumptions, and redundancies."""
    deduplicator = SigmaDeduplicator(overlap_threshold=threshold)
    search_dirs = _resolve_query_paths(path, hunt_id)

    # Collect corpus rules
    corpus_rules: List[SigmaRuleAST] = []
    seen_files: set[str] = set()

    for d in search_dirs:
        for r in deduplicator.load_rules_from_directory(d):
            if r.file_path and r.file_path not in seen_files:
                seen_files.add(r.file_path)
                corpus_rules.append(r)

    # If targeting a specific single file
    if path and Path(path).is_file():
        try:
            corpus_rules = [SigmaRuleAST.from_yaml_file(path)]
        except Exception as e:
            console.print(f"[red]Error loading {path}: {e}[/red]")
            return

    # Branch 1: Checking a candidate rule against the corpus
    if check_file:
        try:
            candidate = SigmaRuleAST.from_yaml_file(check_file)
        except Exception as e:
            console.print(f"[red]Error parsing candidate rule {check_file}: {e}[/red]")
            return

        internal_issues = deduplicator.audit_internal_redundancy(candidate)
        matches = deduplicator.check_candidate(candidate, corpus_rules)

        if output_format == "json":
            out_data = {
                "candidate": {"id": candidate.id, "title": candidate.title, "file": check_file},
                "internal_issues": internal_issues,
                "matches": [m.to_dict() for m in matches],
            }
            click.echo(json.dumps(out_data, indent=2))
            return
        elif output_format == "yaml":
            out_data = {
                "candidate": {"id": candidate.id, "title": candidate.title, "file": check_file},
                "internal_issues": internal_issues,
                "matches": [m.to_dict() for m in matches],
            }
            click.echo(yaml.safe_dump(out_data, sort_keys=False))
            return

        # Render rich check report
        console.print(
            Panel(
                f"[bold]Candidate Rule:[/bold] {candidate.title}\n"
                f"[dim]ID:[/dim] {candidate.id or 'None'} | [dim]Category:[/dim] {candidate.category}\n"
                f"[dim]File:[/dim] {check_file}",
                title="🔍 [bold cyan]Sigma Rule Redundancy Check[/bold cyan]",
                border_style="cyan",
            )
        )

        if internal_issues:
            console.print("\n[bold yellow]⚠️ Internal Redundancies Found in Candidate Rule:[/bold yellow]")
            for issue in internal_issues:
                console.print(f"  • [yellow]{issue}[/yellow]")

        if not matches:
            console.print(
                "\n[bold green]✅ No duplicates or subsumptions found.[/bold green] Rule provides novel detection coverage."
            )
            return

        table = Table(title=f"Corpus Match Diagnostics ({len(matches)} matches)")
        table.add_column("Relation", style="bold")
        table.add_column("Existing Rule Title")
        table.add_column("Score", justify="right")
        table.add_column("Explanation")

        for m in matches:
            style = "green"
            if m.relation == SubsumptionRelation.EQUIVALENT:
                style = "bold red"
            elif m.relation in (SubsumptionRelation.SUBSUMES, SubsumptionRelation.SUBSUMED_BY):
                style = "bold yellow"
            elif m.relation == SubsumptionRelation.OVERLAPPING:
                style = "cyan"

            table.add_row(
                f"[{style}]{m.relation.value}[/{style}]",
                m.rule_b_title,
                f"{m.overlap_score:.0%}",
                m.explanation,
            )
        console.print(table)
        return

    # Branch 2: Scanning the corpus for all duplicates and subsumptions
    if not corpus_rules:
        console.print("[yellow]No Sigma rules found in specified query locations.[/yellow]")
        return

    report = deduplicator.analyze_corpus(corpus_rules, include_overlaps=include_overlapping)

    if output_format == "json":
        click.echo(report.to_json(indent=2))
        return
    elif output_format == "yaml":
        click.echo(yaml.safe_dump(report.to_dict(), sort_keys=False))
        return

    # Rich summary table
    console.print(
        Panel(
            f"[bold]Total Rules Scanned:[/bold] {report.total_rules}\n"
            f"[bold red]Duplicates (Equivalent):[/bold red] {len(report.duplicates)}\n"
            f"[bold yellow]Subsumptions (Broader/Narrower):[/bold yellow] {len(report.subsumptions)}\n"
            f"[bold cyan]Overlaps (Candidates for consolidation):[/bold cyan] {len(report.overlaps)}\n"
            f"[bold magenta]Internal Redundancies:[/bold magenta] {sum(len(v) for v in report.internal_redundancies.values())}",
            title="📊 [bold green]Sigma Deduplication & Subsumption Summary[/bold green]",
            border_style="green" if not report.has_issues else "yellow",
        )
    )

    # Show duplicates
    if report.duplicates:
        table_dup = Table(title=f"Exact Duplicates ({len(report.duplicates)})", border_style="red")
        table_dup.add_column("Rule A", style="bold")
        table_dup.add_column("Rule B", style="bold")
        table_dup.add_column("Category")
        table_dup.add_column("Details")
        for duplicate in report.duplicates:
            table_dup.add_row(
                duplicate.rule_a_title,
                duplicate.rule_b_title,
                Path(duplicate.rule_a_file).parent.name if duplicate.rule_a_file else "",
                duplicate.explanation,
            )
        console.print(table_dup)

    # Show subsumptions
    if report.subsumptions:
        table_sub = Table(title=f"Subsumption Hierarchies ({len(report.subsumptions)})", border_style="yellow")
        table_sub.add_column("Relation", style="bold yellow")
        table_sub.add_column("Rule A (Broader)")
        table_sub.add_column("Rule B (Narrower / Redundant)")
        table_sub.add_column("Explanation")
        for s in report.subsumptions:
            table_sub.add_row(
                s.relation.value,
                s.rule_a_title,
                s.rule_b_title,
                s.explanation,
            )
        console.print(table_sub)

    # Show overlaps if requested
    if include_overlapping and report.overlaps:
        table_ov = Table(title=f"Significant Overlaps ({len(report.overlaps)})", border_style="cyan")
        table_ov.add_column("Rule A")
        table_ov.add_column("Rule B")
        table_ov.add_column("Similarity", justify="right")
        table_ov.add_column("Shared Fields")
        for o in report.overlaps:
            table_ov.add_row(
                o.rule_a_title,
                o.rule_b_title,
                f"{o.overlap_score:.0%}",
                ", ".join(o.shared_fields),
            )
        console.print(table_ov)

    # Show internal redundancies
    if report.internal_redundancies:
        console.print("\n[bold magenta]⚠️ Internal Redundancies within Single Rules:[/bold magenta]")
        for rule_key, issues in report.internal_redundancies.items():
            console.print(f"  • [bold]{rule_key}[/bold]:")
            for iss in issues:
                console.print(f"      - {iss}")

    if not report.has_issues and not (include_overlapping and report.overlaps):
        console.print(
            "\n[bold green]✅ Clean corpus: No duplicates, redundant subsumptions, or internal dead code detected.[/bold green]"
        )
