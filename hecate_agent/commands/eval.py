"""Model-quality eval harness CLI — scripted known-answer spot checks.

Replaces manually asking a model "what is T1003.001?" and eyeballing the
answer with a repeatable command, so a model swap (or provider swap) can be
checked for confident hallucination before it goes into production.
"""

import json
from pathlib import Path
from typing import Any, Optional

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

console = Console()

EVAL_EPILOG = """
\b
Examples:
  # Eval the currently configured provider/model
  hecate-agent eval

  # Eval a specific model without changing your .env
  hecate-agent eval --provider ollama --model qwen2.5:14b-instruct-q4_K_M

  # Compare two models by running each and diffing the score
  hecate-agent eval --model qwen2.5:7b-instruct-q4_K_M --output json > 7b.json
  hecate-agent eval --model qwen2.5:14b-instruct-q4_K_M --output json > 14b.json

  # Isolate "does the model know this fact" from "can it use a fact it's
  # handed" — grounds the same technique fixtures with real STIX data
  # instead of asking the model to recall them cold
  hecate-agent eval --grounded

  # Gate demoting a locked capability (hypothesis/Sigma/…) onto the simple tier
  hecate-agent eval --tier simple --write-gate research_synthesize --fail-under 0.8

\b
What it checks:
  A small set of unambiguous, known-answer fixtures (mostly MITRE ATT&CK
  technique-ID recall) that catch confident hallucination — e.g. a model
  answering "System Information Discovery" for T1003.001 instead of
  "OS Credential Dumping: LSASS Memory". Not a general capability benchmark.
"""


def _print_eval_report(report: Any) -> None:
    """Render the per-fixture table, the score, and any failures."""
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Fixture", style="cyan", no_wrap=True)
    table.add_column("Category", style="dim")
    table.add_column("Result")
    table.add_column("Duration", justify="right", style="dim")
    table.add_column("Notes", style="dim")

    for r in report.results:
        result_str = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
        notes = r.error or (r.response_text[:60] + "..." if len(r.response_text) > 60 else r.response_text)
        table.add_row(r.fixture.id, r.fixture.category, result_str, f"{r.duration_ms / 1000:.1f}s", notes)

    console.print(table)
    console.print(
        f"\n[bold]Score:[/bold] {report.passed_count}/{report.total_count} "
        f"({report.score * 100:.0f}%)  [dim]({report.total_duration_ms / 1000:.1f}s total)[/dim]"
    )

    if report.score < 1.0:
        console.print("\n[yellow]Failed fixtures:[/yellow]")
        for r in report.results:
            if not r.passed:
                console.print(f"  [red]✗[/red] {r.fixture.id} ({r.fixture.description})")
                if r.error:
                    console.print(f"      error: {r.error}")
                else:
                    console.print(f"      got: {r.response_text[:150]}")


@click.command(name="eval", epilog=EVAL_EPILOG)
@click.option("--provider", help="Override the configured LLM provider (e.g. ollama, litellm, bedrock)")
@click.option("--model", help="Override the configured model")
@click.option("--output", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option(
    "--temperature",
    type=float,
    default=0.0,
    help="Sampling temperature. Defaults to 0.0 (deterministic) so results are reproducible run to run.",
)
@click.option(
    "--grounded",
    is_flag=True,
    help=(
        "Test STIX-grounded MITRE technique fixtures instead of cold recall — hands the model "
        "the real technique name/description and asks it to summarize, instead of asking it to "
        "recall the fact unaided. Separates 'does the model know this' from 'can it use a fact "
        "it's given', which points at whether to fix retrieval/prompting vs. chase a bigger model."
    ),
)
@click.option(
    "--tier",
    type=click.Choice(["simple", "complex"]),
    default=None,
    help="Eval the dual-router simple or complex backend instead of the legacy single provider.",
)
@click.option(
    "--fail-under",
    type=float,
    default=None,
    help="Exit 1 when the score (0-1) is below this threshold.",
)
@click.option(
    "--write-gate",
    "write_gate",
    default=None,
    help=(
        "If the score meets --fail-under (default 0.8), write a demotion gate stamp unlocking "
        "this locked capability for simple-tier routing (e.g. research_synthesize)."
    ),
)
def eval_cmd(
    provider: Optional[str],
    model: Optional[str],
    output_format: str,
    temperature: float,
    grounded: bool,
    tier: Optional[str],
    fail_under: Optional[float],
    write_gate: Optional[str],
) -> None:
    """Run known-answer fixtures against an LLM provider and score the result."""
    from hecate_agent.core.eval_harness import build_grounded_fixtures, run_eval
    from hecate_agent.core.llm_demotion import (
        DEFAULT_FAIL_UNDER,
        DemotionGateResult,
        write_demotion_gate,
    )
    from hecate_agent.core.llm_provider import create_provider
    from hecate_agent.core.llm_router import create_router

    config: dict[str, str] = {}
    if provider:
        config["provider"] = provider
    if model:
        config["model"] = model

    try:
        if tier is not None:
            llm_provider = create_router(config or None).provider_for(tier=tier)
        else:
            llm_provider = create_provider(config or None)
    except (RuntimeError, ValueError) as exc:
        console.print(f"[red]Could not create LLM provider: {exc}[/red]")
        raise click.Abort()

    fixtures = build_grounded_fixtures() if grounded else None

    if output_format == "table":
        mode = "grounded (STIX-fed)" if grounded else "cold recall"
        tier_note = f", tier={tier}" if tier else ""
        console.print(
            f"\n[bold cyan]Running eval:[/bold cyan] {llm_provider.provider_name} / "
            f"{getattr(llm_provider, 'model', 'unknown')} [dim]({mode}{tier_note})[/dim]"
        )
        console.print("[dim]This makes one LLM call per fixture — may take a few minutes on a local model.[/dim]\n")

    report = run_eval(llm_provider, fixtures=fixtures, temperature=temperature)
    threshold = fail_under if fail_under is not None else (DEFAULT_FAIL_UNDER if write_gate else None)

    if write_gate:
        gate_threshold = threshold if threshold is not None else DEFAULT_FAIL_UNDER
        gate = DemotionGateResult(
            capability=write_gate,
            allowed=report.score >= gate_threshold,
            score=report.score,
            fail_under=gate_threshold,
            provider=llm_provider.provider_name,
            model=str(getattr(llm_provider, "model", getattr(llm_provider, "model_id", "unknown"))),
            reason=(
                f"score {report.score:.3f} meets fail_under {gate_threshold:.3f}"
                if report.score >= gate_threshold
                else f"score {report.score:.3f} below fail_under {gate_threshold:.3f}"
            ),
            report=report,
        )
        if gate.allowed:
            path = write_demotion_gate(gate)
            if output_format == "table":
                console.print(
                    f"[green]Demotion gate written[/green] for `{write_gate}` → {path}"
                )
        elif output_format == "table":
            console.print(
                f"[yellow]Demotion gate not written[/yellow] for `{write_gate}`: {gate.reason}"
            )

    if output_format == "json":
        payload = report.to_dict()
        if write_gate:
            payload["demotion_gate"] = {
                "capability": write_gate,
                "allowed": report.score >= (threshold or DEFAULT_FAIL_UNDER),
                "fail_under": threshold or DEFAULT_FAIL_UNDER,
            }
        console.print(json.dumps(payload, indent=2), soft_wrap=True)
        if threshold is not None and report.score < threshold:
            raise SystemExit(1)
        return

    _print_eval_report(report)
    if threshold is not None and report.score < threshold:
        console.print(
            f"\n[red]Score {report.score:.3f} is below fail-under {threshold:.3f}[/red]"
        )
        raise SystemExit(1)


EVAL_GOLD_EPILOG = """
\b
Examples:
  # Score a draft against a reviewed gold set
  hecate-agent eval-gold evals/gold/vshell-fake-resume.yaml hunts/2026/Q3/H-0618.md

  # Compare two pipeline versions on the same CTI
  hecate-agent eval-gold GOLD before/H-0618.md --output json > before.json
  hecate-agent eval-gold GOLD after/H-0618.md --output json > after.json

  # Gate a script or CI job on a minimum score
  hecate-agent eval-gold GOLD DRAFT --fail-under 0.6

\b
What it checks (no model calls, so scores are comparable across runs):
  techniques      each reviewed observed technique (the recall denominator)
                  and each technique the source rules out
  platform        expected platforms present, unsupported ones absent
  claims          statements the draft's own prose must and must not make
  indicators      each artifact placed only where its role allows
  detections      expected detections, same-selection AND semantics
  rule semantics  fields outside their category, non-executable process
                  images, descriptions that promise more than the rule does
"""


@click.command(name="eval-gold", epilog=EVAL_GOLD_EPILOG)
@click.argument("gold_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("draft_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--queries",
    "queries_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Rule directory to score (default: <workspace>/queries/<hunt_id>, else the rules embedded in the draft)",
)
@click.option("--output", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option("--fail-under", type=float, default=None, help="Exit 1 when the score (0-1) is below this")
def eval_gold_cmd(
    gold_path: Path, draft_path: Path, queries_dir: Optional[Path], output_format: str, fail_under: Optional[float]
) -> None:
    """Score a drafted hunt against a reviewed gold set."""
    from hecate_agent.core.gold_eval import load_gold, score_draft

    try:
        report = score_draft(load_gold(gold_path), draft_path, queries_dir)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(2)

    if output_format == "json":
        click.echo(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_gold_report(report)

    if fail_under is not None and report.score < fail_under:
        raise SystemExit(1)


def _print_gold_report(report: Any) -> None:
    console.print(f"[bold]Gold case:[/bold] {report.case_id}   [bold]Draft:[/bold] {report.draft}")
    console.print(f"[dim]Rules scored: {report.rules_scored} ({report.rules_source})[/dim]\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Dimension", style="cyan")
    table.add_column("Passed", justify="right")
    for dimension, (passed, total) in report.dimensions().items():
        colour = "green" if passed == total else "yellow" if passed else "red"
        table.add_row(dimension, f"[{colour}]{passed}/{total}[/{colour}]")
    console.print(table)

    console.print(
        f"\n[bold]Score:[/bold] {report.passed}/{report.total} checks ({report.score:.1%})\n"
        f"[bold]Technique recall:[/bold] {len(report.technique_hits)}/{report.technique_denominator} "
        f"({report.technique_recall:.1%}), denominator = the gold set's reviewed observed techniques"
    )
    if report.acceptable_found:
        console.print(f"[dim]Acceptable, not required: {', '.join(report.acceptable_found)}[/dim]")
    if report.unreviewed_techniques:
        console.print(f"[yellow]Not in the gold set (review them): {', '.join(report.unreviewed_techniques)}[/yellow]")

    failures = [c for c in report.checks if not c.passed]
    if failures:
        console.print(f"\n[bold red]Failed checks ({len(failures)}):[/bold red]")
        for check in failures:
            detail = f" — {check.detail}" if check.detail else ""
            console.print(f"  [red]✗[/red] {escape(f'[{check.dimension}] {check.id}{detail}')}")
