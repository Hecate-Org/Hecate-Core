"""Explicit live model evaluations and offline report comparison."""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click

from hecate_agent.core import model_quality
from hecate_agent.core.model_quality import DEFAULT_SUITE, compare_reports, load_suite, rescore_report, run_suite


@click.command("eval-suite")
@click.option("--suite", type=click.Path(path_type=Path, exists=True), default=DEFAULT_SUITE, show_default=True)
@click.option("--validate-only", is_flag=True, help="Validate cases offline; never instantiate a provider.")
@click.option(
    "--rescore", type=click.Path(path_type=Path, exists=True), help="Score a saved response report offline; no model calls."
)
@click.option("--provider", type=click.Choice(["ollama", "litellm", "bedrock", "openai"]))
@click.option("--model", help="Explicit model ID; no automatic provider/model fallback.")
@click.option("--repeats", type=click.IntRange(1, 10), default=1, show_default=True)
@click.option("--max-tokens", type=click.IntRange(64, 4096), default=512, show_default=True)
@click.option("--fail-under", type=click.FloatRange(0, 1), default=0.85, show_default=True)
@click.option("--max-cost-usd", type=click.FloatRange(min=0, min_open=True), default=1.0, show_default=True)
@click.option(
    "--report", type=click.Path(path_type=Path), help="Write a JSON artifact; refuses to overwrite an existing file."
)
def eval_suite_cmd(
    suite: Path,
    validate_only: bool,
    rescore: Path | None,
    provider: str | None,
    model: str | None,
    repeats: int,
    max_tokens: int,
    fail_under: float,
    max_cost_usd: float,
    report: Path | None,
) -> None:
    """Run reviewed task gold cases (live only when explicitly requested).

    This does not change routing or write demotion gates. API cost is estimated;
    local electricity/GPU cost is not metered. For release checks use --repeats 3.
    """
    try:
        cases = load_suite(suite)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from None
    if rescore and (validate_only or provider or model):
        raise click.UsageError("--rescore cannot be combined with live model selection or --validate-only")
    if validate_only:
        click.echo(json.dumps({"suite_id": cases["suite_id"], "cases": len(cases["cases"]), "valid": True}))
        return
    if not rescore and (not provider or not model):
        raise click.UsageError("Live evaluation requires both --provider and --model")
    if report and report.exists():
        raise click.ClickException("Report already exists; choose a fresh path")
    code_sha256 = hashlib.sha256(Path(model_quality.__file__).read_bytes()).hexdigest()

    def progress(result: dict[str, Any]) -> None:
        click.echo(
            f"{result['id']} #{result['repeat']}: {result['status']} / {'PASS' if result['passed'] else 'FAIL'}", err=True
        )

    if rescore:
        try:
            payload = rescore_report(json.loads(rescore.read_text()), cases)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise click.ClickException("Cannot rescore report: " + str(exc)) from None
    else:
        from hecate_agent.core.llm_provider import create_provider

        try:
            backend = create_provider({"provider": provider, "model": model})
        except Exception as exc:
            raise click.ClickException("Provider setup failed: " + type(exc).__name__) from None
        payload = run_suite(
            backend,
            cases,
            repeats=repeats,
            max_tokens=max_tokens,
            fail_under=fail_under,
            max_cost_usd=max_cost_usd,
            progress=progress,
        )
        if provider == "ollama":
            payload["provider_options"] = {"think": backend.think, "num_ctx": backend.num_ctx}  # type: ignore[attr-defined]
    payload["checked_at_utc"] = datetime.now(timezone.utc).isoformat()
    payload["evaluation_code_sha256"] = code_sha256
    encoded = json.dumps(payload, indent=2) + "\n"
    if report:
        # Exclusive creation prevents symlink writes or accidental baseline replacement.
        with report.open("x", encoding="utf-8") as handle:
            handle.write(encoded)
    sys.stdout.write(encoded)
    if not payload["gate_passed"]:
        raise click.exceptions.Exit(1)


@click.command("eval-compare")
@click.argument("reports", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("--output", type=click.Choice(["table", "json"]), default="table")
@click.option("--check", is_flag=True, help="Exit 1 for a failed gate or a case regression against the first report.")
def eval_compare_cmd(reports: tuple[Path, ...], output: str, check: bool) -> None:
    """Compare compatible JSON reports offline. The first report is the baseline."""
    try:
        comparison = compare_reports([json.loads(path.read_text()) for path in reports])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise click.ClickException(str(exc)) from None
    if output == "json":
        click.echo(json.dumps(comparison, indent=2))
    else:
        from rich.console import Console
        from rich.table import Table

        table = Table("Model", "Cases passed", "Gate", "Median / p95", "Estimated API cost")
        for row in comparison["models"]:
            latency, cost = row["latency_ms"], row["cost"]
            amount = cost["estimated_api_usd"]
            cost_text = f"${amount:.4f}" if amount is not None else cost["basis"]
            times = f"{latency['median']} / {latency['p95']} ms"
            table.add_row(
                row["model"], f"{row['passed']}/{row['total']}", "PASS" if row["gate_passed"] else "FAIL", times, cost_text
            )
        Console().print(table)
    if check and any(not row["gate_passed"] or row["regressions_vs_first"] for row in comparison["models"]):
        raise click.exceptions.Exit(1)
