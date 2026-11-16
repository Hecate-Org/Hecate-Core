"""Explicit live model evaluations and offline report comparison."""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click

from hecate_agent.core import model_quality
from hecate_agent.core.model_quality import DEFAULT_SUITE, compare_reports, load_suite, rescore_report, run_suite
from hecate_agent.core.model_quality_io import interruptible, load_report, reserve_report, write_checkpoint


@click.command("eval-suite")
@click.option("--suite", type=click.Path(path_type=Path, exists=True), default=DEFAULT_SUITE, show_default=True)
@click.option("--validate-only", is_flag=True, help="Validate cases offline; never instantiate a provider.")
@click.option(
    "--prompt-profile",
    type=click.Choice(list(model_quality.PROMPT_PROFILES)),
    default=model_quality.DEFAULT_PROMPT_PROFILE,
    show_default=True,
    help="Versioned evaluation instructions; baseline-v1 reproduces the original prompt.",
)
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
    prompt_profile: str,
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
    if rescore and any(
        click.get_current_context().get_parameter_source(name) == click.core.ParameterSource.COMMANDLINE
        for name in ("repeats", "max_tokens", "fail_under", "max_cost_usd", "prompt_profile")
    ):
        raise click.UsageError("--rescore preserves the original run parameters and prompt; live options cannot override them")
    if validate_only:
        click.echo(json.dumps({"suite_id": cases["suite_id"], "cases": len(cases["cases"]), "valid": True}))
        return
    if not rescore and (not provider or not model):
        raise click.UsageError("Live evaluation requires both --provider and --model")
    modules = [
        Path(model_quality.__file__),
        Path(__file__),
        Path(model_quality.__file__).with_name("model_quality_io.py"),
        Path(model_quality.__file__).with_name("model_quality_reports.py"),
    ]
    code_sha256 = model_quality.digest(
        {str(p.parent.name + "/" + p.name): hashlib.sha256(p.read_bytes()).hexdigest() for p in modules}
    )
    try:
        with reserve_report(report) as (destination, journal):
            write_checkpoint(journal, {"event": "evaluation_started", "suite_sha256": model_quality.digest(cases)})

            def progress(result: dict[str, Any]) -> None:
                write_checkpoint(journal, result)
                click.echo(
                    f"{result['id']} #{result['repeat']}: {result['status']} / {'PASS' if result['passed'] else 'FAIL'}",
                    err=True,
                )

            if rescore:
                payload = rescore_report(load_report(rescore), cases)
            else:
                from hecate_agent.core.llm_provider import create_provider

                try:
                    backend = create_provider({"provider": provider, "model": model})
                except Exception as exc:
                    raise click.ClickException("Provider setup failed: " + type(exc).__name__) from None
                with interruptible():
                    payload = run_suite(
                        backend,
                        cases,
                        repeats=repeats,
                        max_tokens=max_tokens,
                        fail_under=fail_under,
                        max_cost_usd=max_cost_usd,
                        progress=progress,
                        prompt_profile=prompt_profile,
                    )
                if provider == "ollama":
                    payload["provider_options"] = {"think": backend.think, "num_ctx": backend.num_ctx}  # type: ignore[attr-defined]
            payload["checked_at_utc"] = datetime.now(timezone.utc).isoformat()
            payload["evaluation_code_sha256"] = code_sha256
            encoded = json.dumps(payload, indent=2, allow_nan=False) + "\n"
            if destination:
                destination.write(encoded)
                destination.flush()
                os.fsync(destination.fileno())
    except FileExistsError:
        raise click.ClickException("Report or progress artifact already exists; choose a fresh path") from None
    except OSError as exc:
        raise click.ClickException("Cannot read/write evaluation artifacts: " + type(exc).__name__) from None
    except (ValueError, KeyError, TypeError) as exc:
        raise click.ClickException("Invalid evaluation data: " + str(exc)) from None
    sys.stdout.write(encoded)
    if payload.get("interrupted"):
        raise click.exceptions.Exit(130)
    if not payload["gate_passed"]:
        raise click.exceptions.Exit(1)


@click.command("eval-compare")
@click.argument("reports", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("--output", type=click.Choice(["table", "json"]), default="table")
@click.option(
    "--check", is_flag=True, help="Exit 1 for a failed candidate gate or a case regression against the first report."
)
def eval_compare_cmd(reports: tuple[Path, ...], output: str, check: bool) -> None:
    """Compare compatible JSON reports offline. The first report is the baseline."""
    try:
        comparison = compare_reports([load_report(path) for path in reports])
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
    if check and any(not row["gate_passed"] or row["regressions_vs_first"] for row in comparison["models"][1:]):
        raise click.exceptions.Exit(1)
