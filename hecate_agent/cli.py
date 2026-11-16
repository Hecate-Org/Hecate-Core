"""Hecate command-line interface."""

import random
import sys

import click
from rich.console import Console

from hecate_agent.core.workspace import load_workspace_env

# Load .env file with workspace auto-discovery (local directory first, then workspace root)
load_workspace_env()

from hecate_agent.__version__ import __version__  # noqa: E402
from hecate_agent.commands import attack, config, context, demo, env, hunt, investigate, maturity, research, similar, splunk  # noqa: E402
from hecate_agent.commands.agent import agent  # noqa: E402
from hecate_agent.commands.eval import eval_cmd, eval_gold_cmd  # noqa: E402
from hecate_agent.commands.model_quality import eval_compare_cmd, eval_suite_cmd  # noqa: E402
from hecate_agent.commands.monitor import monitor  # noqa: E402
from hecate_agent.commands.mcp import mcp  # noqa: E402
from hecate_agent.plugin_system import PluginRegistry  # noqa: E402

console = Console()


EPILOG = """
\b
Examples:
  # Quick start with complete demo hunt
  hecate-agent demo init

  # Assess workspace maturity level
  hecate-agent maturity assess

  # Configure AI providers
  hecate-agent config ai

  # Promote validated hunt logic to a Sigma detection rule
  hecate-agent hunt promote --hunt H-0001 --output sigma

  # Search for credential dumping hunts
  hecate-agent hunt search "credential dumping"

  # List all completed hunts
  hecate-agent hunt list --status completed

  # Show program statistics
  hecate-agent hunt stats

\b
Getting Started:
  1. Run 'hecate-agent demo init' for a complete example hunt in LOCK format
  2. Run 'hecate-agent maturity assess' to check your workspace maturity level
  3. Run 'hecate-agent config ai' to configure AI research & hypothesis generation
  4. Track findings and iterate

\b
Documentation:
  • Full docs: https://github.com/BrizoSec/Hecate-Core/tree/main/docs
  • CLI reference: docs/CLI_REFERENCE.md

\b
Need help? Run 'hecate-agent COMMAND --help' for command-specific help.

"""


@click.group(epilog=EPILOG)
@click.version_option(
    version=__version__,
    prog_name="hecate-agent",
    message="%(prog)s version %(version)s\nHecate, by BrizoSec\nBased on ATHF, © 2025 Sydney Marrone (MIT)",
)
def cli() -> None:
    r"""Hecate - Hunt management CLI.

    \b
    Hecate gives your threat hunting program memory and agency by:
    • Structured documentation with the LOCK pattern
    • Hunt tracking and metrics across your program
    • AI-assisted hypothesis generation and workflows
    • MITRE ATT&CK coverage analysis

    \b
    Quick Start:
      hecate-agent demo init      Initialize zero-config example workspace
      hecate-agent hunt new       Create a hunt from template
      hecate-agent hunt list      View all hunts
      hecate-agent hunt search    Find hunts by keyword
      hecate-agent maturity assess Assess program maturity level
      hecate-agent config ai      Configure AI providers
    """


# Register command groups
cli.add_command(hunt)
cli.add_command(investigate)
cli.add_command(research)
cli.add_command(attack)
cli.add_command(demo)
cli.add_command(config)
cli.add_command(maturity)

# Phase 1 commands (env, context, similar)
cli.add_command(env)
cli.add_command(context)
cli.add_command(similar)

# Agent commands
cli.add_command(agent)

# Model-quality eval harness
cli.add_command(eval_cmd)
cli.add_command(eval_gold_cmd)
cli.add_command(eval_suite_cmd)
cli.add_command(eval_compare_cmd)
cli.add_command(monitor)

# MCP server command
cli.add_command(mcp)

# Integration commands (optional, requires additional dependencies)
if splunk is not None:
    cli.add_command(splunk)

# Load and register plugins
PluginRegistry.load_plugins()
for name, cmd in PluginRegistry._commands.items():
    cli.add_command(cmd, name=name)


@cli.command(hidden=True)
def wisdom() -> None:
    """Security wisdom for threat hunters."""
    quotes = [
        "The best threat hunters build memory, not just alerts.",
        "Adversaries don't repeat signatures. They repeat behaviors.",
        "A hunt without findings is still a hunt. Absence of evidence is evidence.",
        "Your SIEM doesn't have a storage problem. It has a memory problem.",
        "Indicators expire. Behaviors persist.",
        "The top of the Pyramid of Pain is the adversary's comfort zone. Make them uncomfortable.",
        "Hunt for TTPs, not IOCs. Adversaries swap infrastructure daily, not tactics.",
        "False positives teach you about your environment. True positives teach you about adversaries.",
        "Every expert threat hunter started with their first hypothesis. Keep building.",
        "The LOCK pattern isn't just documentation—it's institutional memory.",
        "Threat intelligence tells you what to hunt. Your environment tells you how.",
        "Behavioral detections age like wine. Signature detections age like milk.",
        "The most dangerous threats blend in. Hunt for the subtle, not the obvious.",
        "A mature hunt program isn't measured by detections. It's measured by learning velocity.",
        "Pivoting is an art. Knowing when to stop pivoting is wisdom.",
        "Your baseline is your best threat intelligence. Protect it.",
        "Hunt like an adversary thinks: what would I do if I were already inside?",
        "The best detection is a hunt hypothesis validated repeatedly.",
        "Memory is the multiplier. Agency is the force.",
        "Document the hunt that found nothing—it eliminates hypotheses for everyone who comes after you.",
    ]

    console.print(f"\n💭 [italic]{random.choice(quotes)}[/italic]\n")  # nosec B311


@cli.command(hidden=True)
def thrunt() -> None:
    """Activate the secret thrunt mode."""
    console.print("\n[bold cyan]🎯 THRUNT MODE ACTIVATED[/bold cyan]\n")
    console.print("[italic]You've discovered the secret: threat hunting has always been 'thrunting'.[/italic]")
    console.print("[italic]Welcome to the club. Now go hunt some threats.[/italic]\n")


def _ensure_printable_stdio() -> None:
    """Make stdout/stderr able to carry this CLI's non-ASCII output.

    A legacy Windows console encodes as cp1252, which has no mapping for the
    emoji and box-drawing characters used throughout the command output. rich
    writes through the stream, so the first such character raised
    UnicodeEncodeError mid-print and aborted the command: `hecate-agent hunt new` exited
    1 without creating the hunt, before doing any of its real work. 27 source
    files emit characters outside cp1252, so this is fixed once here rather
    than by stripping them from every message.

    UTF-8 first, since it can carry everything this CLI prints. If the stream
    refuses to change encoding, fall back to leaving the encoding alone and
    only relaxing the error handler -- losing a glyph to a placeholder is an
    acceptable outcome, aborting the command halfway through its output is not.

    Best-effort throughout: a stream without reconfigure() (pytest's capture,
    click's CliRunner) is left exactly as it was.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            try:
                reconfigure(errors="replace")
            except (AttributeError, ValueError, OSError):  # pragma: no cover - stream-dependent
                pass


def main() -> None:
    """Run the CLI."""
    _ensure_printable_stdio()
    cli()


if __name__ == "__main__":
    main()
