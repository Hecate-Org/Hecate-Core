"""Hunt management commands."""

import click

HUNT_EPILOG = """
\b
Examples:
  # Interactive hunt creation (guided prompts)
  hecate-agent hunt new

  # Non-interactive with all options
  hecate-agent hunt new --technique T1003.001 --title "LSASS Dumping" --non-interactive

  # Link research document to hunt
  hecate-agent hunt new --research R-0001 --title "Hunt Title" --non-interactive

  # List hunts with filters
  hecate-agent hunt list --status completed --tactic credential-access

  # Search hunts for keywords
  hecate-agent hunt search "kerberoasting"

  # Get JSON output for scripting
  hecate-agent hunt list --format json

  # Show coverage gaps
  hecate-agent hunt coverage

  # Filter coverage by tactic
  hecate-agent hunt coverage --tactic credential-access

  # Validate hunt structure
  hecate-agent hunt validate H-0042

\b
Workflow:
  1. Create hunt → hecate-agent hunt new
  2. Edit hunt file → hunts/H-XXXX.md (use LOCK pattern)
  3. Create query → queries/H-XXXX.spl
  4. Execute hunt → document findings in runs/H-XXXX_YYYY-MM-DD.md
  5. Track results → hecate-agent hunt stats

\b
Learn more: https://github.com/BrizoSec/Hecate-Core/blob/main/docs/CLI_REFERENCE.md
"""


@click.group(epilog=HUNT_EPILOG)
def hunt() -> None:
    """Manage threat hunting activities and track program metrics.

    \b
    Hunt commands help you:
    • Create structured hunt hypotheses
    • Track hunts across your program
    • Search past work to avoid duplication
    • Calculate success rates and coverage
    • Validate hunt file structure
    """


# Register subcommands from split submodules
from hecate_agent.commands._hunt_create import new, new_baseline, new_model_assisted  # noqa: E402
from hecate_agent.commands._hunt_dedup import dedup  # noqa: E402
from hecate_agent.commands._hunt_lifecycle import brief, export_hunt, operationalize, promote_hunt, update_hunt  # noqa: E402
from hecate_agent.commands._hunt_query import coffee, coverage, list_hunts, search, stats, validate  # noqa: E402

hunt.add_command(new)
hunt.add_command(new_baseline)
hunt.add_command(new_model_assisted)
hunt.add_command(list_hunts)
hunt.add_command(validate)
hunt.add_command(stats)
hunt.add_command(search)
hunt.add_command(coverage)
hunt.add_command(coffee)
hunt.add_command(update_hunt)
hunt.add_command(operationalize)
hunt.add_command(promote_hunt)
hunt.add_command(export_hunt)
hunt.add_command(brief)
hunt.add_command(dedup)
