# Hecate Installation & Development Guide

## Source installation

Requirements: Python 3.11.5+, Git and uv. For Core alone:

```bash
git clone https://github.com/Hecate-Org/Hecate-Core.git
cd Hecate-Core
uv sync --locked --extra all --extra dev
source .venv/bin/activate
hecate-agent --version
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`. For Core and
Runner together, use the single shared interpreter in [onboarding](ONBOARDING.md).
Do not mix environments: Runner imports Core in-process.

Standard Python/venv is an alternative from a Core checkout:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[all,dev]'
```

The uv path uses the reviewed lock; the pip example resolves dependencies from
package constraints. For wheel installations, choose an existing, reviewed
versioned artifact rather than assuming a registry release or `latest` filename.

## Installation options

### Optional features

Use the extras declared in [pyproject.toml](../pyproject.toml). `[all]` is curated;
it does not include every adapter or the development tools.

| Feature | Extra or requirement |
| --- | --- |
| ATT&CK reference data | `attack` |
| Web research | `research` plus search configuration |
| Similarity search | `similarity` |
| Sigma conversion | `sigma` and the required backends |
| LiteLLM providers | `litellm` plus provider credentials |
| Direct OpenAI or Bedrock adapters | `openai` or `bedrock` |
| MCP server | `mcp` |
| Splunk client | `splunk` plus endpoint/authentication |
| Direct Ollama adapter | Running Ollama server; no Python SDK required |
| Development tools | `dev` |

For example, `uv sync --locked --extra attack --extra research` selects those
extras. Preserve any other extras your environment needs when changing the set.
See [configuration](CONFIGURATION.md) for endpoints, models and credentials;
installation does not supply API keys.

### No installation (pure Markdown)

The [LOCK pattern](lock-pattern.md), templates and example records can be read
without Python. CLI validation, ID allocation, search, statistics and automation
require installation. Use `hecate-agent hunt new` for framework-managed creation.

## Development & Customization

Install `dev` and the extras exercised by your change, then run from Core:

```bash
python -m pytest tests/ -q
ruff check .
mypy hecate_agent --ignore-missing-imports
python scripts/sync_docs.py --check
```

Default tests isolate operator configuration and reject unmocked external calls.
Live checks require explicit `-m network` selection and test-specific setup.
See [tests/commands/](../tests/commands/) for CLI test examples and
[pyproject.toml](../pyproject.toml) for lint, format, type and coverage settings.

### Customization Examples

Register a Click command in `hecate_agent/cli.py` after adding its implementation
under `hecate_agent/commands/`. Configure hunt fields and templates using the
[template reference](CONFIGURATION.md#hunt-template-hunt_templatej2); keep managed
IDs and required metadata. Document new options and add checks for changed behavior.

Use existing commands in small scripts, for example:

```bash
hecate-agent hunt list --status completed --format json
```

### CI/CD Integration

[Tests CI](../.github/workflows/tests.yml) covers Python 3.11–3.13 on Linux,
macOS and Windows, along with lint, types, hunt validation, docs sync and package
builds. [Security CI](../.github/workflows/security.yml) scans code, secrets and
locked dependencies. Model quality evaluations are separate manual checks; see
[evals/README.md](../evals/README.md).

## Platform-Specific Instructions

Use a virtual environment on each platform rather than a global install.
Activate `.venv/bin/activate` in Linux/macOS shells or
`.venv\Scripts\Activate.ps1` in Windows PowerShell. Runner's shared setup examples
use Bash on Linux/macOS or WSL. Confirm the selected interpreter meets the minimum
version with `python --version`.

## Verifying Installation

```bash
hecate-agent --version
hecate-agent --help
hecate-agent env check
```

For an isolated example, run `hecate-agent demo init --path /path/to/new-demo`.
It writes example files, so select a new directory. Runner's `hecate-runner demo`
instead uses an ephemeral fixture workspace and mock clients. Neither proves
live model or SIEM access.

## Troubleshooting

| Symptom | Check or fix |
| --- | --- |
| `hecate-agent: command not found` | Activate the environment containing the package |
| `No module named hecate_agent` | Check the interpreter and reinstall into that same environment |
| Unsupported Python/dependency resolution | Use Python 3.11.5+ and review the selected extras and lock |
| Installation permission error | Use an owned virtual environment; avoid global or sudo pip installation |
| Dependency import conflict | Reproduce in a fresh venv using the documented setup; run `uv pip check` |
| Empty or unexpected hunt list | Export the correct absolute `HECATE_WORKSPACE` |
| Windows cannot find Python | Check the Python installation and PATH, then reopen the terminal |

Keep private telemetry and credentials out of issue reports. Include the command,
Python version, repository commits and relevant error text.

## Upgrading Hecate

For a Core-only locked setup, preserve local changes and review the update before:

```bash
git pull --ff-only
uv sync --locked --extra all --extra dev
hecate-agent --version
```

Editable source changes apply to new processes; dependency changes require
resolving/installing again. Restart long-running applications after reviewed
updates. Protected installed service runtimes are separate from source checkouts;
follow [Runner service isolation](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/SERVICE_ISOLATION.md)
for their update and recovery procedure.

## Uninstalling Hecate

From the intended environment, use `uv pip uninstall hecate-agent` (or
`python -m pip uninstall hecate-agent` for a pip-managed environment). Uninstalling
the package leaves workspace records intact. Keep workspace deletion separate.

## Next Steps

- [Getting started](getting-started.md)
- [Configuration](CONFIGURATION.md)
- [CLI reference](CLI_REFERENCE.md)
- [Dependency security](DEPENDENCY_SECURITY.md)
