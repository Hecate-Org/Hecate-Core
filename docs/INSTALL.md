# Hecate Installation & Development Guide

This guide covers installation methods and development setup for Hecate.

## Source installation

The supported setup in this guide uses a source checkout, so it does not depend
on package-registry availability or an assumed GitHub release filename.

Requirements: Python 3.11+, Git, and uv or Python's venv/pip tooling.

```bash
git clone https://github.com/Hecate-Org/Hecate-Core.git
cd Hecate-Core
uv venv .venv
source .venv/bin/activate
uv pip install -e '.[all,dev]'
hecate-agent --version
```

For Core and Runner together, use the single shared environment described in
[onboarding](ONBOARDING.md). Core and Runner must resolve compatible packages in
the same interpreter for in-process integration. Basic management works without
LLM keys; model/search/SIEM features need their own configuration.

With standard Python instead of uv:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[all,dev]'
```

On Windows PowerShell activate with `.venv\Scripts\Activate.ps1`. For published
wheels, use a reviewed versioned artifact that actually exists; this guide does
not assume a PyPI release or a `hecate_agent-latest-py3-none-any.whl` asset.

## Installation options

### Optional features

`[all]` is a curated set, not every extra. Add `[bedrock]` when selecting the
direct Bedrock adapter, and install only the other SDK extras your workflow needs.
The current direct Ollama adapter uses standard-library HTTP and needs a running
Ollama server, not the optional Ollama Python SDK.

**Best for**: Running the AI agents, web research, ATT&CK validation or the MCP server.

```bash
# Clone the repository
git clone https://github.com/Hecate-Org/Hecate-Core.git
cd Hecate-Core

# Everything the agents and the Runner use
pip install -e ".[all]"

# Or pick extras: attack, research, similarity, sigma, litellm, ollama, mcp, splunk
pip install -e ".[attack,research]"

# Verify installation
hecate-agent --version
```

---

### No installation (pure Markdown)

**Best for**: Users who prefer a documentation-only approach or don't want to install Python packages.

```bash
# Clone the repository
git clone https://github.com/Hecate-Org/Hecate-Core.git
cd Hecate-Core

# Copy the template structure
mkdir -p my-hunts/hunts my-hunts/queries my-hunts/runs my-hunts/templates
cp templates/HUNT_LOCK.md my-hunts/templates/
cp AGENTS.md my-hunts/

# Start creating hunts by copying the template
cp templates/HUNT_LOCK.md my-hunts/hunts/H-0001.md
```

**Pros**:
- No installation required
- Works with any text editor
- Complete control over file structure
- AI assistants can edit markdown directly

**Cons**:
- No validation or automation
- Manual hunt ID tracking
- No built-in search or statistics
- No standardized workflow

---

## Development & Customization

Hecate is designed to be forked and customized for your organization. This section covers setting up your development environment and maintaining code quality in your fork.

### Setting Up Your Fork for Development

```bash
# Fork and clone your repository
git clone https://github.com/YOUR-ORG/hecate-agent
cd hecate-agent

# Install with development dependencies
pip install -e ".[dev]"

# Set up pre-commit hooks (recommended)
pre-commit install

# Run tests
pytest tests/ -v

# Run type checking
mypy hecate_agent --ignore-missing-imports

# Run linting
flake8 hecate_agent
black hecate_agent --check
isort hecate_agent --check-only
```

### Pre-commit Hooks (Optional)

Pre-commit hooks help maintain code quality as you customize Hecate for your organization. Once installed, they run automatically on every commit and check:

- **Code formatting** (black, isort)
- **Linting** (flake8)
- **Security** (bandit)
- **Type checking** (mypy)
- **File hygiene** (trailing whitespace, end-of-file fixes, etc.)

**Installing Pre-commit Hooks**:

```bash
# Install pre-commit (included in dev dependencies)
pip install -e ".[dev]"

# Set up the git hook
pre-commit install

# Run manually on all files (optional)
pre-commit run --all-files
```

**Running Individual Tools**:

```bash
# Format code
black hecate_agent
isort hecate_agent

# Check formatting without changes
black hecate_agent --check
isort hecate_agent --check-only

# Lint code
flake8 hecate_agent

# Check security issues
bandit -r hecate_agent -c pyproject.toml

# Type check
mypy hecate_agent --ignore-missing-imports
```

### Code Quality Standards

When customizing Hecate for your team:

**Type Hints**: Maintain type annotations for better IDE support and catch errors early:

```python
def get_config_path() -> Path:
    """Get config file path."""
    return Path("config/.hecateconfig.yaml")

def search_hunts(query: str) -> list[dict]:
    """Search hunts by query string."""
    results = []
    return results
```

The mypy configuration in `pyproject.toml` enforces:
- `disallow_untyped_defs = true` - All functions need type annotations
- `disallow_incomplete_defs = true` - Function signatures must be complete

**Testing**: Add tests for custom features you build. Hecate uses pytest:

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/commands/test_commands.py -v

# Run with coverage
pytest tests/ -v --cov=hecate_agent --cov-report=term-missing

# Run specific test
pytest tests/commands/test_commands.py::TestHuntNewCommand::test_hunt_new_non_interactive -v
```

Tests use Click's `CliRunner` to test actual CLI commands rather than mocks. See [tests/commands/test_commands.py](../tests/commands/test_commands.py) for examples.

**Documentation**: Keep your fork's documentation current:
- **AGENTS.md** - Update with your environment details, data sources, team context
- **environment.md** - Document your tech stack, tools, known gaps
- **Hunt files** - Use LOCK pattern consistently across all hunts
- **Custom features** - Document any custom commands or extensions you build

**Security**: Run bandit to check for security issues in custom code:

```bash
# Check all Python files
bandit -r hecate_agent -c pyproject.toml

# Check specific file
bandit hecate_agent/commands/hunt.py
```

### Testing Your Changes

Before committing significant customizations:

```bash
# 1. Run all tests
pytest tests/ -v

# 2. Check types
mypy hecate_agent --ignore-missing-imports

# 3. Format code
black hecate_agent
isort hecate_agent

# 4. Check security
bandit -r hecate_agent -c pyproject.toml

# 5. Or run pre-commit on everything
pre-commit run --all-files
```

### Customization Examples

**Adding a Custom Command**:

```python
# hecate_agent/commands/custom.py
import click
from rich.console import Console

console = Console()

@click.command()
def mycustom() -> None:
    """My custom command."""
    console.print("[cyan]Running custom command![/cyan]")

# Register in hecate_agent/cli.py
from hecate_agent.commands import custom
cli.add_command(custom.mycustom)
```

**Extending Hunt Metadata**: Modify the hunt template in `hecate_agent/core/template_engine.py` to add custom fields:

```python
HUNT_TEMPLATE = """---
hunt_id: {{ hunt_id }}
title: {{ title }}
# Your custom fields
priority: {{ priority | default('medium') }}
owner_team: {{ owner_team | default('SOC') }}
---
```

**Custom Workflows**: Hecate's structure makes it easy to build custom workflows:

```bash
#!/bin/bash
# weekly-hunt-report.sh

# Get all completed hunts from last week
hecate-agent hunt list --status completed --output json | \
  jq '[.[] | select(.date >= "2026-10-25")] | length'
```

### CI/CD Integration

Hecate includes a GitHub Actions workflow ([.github/workflows/tests.yml](../.github/workflows/tests.yml)) that runs:

- Tests across Python 3.11-3.13 on Ubuntu, macOS, Windows
- Linting with ruff
- Type checking with mypy
- Hunt validation
- Package building

Customize the workflow for your organization's needs.

### Tools Configuration

All tools are configured in `pyproject.toml`:

- **Ruff**: The lint CI runs (`ruff check .`), line length 127
- **Black**: Line length 127, targets Python 3.11-3.13
- **isort**: Black-compatible profile
- **mypy**: Strict type checking enabled
- **pytest**: Test discovery, coverage reporting
- **bandit**: Security checks with test exclusions

See [pyproject.toml](../pyproject.toml) for full configuration.

---

## Platform-Specific Instructions

### macOS

```bash
# Python 3 usually comes pre-installed on modern macOS
python3 --version

# If not installed, get it from homebrew
brew install python3

# Install Hecate
pip3 install hecate-agent

# Add to PATH if needed (check installation output)
export PATH="$HOME/Library/Python/3.x/bin:$PATH"
```

Add the PATH export to your `~/.zshrc` or `~/.bash_profile` to make it permanent.

### Linux (Ubuntu/Debian)

```bash
# Install Python 3 and pip
sudo apt update
sudo apt install python3 python3-pip python3-venv

# Install Hecate
pip3 install hecate-agent

# Add to PATH if needed
export PATH="$HOME/.local/bin:$PATH"
```

Add the PATH export to your `~/.bashrc` to make it permanent.

### Windows

```powershell
# Download Python from python.org (ensure "Add to PATH" is checked)

# Verify installation
python --version

# Install Hecate from your clone
pip install -e C:\path\to\Hecate-Core

# Verify
hecate-agent --version
```

If `hecate-agent` is not recognized, add Python Scripts to your PATH:
- `C:\Users\<YourUser>\AppData\Local\Programs\Python\Python3x\Scripts`

---

## Verifying Installation

After installation, verify everything works:

```bash
# Check version
hecate-agent --version

# Get help
hecate-agent --help

# List available commands
hecate-agent hunt --help

# Create a test workspace
mkdir hecate-test
cd hecate-test

# Create a test hunt (hunts/ is created automatically)
hecate-agent hunt new --technique T1003.001 --title "Test Hunt" --non-interactive

# List hunts
hecate-agent hunt list

# View statistics
hecate-agent hunt stats
```

If all commands work, you're ready to go!

---

## Troubleshooting

### "hecate-agent: command not found"

**Cause**: The Python scripts directory is not in your PATH.

**Solution**:

1. Find where pip installed the package:
   ```bash
   pip show hecate-agent
   ```

2. The scripts are typically in:
    - **macOS**: `~/Library/Python/3.x/bin`
    - **Linux**: `~/.local/bin`
    - **Windows**: `%APPDATA%\Python\Python3x\Scripts`

3. Add to PATH:
   ```bash
   # macOS/Linux (add to ~/.zshrc or ~/.bashrc)
   export PATH="$HOME/Library/Python/3.11/bin:$PATH"

   # Windows (use System Properties > Environment Variables)
   ```

4. Reload your shell or open a new terminal.

### "No module named 'hecate_agent'"

**Cause**: Package not installed or wrong Python environment.

**Solution**:

```bash
# Check if installed
pip list | grep hecate

# If not listed, install it from your clone
pip install -e /path/to/Hecate-Core

# Check which Python pip is using
pip --version

# Make sure it matches your Python
python --version
```

### "ERROR: Could not find a version that satisfies the requirement"

**Cause**: Python version too old (< 3.11).

**Solution**:

```bash
# Check Python version
python --version

# Upgrade Python to 3.11 or higher
# - macOS: brew install python3
# - Linux: sudo apt install python3.11
# - Windows: Download from python.org
```

### "Permission denied" errors

**Cause**: Installing globally without sudo (Linux/macOS).

**Solution** (choose one):

```bash
# Option 1: Install for current user only (recommended)
pip install --user -e /path/to/Hecate-Core

# Option 2: Use a virtual environment (best practice)
python3 -m venv hecate-env
source hecate-env/bin/activate
pip install -e /path/to/Hecate-Core

# Option 3: Install globally (not recommended)
sudo pip install /path/to/Hecate-Core
```

### Import errors with dependencies

**Cause**: Dependency version conflicts.

**Solution**:

```bash
# Use a fresh virtual environment
python3 -m venv fresh-env
source fresh-env/bin/activate

# Install Hecate in the clean environment
pip install -e /path/to/Hecate-Core

# Verify dependencies
pip list
```

### Windows: "python is not recognized"

**Cause**: Python not installed or not in PATH.

**Solution**:

1. Download Python from [python.org](https://www.python.org/downloads/)
2. During installation, **check "Add Python to PATH"**
3. Restart your terminal
4. Verify: `python --version`

---

## Upgrading Hecate

To upgrade to the latest version:

```bash
cd Hecate-Core
git pull
pip install -e .    # only needed when dependencies changed

# Verify new version
hecate-agent --version
```

---

## Uninstalling Hecate

To remove Hecate:

```bash
# Uninstall the package
pip uninstall hecate-agent

# Remove your workspace (optional - this deletes your hunts!)
# rm -rf /path/to/your/hecate-workspace
```

Your hunt files are separate from the package installation, so uninstalling Hecate won't delete your hunts.

---

## Next Steps

After installation:

1. **Read the getting started guide**: [getting-started.md](getting-started.md)
2. **Review the CLI reference**: [CLI_REFERENCE.md](CLI_REFERENCE.md)
3. **Create your first hunt**: `hecate-agent hunt new`
4. **Check your workspace**: `hecate-agent env check`
5. **Explore worked examples**: [SHOWCASE.md](SHOWCASE.md)

---

## Getting Help

- **CLI help**: `hecate-agent --help` or `hecate-agent <command> --help`
- **Documentation**: [getting-started.md](getting-started.md)
- **Issues**: [GitHub Issues](https://github.com/Hecate-Org/Hecate-Core/issues)

---

## System Requirements

- **Python**: 3.11 or higher
- **OS**: macOS, Linux, or Windows
- **Disk Space**: small for the base install; the optional extras (LLM clients, ATT&CK data, scikit-learn) add several hundred MB
- **Core dependencies**: click, pyyaml, rich, jinja2, python-dotenv, httpx, beautifulsoup4, langgraph, langchain-core, langgraph-checkpoint-sqlite
- **Optional extras**: see the table in [CLAUDE.md](../CLAUDE.md#optional-dependencies)
