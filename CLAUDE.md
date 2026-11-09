# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **Hecate**, an agentic threat hunting framework — a Python CLI + MCP server that gives threat hunting programs structured documentation, AI-powered research, and hunt lifecycle management. It is the `hecate-agent` Python package (distributed via PyPI: `pip install hecate-agent`, GitHub Releases wheels, or installed in editable mode from this checkout), with the `hecate-agent` entry point.

**This repository is dual-purpose:** it is both the framework's source (`hecate_agent/`, `tests/`) and a live, dogfooded hunting workspace. `hunts/`, `research/`, `knowledge/`, and `integrations/` contain real hunt (`H-XXXX.md`), research (`R-XXXX.md`), and environment content produced by using Hecate against this org's own data sources. Files in those directories are framework *output*, not source code — see `AGENTS.md` for the CLI-first rules that govern editing them (never hand-write hunt/research frontmatter; use the CLI).

## Development Setup

```bash
# Create .venv and install in editable mode (equivalent to pip install -e ".[dev]")
hecate-agent env setup --dev
# or manually:
pip install -e ".[dev]"

# For a workspace that runs real research/hunting (grounded web search +
# ATT&CK technique validation + hunt similarity search) -- `[dev]` alone is
# not enough: hunt_researcher.py's web search and the technique validator
# both fail *silently* without tavily-python/mitreattack-python (caught
# ImportErrors, not surfaced as errors -- see _get_search_client() and
# _validate_techniques()), so a bare `[dev]` install looks like it's working
# while quietly producing ungrounded research and unvalidated technique IDs.
pip install -e ".[dev,similarity,attack,research]"

# Install with all optional features
pip install -e ".[all]"

# Set up pre-commit hooks
pre-commit install
```

Copy `.env.example` to `.env` and configure API keys before running agents or research commands.

## Common Commands

```bash
# IMPORTANT: activate the venv first — two tests invoke `hecate-agent` via subprocess
# and will fail if a system-installed hecate-agent binary is found first on PATH
source .venv/bin/activate
which hecate-agent   # sanity check: should point inside .venv

# Run all tests with coverage
pytest tests/ -v --cov=hecate_agent --cov-report=term-missing

# Run a single test file
pytest tests/core/test_hunt_manager.py -v

# Run a single test
pytest tests/core/test_hunt_manager.py::TestGetHuntDirectory::test_get_hunt_directory_production -v

# Lint as CI does (ruff, default rules, 127-column lines)
ruff check .

# flake8, black and isort below are the pre-commit hooks' formatting checks
# Lint (syntax errors only — fast)
flake8 hecate_agent --count --select=E9,F63,F7,F82 --show-source --statistics

# Full lint pass
flake8 hecate_agent --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

# Type check
mypy hecate_agent --ignore-missing-imports

# Format code
black hecate_agent --line-length=127
isort hecate_agent --profile black --line-length 127

# Security scan (pre-commit gates on high severity only; drop the flag
# to review the low/medium findings, which are known and triaged)
bandit -c pyproject.toml -r hecate_agent --severity-level high

# Run all pre-commit hooks
pre-commit run --all-files

# Validate hunt files in a workspace
hecate-agent hunt validate

# Start the MCP server
hecate-agent mcp serve
hecate-agent-mcp  # standalone entry point
```

## Architecture

### Package Structure

```
hecate_agent/
├── cli.py                  # Click CLI root; registers all command groups + plugin system
├── plugin_system.py        # Entry-point-based plugin discovery (hecate_agent.commands / hecate_agent.mcp_tools groups)
├── commands/               # Click command groups (one file per top-level command)
│   ├── hunt.py             # Hunt management (delegates to _hunt_create, _hunt_lifecycle, _hunt_query)
│   ├── investigate.py      # Investigation commands (delegates to _investigate_*)
│   ├── research.py         # Research lifecycle
│   ├── agent.py            # Agent execution (hypothesis-generator, hunt-researcher)
│   ├── context.py          # AI-optimized context export (reduces token usage)
│   ├── similar.py          # Semantic similarity search via TF-IDF (requires scikit-learn)
│   ├── attack.py           # MITRE ATT&CK STIX data management
│   ├── env.py              # `hecate-agent env setup/clean` — creates/manages the project .venv
│   ├── eval.py             # Model-quality eval harness — scripted known-answer spot checks
│   ├── mcp.py              # MCP server control
│   ├── monitor.py          # Live terminal dashboard over a Runner cycle (state polling, event aggregation)
│   ├── monitor_views.py    # Terminal UI views, stage renderers, ribbons, and layout rendering
│   └── splunk.py           # Optional Splunk integration (loaded conditionally)
├── enrichment/             # Modular CTI enrichment architecture
│   ├── constants.py        # Shared normalization mappings, confidence scoring, timeouts
│   └── providers/          # 17 pluggable OSINT/CTI provider modules (VT, Shodan, GreyNoise...)
├── core/                   # Business logic layer
│   ├── hunt_manager.py     # Hunt file discovery, lifecycle, stats, ATT&CK coverage; class-level cache keyed on fs fingerprint
│   ├── hunt_parser.py      # YAML frontmatter + LOCK section markdown parser
│   ├── investigation_parser.py
│   ├── research_manager.py # Research document lifecycle (R-XXXX.md)
│   ├── llm_provider.py     # Model-agnostic LLM abstraction (LiteLLM / OpenAI / Anthropic / Bedrock / Ollama); lazy imports
│   ├── llm_activity.py     # Live per-call log, written only when HECATE_LLM_CALL_LOG is set (the Runner sets it)
│   ├── source_evidence.py  # Fetches a CTI item's report and keeps only artifacts verified verbatim against it
│   ├── attack_matrix.py    # MITRE ATT&CK coverage; STIX provider with JSON fallback
│   ├── cost_tracker.py     # Token cost estimation with fuzzy model-name matching
│   ├── envelope.py         # Structured data envelope / schema
│   ├── eval_harness.py     # Model quality evaluation
│   ├── template_engine.py  # Jinja2 template rendering for hunt/investigation files
│   ├── splunk_client.py    # Splunk REST API client
│   └── web_search.py       # Tavily search integration
├── agents/                 # LLM-powered agent implementations
│   ├── base.py             # BaseAgent abstract class
│   └── llm/
│       ├── hypothesis_generator.py  # Generates hunt hypotheses from threat intel
│       ├── hunt_researcher.py       # 5-skill pre-hunt research methodology
│       ├── sigma_generator.py       # Drafts Sigma rules per log source
│       ├── rule_reviewer.py         # Reviews drafted rules against the hypothesis and source
│       └── pivot_suggester.py       # Suggests pivot queries from hunt findings
├── mcp/                    # MCP server (FastMCP)
│   ├── server.py           # Server factory, workspace discovery, plugin tool loading
│   └── tools/              # MCP tool implementations (mirrors CLI commands)
│       ├── hunt_tools.py
│       ├── investigate_tools.py
│       ├── research_tools.py
│       ├── agent_tools.py
│       ├── attack_tools.py
│       └── search_tools.py
└── data/                   # Bundled package data (templates, docs, example hunts, prompts)
    ├── templates/HUNT_LOCK.md       # Canonical hunt template
    ├── knowledge/hunting-knowledge.md
    └── prompts/ai-workflow.md
```

### Key Design Patterns

**Hunt file format:** Markdown files with YAML frontmatter (`---`) followed by the LOCK-pattern body (Learn / Observe / Check / Keep sections). Files are named `H-XXXX.md` and stored under `hunts/{YYYY}/{QX}/`. Investigations use `I-XXXX.md` under `investigations/`, research uses `R-XXXX.md` under `research/`.

**CLI-first invariant:** The CLI (and MCP tools) are the only sanctioned way to create/validate hunt files. Direct file writes bypass ID sequencing and YAML frontmatter generation — never create hunt/investigation/research files manually.

**LLM provider resolution:** `hecate_agent.core.llm_provider.create_provider()` resolves in four layers, highest precedence first: an explicit `config` dict → `HECATE_LLM_PROVIDER` / `HECATE_LLM_MODEL` → the `llm` section of `.hecateconfig.yaml` → auto-detection. Auto-detection probes `ANTHROPIC_API_KEY` (via LiteLLM) → `OPENAI_API_KEY` → `AWS_PROFILE`/`AWS_ACCESS_KEY_ID` (Bedrock) → a locally running Ollama, and raises `RuntimeError` if none match.

Note that this workspace sets `HECATE_LLM_PROVIDER=ollama` in `.env`, so auto-detection never runs here — changing which model is used means editing that, not adding an API key. All optional LLM dependencies use lazy imports so the base package installs without any AI SDK.

**HuntManager caching:** `HuntManager` uses a class-level cache keyed on a filesystem fingerprint (file count + max mtime). Fresh instances are created per CLI invocation and per MCP tool call, making the class-level cache the right scope for deduplication without stale-data risk.

**Plugin system:** Plugins register via `entry_points` groups `hecate_agent.commands` (CLI commands) and `hecate_agent.mcp_tools` (MCP tool registrations). The CLI and MCP server discover them at startup.

**MCP server:** `mcp/server.py` uses `FastMCP` (requires `mcp[cli]<2.0.0` — the 2.0.0 release removed `mcp.server.fastmcp`). Start with `hecate-agent mcp serve` or the `hecate-agent-mcp` entry point.

### Optional Dependencies

| Extra | Provides |
|-------|----------|
| `[similarity]` | `scikit-learn` — required for `hecate-agent similar` |
| `[splunk]` | `requests` — Splunk REST integration |
| `[litellm]` / `[llm]` | LiteLLM multi-provider support |
| `[anthropic]` | Direct Anthropic SDK |
| `[openai]` | Direct OpenAI SDK |
| `[bedrock]` | `boto3` for AWS Bedrock |
| `[attack]` | `mitreattack-python` for live STIX data |
| `[mcp]` | `mcp[cli]<2.0.0` for MCP server |
| `[sigma]` | `pysigma` — Sigma rule validation |
| `[research]` | `tavily-python` — web-search grounding for `hecate-agent research new` |
| `[docs]` | `mkdocs` + `mkdocs-material` |
| `[all]` | `[sigma]`, `[litellm]`, `[similarity]`, `[splunk]`, `[research]`, `[mcp]`, `[attack]` |

`[all]` is **not** every extra: it deliberately omits the direct provider SDKs
(`[anthropic]`, `[openai]`, `[bedrock]`, `[ollama]`) and `[docs]`, since LiteLLM
already covers the providers. An Ollama workspace still needs `[ollama]`.

### Code Style

- Line length: 127 characters (black + flake8 + isort all configured to 127)
- Python 3.11+ (`requires-python = ">=3.11"`; CI tests 3.11/3.12/3.13)
- Typing style is `Optional[X]` / `Dict[...]`, not `X | None` — 41 modules use it
  against 1 that does not. This is consistency with the surrounding code, not a
  version constraint: the 3.11 floor permits either.
- mypy is configured per-flag rather than `strict = true` (`disallow_untyped_defs`,
  `disallow_incomplete_defs`, `check_untyped_defs`, `no_implicit_optional`,
  `warn_return_any`); all functions need type annotations
- Bandit security linting skips `B101` (assert statements)
