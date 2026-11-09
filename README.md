# Hecate-Core

> **The Agentic Detection Engineering & Threat Hunting Reasoning Engine.**
> Python library, CLI, and prompt framework powering autonomous detection generation from threat intelligence.

[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

---

## 🧭 Overview

**Hecate-Core** (`hecate_agent`) is the foundation of the Hecate threat hunting ecosystem. It provides the core agent reasoning loops, prompt templates, MITRE ATT&CK knowledge graphs, Sigma rule generation, and pySigma transpilation to multi-engine SIEM/EDR query languages.

It operates under a strict principle: **The LLM proposes, deterministic code disposes.** Models draft behavioral hypotheses and candidate detections; deterministic AST parsers, schema validators, and grounding auditors verify and tune every artifact.

---

## 🏛 Ecosystem Architecture

Hecate is structured into three coordinated repositories:

```mermaid
flowchart LR
    CTI["Threat Feeds<br/>(20+ Sources)"] --> RUNNER["Hecate-Runner<br/>(Autonomous Daemon)"]
    RUNNER -- "imports in-process" --> CORE["Hecate-Core<br/>(Reasoning & Sigma Engine)"]
    CORE --> LLM["LLM & Web Search"]
    RUNNER -- "commits / publishes PRs" --> WS["Hecate-Workspace<br/>(Hecate-Org/Hecate-Public)"]
    WS --> SOC["SOC / SIEM Deployment<br/>(Splunk, Sentinel, CrowdStrike...)"]
```

- **[Hecate-Core](https://github.com/Hecate-Org/Hecate-Core)** *(this repo)*: Detection reasoning library, CLI, Sigma generation, MITRE ATT&CK STIX grounder, pySigma transpiler.
- **[Hecate-Runner](https://github.com/Hecate-Org/Hecate-Runner)**: Autonomous perpetual daemon, 20+ CTI intake feeds, purple team emulation, automated reviewer self-remediation, GitHub PR publisher, Slack bot.
- **[Hecate-Workspace](https://github.com/Hecate-Org/Hecate-Public)**: Version-controlled detection repository holding hunts (`hunts/`), queries (`queries/`), research briefs (`research/`), and promotion policies.

---

## 📂 File & Directory Structure

```text
Hecate-Core/
├── hecate_agent/                # Primary Python package
│   ├── agents/                  # Autonomous LLM agents (Hypothesis, Researcher, Reviewer)
│   ├── commands/                # CLI subcommands (hunt, attack, investigate, monitor, monitor_views)
│   ├── core/                    # Deterministic engines (grounding, AST validation, transpiler)
│   ├── enrichment/              # Pluggable CTI enrichment providers (VT, Shodan, AbuseIPDB, Censys...)
│   ├── mcp/                     # Model Context Protocol (MCP) server & tool integrations
│   ├── utils/                   # Validation & helper utilities
│   ├── api.py                   # High-level Python programmatic API
│   └── cli.py                   # Typer CLI entrypoint
├── docs/                        # Complete technical documentation
│   ├── ARCHITECTURE.md          # 3-repo architecture blueprint & data flow
│   ├── FEATURES.md              # Exhaustive feature matrix and subsystem details
│   ├── CHALLENGES.md            # Technical challenges solved (hallucinations, token quotas)
│   ├── HOW_TO.md                # Developer recipes & step-by-step guides
│   ├── ONBOARDING.md            # Fast-track onboarding guide for new joiners
│   └── CLI_REFERENCE.md         # Comprehensive CLI argument reference
├── evals/                       # Ground-truth evaluation pulses and replay scripts
├── knowledge/                   # OCSF schemas, ATT&CK STIX cache, hunting knowledge
├── prompts/                     # System prompts and few-shot templates
└── tests/                       # 2,197+ unit and integration tests
```

---

## 🚀 5-Minute Quick Install & Getting Started

### Prerequisites
- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- An LLM API key (Anthropic, OpenAI, AWS Bedrock) or a local [Ollama](https://ollama.com) instance

### Step 1: Clone Repositories Side-by-Side
```bash
mkdir -p ~/betas && cd ~/betas

git clone https://github.com/Hecate-Org/Hecate-Core.git
git clone https://github.com/Hecate-Org/Hecate-Runner.git
git clone https://github.com/Hecate-Org/Hecate-Public.git Hecate-Workspace
```

### Step 2: Install Dependencies with `uv`
```bash
# Install Hecate-Core with all extras (ATT&CK STIX, pySigma backends, MCP)
cd ~/betas/Hecate-Core
uv sync --all-extras
```

### Step 3: Configure Environment
Copy the template configuration into `Hecate-Workspace/.env`:
```bash
cd ~/betas/Hecate-Workspace
cp .env.example .env
```

Edit `.env` with your preferred AI provider:
```dotenv
HECATE_AI_PROVIDER=anthropic      # options: anthropic, openai, bedrock, ollama
ANTHROPIC_API_KEY=sk-ant-...
TAVILY_API_KEY=tvly-...          # For web-grounded threat research
HECATE_WORKSPACE=~/betas/Hecate-Workspace
```

Verify your environment configuration:
```bash
cd ~/betas/Hecate-Core
uv run hecate-agent env check
```

### Step 4: Your First Hunt Commands
```bash
# 1. Zero-configuration demo: initialize an example hunt
uv run hecate-agent demo init

# 2. List all hunts in the workspace
uv run hecate-agent hunt list

# 3. Search MITRE ATT&CK techniques
uv run hecate-agent attack search "lsass memory"

# 4. Export validated Sigma logic to SIEM queries
uv run hecate-agent hunt promote --hunt H-0001 --output splunk
```

---

## 💻 CLI Usage (`hecate-agent`)

The `hecate-agent` CLI gives detection engineers interactive access to the reasoning engine:

### Manage & Explore Hunts
```bash
# List all recorded hunts across quarters
uv run hecate-agent hunt list

# Inspect a specific hunt
uv run hecate-agent hunt show H-0885

# Promote a hunt and transpile Sigma rules to SIEM queries
uv run hecate-agent hunt promote --hunt H-0885 --output splunk
uv run hecate-agent hunt promote --hunt H-0885 --output sentinel
uv run hecate-agent hunt promote --hunt H-0885 --output crowdstrike
```

### MITRE ATT&CK Matrix & Search
```bash
# Search ATT&CK techniques by keyword or identifier
uv run hecate-agent attack search "credential dumping"

# Inspect technique coverage and mapped data sources
uv run hecate-agent attack show T1003.001
```

### Live Terminal Monitoring Dashboard
```bash
# Launch interactive curses-based TUI monitoring pipeline activity
uv run hecate-agent monitor
```

---

## 🐍 Python API Usage

Hecate-Core exposes a clean programmatic API in [`hecate_agent.api`](file:///home/chemch/betas/Hecate-Core/hecate_agent/api.py):

```python
from hecate_agent.api import (
    generate_hypothesis,
    generate_sigma_rules,
    transpile_sigma_rule,
)

# 1. Generate a grounded hypothesis from threat intelligence
hypothesis = generate_hypothesis(
    title="Salt Typhoon Cisco Router Backdoor",
    cti_text="Adversaries deployed GhostHook backdoor via CVE-2026-1934 into /tmp/gh.elf...",
)

# 2. Draft candidate Sigma detection rules
rules = generate_sigma_rules(hypothesis=hypothesis)

# 3. Transpile Sigma YAML into target SIEM dialects
for rule in rules:
    splunk_spl = transpile_sigma_rule(rule.yaml, target="splunk")
    sentinel_kql = transpile_sigma_rule(rule.yaml, target="sentinel")
    print(f"Generated Splunk SPL:\n{splunk_spl}")
```

---

## 🧪 Testing & Verification

The test suite runs offline without requiring network calls or paid API credits:

```bash
# Run full test suite (2,197+ tests)
uv run pytest -q

# Run with coverage report
uv run pytest --cov=hecate_agent tests/
```

---

## 📦 Public Metadata Exports

`hecate-agent hunt export H-0001 --public` produces a versioned metadata-only
profile for review. It excludes sessions, raw content, research, operator paths,
and claimed validation results. Titles and tags undergo privacy and source
rights review before publication. Downstream external publishing is owned by
`Hecate-Runner`.

---

## 📚 Complete Documentation

- **[System Architecture](docs/ARCHITECTURE.md)**: Three-repository design, lifecycle diagrams, and agent graphs.
- **[Feature Reference](docs/FEATURES.md)**: Exhaustive breakdown of ingestion, dual-track scheduling, and evaluation.
- **[Engineering Challenges](docs/CHALLENGES.md)**: Deep dive into hallucination defense, token economics, and telemetry synthesis.
- **[Developer How-To Guides](docs/HOW_TO.md)**: Step-by-step recipes for adding CTI feeds, SIEM targets, and local evals.
- **[New Developer Onboarding](docs/ONBOARDING.md)**: Getting started guide for new joiners.
- **[CLI Reference](docs/CLI_REFERENCE.md)**: Full argument documentation for every CLI command.

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
