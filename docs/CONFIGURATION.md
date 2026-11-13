# Hecate Configuration Reference

This guide describes Core configuration, workspace YAML and model setup. The
feature stubs in [Core `.env.example`](../.env.example) and
[Runner `.env.example`](https://github.com/Hecate-Org/Hecate-Runner/blob/main/.env.example)
are companion references for current integrations. Runner scheduling, BAS,
publication and services are documented in its operating guides.

Export `HECATE_WORKSPACE` before launching either application. Both read its
ignored `.env`; process environment values win, and a cwd `.env` can override
workspace values. Local `.env` settings do not configure GitHub Actions, which
uses repository secrets/variables and workflow inputs. No repository supplies
working credentials or measured enterprise knowledge.

---

## Table of Contents

1. [How the Pipeline Works](#how-the-pipeline-works)
2. [Quick Setup](#quick-setup)
3. [API Keys Reference](#api-keys-reference)
4. [LLM Provider Configuration](#llm-provider-configuration)
5. [`.hecateconfig.yaml` Format](#hecateconfigyaml-format)
6. [All Environment Variables](#all-environment-variables)
7. [Hunt Template (`HUNT_TEMPLATE.j2`)](#hunt-template-hunt_templatej2)
8. [MCP Server Configuration](#mcp-server-configuration)
9. [STIX / ATT&CK Data](#stix--attck-data)
10. [Docker Configuration](#docker-configuration)

---

## How the Pipeline Works

```
User / AI assistant
        │
        ▼
┌───────────────────────────────────────────────────────────────────┐
│  1. RESEARCH   hecate-agent research new --topic "..." --technique T1003  │
│     • Skill 1: System internals (web search via Tavily)           │
│     • Skill 2: Adversary tradecraft (web search + ATT&CK STIX)    │
│     • Skill 3: Telemetry mapping (OCSF schema + environment.md)   │
│     • Skill 4: Related past hunts (semantic similarity search)    │
│     • Skill 5: Synthesis (LLM aggregation)                        │
│     → Creates R-XXXX.md in research/                              │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  2. HYPOTHESIS   hecate-agent agent run hypothesis-generator              │
│     • Loads research context from R-XXXX.md                       │
│     • Injects real ATT&CK technique names (STIX grounding)        │
│     • Calls LLM to generate structured JSON hypothesis            │
│     • Validates output T-codes against ATT&CK (strips hallucinations) │
│     → Prints hypothesis; optionally appends to R-XXXX.md          │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  3. HUNT CREATION   hecate-agent hunt new --research R-XXXX               │
│     • Renders HUNT_TEMPLATE.j2 with hypothesis fields             │
│     • Creates H-XXXX.md in hunts/production/YYYY/QN/             │
│     • Validates YAML frontmatter                                  │
│     → Hunt file ready for query development                       │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  4. QUERY EXECUTION   (human or data source integration)          │
│     • Analyst writes and runs queries (Splunk, KQL, SQL, etc.)    │
│     • hecate-agent splunk search (Splunk REST integration)                │
│     • Results recorded in hunt file (CHECK section)               │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  5. DOCUMENTATION   (human edits hunt file)                       │
│     • KEEP section: findings, TP/FP counts, lessons learned       │
│     • hecate-agent hunt validate H-XXXX (CI/CD check)                    │
│     • hecate-agent investigate promote I-XXXX (if started as investigation)│
└───────────────────────────────────────────────────────────────────┘
```

Each LLM call is grounded with real data where possible:
- **Technique names/descriptions** come from local ATT&CK STIX data (`hecate-agent attack update`)
- **Adversary tradecraft** comes from Tavily web search results
- **Telemetry fields** come from `knowledge/OCSF_SCHEMA_REFERENCE.md` and `environment.md`
- **Past hunt context** comes from local semantic search against `hunts/`

---

## Quick Setup

### Minimum viable (no AI, no web search)

```bash
pip install -e .        # from your Hecate-Core clone; no registry release is required
hecate-agent hunt new --technique T1003.001 --title "LSASS Dumping" --non-interactive
```

Install commands in this guide are run from your clone.

No API keys required. Hunt creation and management work fully offline.

### With AI hypothesis generation (pick one LLM provider)

```bash
# Option A: Anthropic (Claude)
export ANTHROPIC_API_KEY=sk-ant-...
pip install -e ".[litellm]"

# Option B: OpenAI
export OPENAI_API_KEY=sk-...

# Option C: Local Ollama (no API key needed)
# Install Ollama: https://ollama.com, then:
ollama pull qwen2.5:14b
# Hecate auto-detects Ollama at localhost:11434
```

### With research agent (requires web search)

```bash
export TAVILY_API_KEY=tvly-...
hecate-agent research new --topic "LSASS dumping" --technique T1003.001
```

Get a free Tavily key at <https://tavily.com> (1,000 free searches/month).

### With live ATT&CK data (better grounding)

```bash
pip install -e ".[attack]"
hecate-agent attack update   # Downloads ~50 MB STIX bundle once
```

---

## API Keys Reference

| Key | Required? | What It Enables | Where to Get It |
|-----|-----------|-----------------|-----------------|
| `ANTHROPIC_API_KEY` | Optional | Claude hypothesis/research generation | <https://console.anthropic.com> |
| `OPENAI_API_KEY` | Optional | GPT-4 hypothesis/research generation | <https://platform.openai.com> |
| `TAVILY_API_KEY` | Optional | Web search in research agent (Skills 1 & 2) | <https://tavily.com> |
| `SPLUNK_TOKEN` | Optional | `hecate-agent splunk search` — execute SPL queries | Splunk Settings → Tokens |
| `AWS_PROFILE` / `AWS_ACCESS_KEY_ID` | Optional | AWS Bedrock LLM provider | AWS IAM |

**None of these are required to use core Hecate features** (hunt creation, validation, search, statistics). They unlock progressively richer AI capabilities.

### What happens without each key

| Missing Key | Effect |
|-------------|--------|
| No LLM key and no Ollama | `hecate-agent agent run` and `hecate-agent research new` fall back to template-based output (no AI analysis) |
| No `TAVILY_API_KEY` | Research Skill 1 and Skill 2 proceed with model recall only; findings are flagged `[UNCERTAIN]` |
| No `SPLUNK_TOKEN` | `hecate-agent splunk` commands fail with a credentials error |
| No ATT&CK STIX | Technique grounding uses FallbackProvider; output T-code validation is skipped |

---

## LLM Provider Configuration

### Auto-detection order

Prefer explicit `HECATE_LLM_PROVIDER` and `HECATE_LLM_MODEL`, using a model
available in your account or local server. Auto-detection can select a different
provider when several credentials are present. Its exact defaults live in
`hecate_agent/core/llm_provider.py`; they are implementation choices, not
guarantees of provider model availability.

Supported adapters include OpenAI-compatible, LiteLLM, Bedrock and Ollama.
Anthropic uses LiteLLM with its appropriate model ID/key. Basic hunt management
remains offline; model-assisted generation and web search have separate prerequisites.

### Config file override (`.hecateconfig.yaml`)

Takes priority over auto-detection. Supports all four providers:

```yaml
# Anthropic via LiteLLM
llm:
  provider: litellm
  model: anthropic/claude-opus-4-5

# OpenAI-compatible (including Azure, Together, etc.)
llm:
  provider: openai
  model: gpt-4o-mini
  base_url: https://api.openai.com/v1   # optional override

# AWS Bedrock
llm:
  provider: bedrock
  model: us.anthropic.claude-sonnet-4-5-20250929-v1:0
  region: us-west-2

# Local Ollama
llm:
  provider: ollama
  model: qwen2.5:14b
  base_url: http://localhost:11434
  timeout_sec: 300   # seconds per request (default: 180)
```

### Environment variable overrides

Environment variables take priority over `.hecateconfig.yaml`:

```bash
HECATE_LLM_PROVIDER=ollama      # Force a specific provider
HECATE_LLM_MODEL=llama3.2:3b   # Override the model
HECATE_LLM_BASE_URL=http://...  # Override the base URL (useful in Docker)
HECATE_OLLAMA_TIMEOUT_SEC=300   # Ollama request timeout
```

### Full priority order (highest → lowest)

```
explicit config dict (programmatic API)
  └── HECATE_LLM_PROVIDER / HECATE_LLM_MODEL / HECATE_LLM_BASE_URL (env vars)
        └── .hecateconfig.yaml llm section (config file)
              └── auto-detection (ANTHROPIC_API_KEY → OPENAI_API_KEY → AWS → Ollama)
```

### Provider-specific notes

**LiteLLM** (`provider: litellm`)
- Requires: `pip install -e ".[litellm]"`
- Supports 100+ models via a single interface (Anthropic, OpenAI, Gemini, Cohere, etc.)
- Model names follow LiteLLM format: `anthropic/claude-opus-4-5`, `openai/gpt-4o`, `gemini/gemini-2.0-flash`
- Set the corresponding provider API key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.)

**Bedrock** (`provider: bedrock`)
- Requires: `pip install -e ".[bedrock]"`
- Uses your existing AWS credentials (`~/.aws/credentials` or IAM role)
- Set `AWS_PROFILE` or `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
- Region defaults to `us-east-1`; override with `AWS_REGION` or config `region:`

**Ollama** (`provider: ollama`)
- Requires: `pip install -e ".[ollama]"` + local Ollama installation
- No API key needed — runs locally
- Install Ollama: <https://ollama.com>
- Pull a model before use: `ollama pull qwen2.5:14b`
- Recommended models by hardware:
  - Apple Silicon (M1/M2/M3): `qwen2.5:14b`, `phi4:14b`, `llama3.1:8b`
  - NVIDIA GPU: `qwen2.5:32b`, `llama3.1:70b`
  - CPU only: `qwen2.5:3b`, `llama3.2:1b`

**OpenAI-compatible** (`provider: openai`)
- Works with OpenAI and any API that follows the OpenAI schema (Together.ai, Groq, LM Studio, vLLM, etc.)
- Set `base_url` in config to point at a non-OpenAI endpoint

---

## `.hecateconfig.yaml` Format

Hecate looks for this file in two locations: `.hecateconfig.yaml` and
`config/.hecateconfig.yaml`. Keep only one. Workspace discovery checks the
root file first, while the LLM settings and hunt creation read
`config/.hecateconfig.yaml` first, both relative to the directory you run
`hecate-agent` from.

**Full example:**

```yaml
# LLM provider configuration
llm:
  provider: ollama          # litellm | bedrock | ollama | openai
  model: qwen2.5:14b
  base_url: http://localhost:11434
  timeout_sec: 300          # Ollama only (default: 180)
  num_ctx: 16384            # Ollama only: context window in tokens (default: 16384)
  think: false              # Ollama only: turn off a reasoning model's thinking

# Prefix for hunt IDs (optional, top-level; default: H-)
hunt_prefix: H-
```

Research (`R-`) and investigation (`I-`) prefixes are fixed.

This file is gitignored by default — it is machine-local config (your LLM key, local Ollama URL, etc.). Commit `environment.md` for team-shared context instead.

---

## All Environment Variables

### LLM / AI

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | Anthropic API key; triggers auto-detection |
| `OPENAI_API_KEY` | — | OpenAI API key; triggers auto-detection |
| `HECATE_LLM_PROVIDER` | auto | Force provider: `litellm`, `bedrock`, `ollama`, `openai` |
| `HECATE_LLM_MODEL` | provider default | Override model name |
| `HECATE_LLM_BASE_URL` | provider default | Override API base URL (useful in Docker) |
| `HECATE_LLM_SIMPLE_PROVIDER` / `_MODEL` / `_BASE_URL` | inherit root | Dual-router local/simple backend (volume work: extraction, summarize, pivots) |
| `HECATE_LLM_COMPLEX_PROVIDER` / `_MODEL` / `_BASE_URL` | inherit root | Dual-router complex backend (hypothesis, Sigma, triage, synthesis) |
| `HECATE_LLM_SIMPLE_MAX_PROMPT_CHARS` | `12000` | Soft clip for simple-tier prompts so local models are not silently truncated mid-token |
| `HECATE_LLM_ALLOW_DEMOTION` | unset | `1` unlocks routing locked capabilities to simple without an eval gate (lab only) |
| `HECATE_LLM_DEMOTION_GATES` | `.hecate/llm_demotion_gates.json` | Path to demotion gate stamps written by `hecate-agent eval --write-gate` |
| `HECATE_OLLAMA_TIMEOUT_SEC` | `180` | Per-request timeout for Ollama calls |
| `HECATE_OLLAMA_NUM_CTX` | `16384` | Context window requested per Ollama call. Ollama's own default of 4096 silently truncates long prompts |
| `HECATE_OLLAMA_THINK` | model default | `false` stops a reasoning model spending its output budget on thinking |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | — | Gemini key, used through LiteLLM. Not auto-detected: also set `HECATE_LLM_PROVIDER=litellm` and a `gemini/...` model |
| `HECATE_LLM_CALL_LOG` | unset (off) | File to append every provider call to as it starts and ends. Hecate-Runner sets it so `hecate-agent monitor` can show a running cycle's usage |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama service URL |

#### Dual LLM demotions

Locked capabilities (`hypothesis`, `sigma_draft`, `sigma_review`, `finding_triage`,
`research_synthesize`) stay on complex until you prove the simple backend:

1. `hecate-agent eval --tier simple --write-gate research_synthesize --fail-under 0.8`
2. Confirm `.hecate/llm_demotion_gates.json` records `allowed: true`
3. Set in `.hecateconfig.yaml`:

```yaml
llm:
  defaults:
    research_synthesize: simple
```

Lab bypass (skips the gate): `HECATE_LLM_ALLOW_DEMOTION=1`.

### AWS Bedrock

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_PROFILE` | — | AWS credentials profile name |
| `AWS_ACCESS_KEY_ID` | — | AWS access key (alternative to profile) |
| `AWS_SECRET_ACCESS_KEY` | — | AWS secret key |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | `us-east-1` | AWS region for Bedrock |

### Web Search (Research Agent)

| Variable | Default | Description |
|----------|---------|-------------|
| `TAVILY_API_KEY` | — | Tavily search API key. Without this, Skills 1 & 2 run without web context and flag uncertain findings with `[UNCERTAIN]` |

### Splunk Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLUNK_HOST` | — | Splunk hostname or IP |
| `SPLUNK_TOKEN` | — | Splunk authentication token |
| `SPLUNK_VERIFY_SSL` | `true` | Whether to verify Splunk SSL certificate |

### Hecate Workspace & Data

| Variable | Default | Description |
|----------|---------|-------------|
| `HECATE_WORKSPACE` | cwd walk-up | Explicit workspace root path (MCP server) |
| `HECATE_HUNTING_KNOWLEDGE` | unset (off) | Inject `knowledge/hunting-knowledge.md` tradecraft into agent prompts. **Off by default** — it measurably degraded hypothesis quality |
| `HECATE_STIX_CACHE` | `~/.hecate/stix-data/` | Directory for ATT&CK STIX JSON cache |

---

## Hunt Template (`HUNT_TEMPLATE.j2`)

Located at `templates/HUNT_TEMPLATE.j2`. Rendered by `hecate-agent hunt new` using Jinja2. You can edit this file to change the structure of every new hunt file created in your workspace.

### Available template variables

| Variable | Type | Source | Description |
|----------|------|--------|-------------|
| `hunt_id` | `str` | auto | Sequential ID, e.g. `H-0042` |
| `title` | `str` | `--title` | Hunt title |
| `status` | `str` | `--status` | Default: `in-progress` |
| `date` | `str` | auto | Today's date (`YYYY-MM-DD`) |
| `hunter` | `str` | `--hunter` | Analyst name. Default: `AI Assistant` |
| `platform` | `list[str]` | `--platform` | e.g. `["Windows", "macOS"]` |
| `tactics` | `list[str]` | `--tactic` | e.g. `["credential-access"]` |
| `techniques` | `list[str]` | `--technique` | e.g. `["T1003.001"]` |
| `data_sources` | `list[str]` | `--data-source` | e.g. `["EDR process telemetry"]` |
| `tags` | `list[str]` | `--tags` | Arbitrary tags |
| `hypothesis` | `str \| None` | `--hypothesis` | Full hypothesis statement |
| `threat_context` | `str \| None` | `--threat-context` | Threat intel motivating the hunt |
| `actor` | `str \| None` | `--actor` | Threat actor (ABLE framework) |
| `behavior` | `str \| None` | `--behavior` | Behavior description (ABLE) |
| `location` | `str \| None` | `--location` | Scope / environment (ABLE) |
| `evidence` | `str \| None` | `--evidence` | Data fields to examine (ABLE) |
| `spawned_from` | `str \| None` | `--research` | Research doc ID, e.g. `R-0001` |
| `hypothesis_duration_minutes` | `float \| None` | `--hypothesis-duration` | Time spent on hypothesis |

### Customizing the template

Edit `templates/HUNT_TEMPLATE.j2` directly. The template uses standard Jinja2 syntax:

```jinja
{# Conditional section #}
{% if actor %}
**Threat Actor:** {{ actor }}
{% endif %}

{# Default value #}
**Status:** {{ status | default('in-progress') }}

{# Join a list #}
**Techniques:** {{ ', '.join(techniques) if techniques else 'TBD' }}
```

Changes take effect immediately on the next `hecate-agent hunt new`. Existing hunt files are not affected.

### LOCK section structure

The template follows the LOCK pattern. Each section serves a specific purpose:

| Section | Purpose | Fill in when |
|---------|---------|--------------|
| **LEARN** | Hypothesis, threat context, ABLE scoping, related research | Hunt creation |
| **OBSERVE** | Normal vs. suspicious behavior, expected observables | Before query execution |
| **CHECK** | Query text, results, performance notes | During hunt execution |
| **KEEP** | Findings, TP/FP counts, lessons learned, follow-up actions | Hunt completion |

---

## MCP Server Configuration

The MCP server exposes Hecate as tools for AI assistants (Claude Code, Cursor, Copilot, etc.).

### Starting the server

```bash
# Default (stdio transport — for Claude Code / local AI tools)
hecate-agent mcp serve

# HTTP transport (for remote / networked AI tools)
hecate-agent mcp serve --transport streamable-http --port 8080

# Explicit workspace
hecate-agent mcp serve --workspace /path/to/your/workspace
```

### Workspace discovery (server)

The server finds your workspace in this order:
1. `--workspace` CLI flag
2. `HECATE_WORKSPACE` environment variable
3. Walk up from `cwd` looking for `.hecateconfig.yaml`

### Claude Code integration

Add to your `.claude/settings.json` or `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "hecate": {
      "command": "hecate-agent-mcp",
      "env": {
        "HECATE_WORKSPACE": "/path/to/your/workspace"
      }
    }
  }
}
```

Or use `hecate-agent-mcp` as a standalone entry point (installed alongside `hecate-agent`).

### MCP tools that create files

These tools write to your workspace without a confirmation prompt:

| Tool | Creates | Notes |
|------|---------|-------|
| `hecate_hunt_new` | `hunts/production/YYYY/QN/H-XXXX.md` | Atomic exclusive create |
| `hecate_research_new` | `research/R-XXXX.md` | |
| `hecate_investigate_new` | `investigations/I-XXXX.md` | |
| `hecate_agent_run_researcher` | `research/R-XXXX.md` | Full 5-skill research |
| `hecate_agent_run_hypothesis` (with `research_id`) | Appends to existing `R-XXXX.md` | |

---

## STIX / ATT&CK Data

Live ATT&CK data improves grounding across all LLM calls:
- Technique names and descriptions are injected into prompts (not recalled from model memory)
- Output technique IDs are validated against the real matrix (hallucinated IDs are stripped)

### Setup

```bash
pip install -e ".[attack]"
hecate-agent attack update        # Downloads enterprise-attack.json (~50 MB, one-time)
hecate-agent attack status        # Verify: shows provider type, technique count, version
hecate-agent attack lookup T1003.001   # Spot-check a technique
```

### Cache location

```
Default:  ~/.hecate/stix-data/enterprise-attack.json
Workspace: <workspace>/.hecate/stix-data/  (if .hecateconfig.yaml exists in workspace)
Override:  HECATE_STIX_CACHE=/custom/path
```

### Without STIX

Hecate falls back to `FallbackProvider` which has no technique data. This means:
- Technique grounding in prompts is skipped (model uses recall)
- Output T-code validation is skipped (hallucinated IDs pass through)
- `hecate-agent attack lookup` returns nothing

---

## Docker Configuration

### Environment variables for containers

```yaml
# docker-compose.yml excerpt
environment:
  - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
  - OPENAI_API_KEY=${OPENAI_API_KEY:-}
  - TAVILY_API_KEY=${TAVILY_API_KEY:-}
  - HECATE_LLM_PROVIDER=${HECATE_LLM_PROVIDER:-}
  - HECATE_LLM_MODEL=${HECATE_LLM_MODEL:-}
  # Override config file's base_url so the container reaches host Ollama:
  - HECATE_LLM_BASE_URL=${HECATE_LLM_BASE_URL:-http://host.docker.internal:11434}
  - OLLAMA_HOST=${OLLAMA_HOST:-http://host.docker.internal:11434}
```

### Running with native macOS Ollama (recommended)

```bash
# 1. Start Ollama on your Mac (uses Metal GPU automatically)
ollama serve
ollama pull qwen2.5:14b

# 2. Start Hecate container (points at host Ollama)
cd deploy
docker compose up -d hecate
docker compose exec hecate bash

# Inside container — Ollama is reachable at host.docker.internal:11434
hecate-agent agent run hypothesis-generator --threat-intel "..."
```

### Running with containerized Ollama

```bash
cd deploy
# Pulls qwen2.5:14b on first run (~9 GB)
docker compose --profile ollama up -d

# Override model
OLLAMA_MODEL=llama3.1:8b docker compose --profile ollama up -d
```

### `.env` file

The compose file lives in `deploy/` and reads its `.env` from there. Copy the
template next to it and fill in your keys:

```bash
cp .env.example deploy/.env
# Edit deploy/.env with your API keys
cd deploy && docker compose up -d
```

The `.env` file is gitignored. Never commit API keys to version control.
