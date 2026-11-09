# Hecate CLI Reference

Reference for the main `hecate-agent` commands. The CLI also includes
`eval-gold`, optional `splunk` commands, and the experimental `orchestrate`
graph, which is not the pipeline the Runner uses (to draft a hunt from
intelligence you supply through that pipeline, use `hecate-runner draft`); use
`hecate-agent --help` and `hecate-agent COMMAND --help` for the installed
version's complete, authoritative command and option list.

## Command Quick Reference

| Command | Category | Description |
|---------|----------|-------------|
| [`hecate-agent env setup`](#hecate-agent-env) | Environment | Setup Python virtual environment with dependencies |
| [`hecate-agent env info`](#hecate-agent-env) | Environment | Show virtual environment information |
| [`hecate-agent agent list`](#hecate-agent-agent-list) | Agent Framework | List all available agents |
| [`hecate-agent agent info`](#hecate-agent-agent-info) | Agent Framework | Show detailed agent information |
| [`hecate-agent agent run`](#hecate-agent-agent-run) | Agent Framework | Run individual agent |
| [`hecate-agent research new`](#hecate-agent-research-new) | Research | Create new research document with web search |
| [`hecate-agent research list`](#hecate-agent-research-list) | Research | List all research documents |
| [`hecate-agent research view`](#hecate-agent-research-view) | Research | View research document |
| [`hecate-agent research link`](#hecate-agent-research-link) | Research | Back-link a hunt to its source research document |
| [`hecate-agent research search`](#hecate-agent-research-search) | Research | Full-text search across research documents |
| [`hecate-agent research stats`](#hecate-agent-research-stats) | Research | Show research program statistics |
| [`hecate-agent hunt new`](#hecate-agent-hunt-new) | Hunt Management | Create new hunt from template with auto-generated ID |
| [`hecate-agent hunt list`](#hecate-agent-hunt-list) | Hunt Management | List all hunts with optional filtering |
| [`hecate-agent hunt validate`](#hecate-agent-hunt-validate) | Hunt Management | Validate hunt file structure and metadata |
| [`hecate-agent hunt stats`](#hecate-agent-hunt-stats) | Hunt Management | Display hunt statistics and success metrics |
| [`hecate-agent hunt search`](#hecate-agent-hunt-search) | Hunt Management | Full-text search across all hunts |
| [`hecate-agent hunt coverage`](#hecate-agent-hunt-coverage) | Hunt Management | Display MITRE ATT&CK coverage heatmap |
| [`hecate-agent hunt new-baseline`](#hecate-agent-hunt-new-baseline) | Hunt Management | Create a hypothesis-free baseline (EDA) hunt |
| [`hecate-agent hunt new-model-assisted`](#hecate-agent-hunt-new-model-assisted) | Hunt Management | Create a model-assisted (M-ATH) hunt |
| [`hecate-agent hunt update`](#hecate-agent-hunt-update) | Hunt Management | Patch hunt frontmatter fields in place |
| [`hecate-agent hunt promote`](#hecate-agent-hunt-promote) | Hunt Management | Promote a hunt from test to production |
| [`hecate-agent hunt operationalize`](#hecate-agent-hunt-operationalize) | Hunt Management | Generate a Sigma rule stub from a hunt |
| [`hecate-agent hunt brief`](#hecate-agent-hunt-brief) | Hunt Management | Render a stakeholder-facing hunt summary |
| [`hecate-agent hunt export`](#hecate-agent-hunt-export) | Hunt Management | Export hunt data as structured JSON |
| [`hecate-agent attack update`](#hecate-agent-attack-update) | ATT&CK Data | Download/refresh STIX data from MITRE |
| [`hecate-agent attack status`](#hecate-agent-attack-status) | ATT&CK Data | Show provider type, version, and cache info |
| [`hecate-agent attack lookup`](#hecate-agent-attack-lookup) | ATT&CK Data | Look up technique metadata by ID |
| [`hecate-agent attack techniques`](#hecate-agent-attack-techniques) | ATT&CK Data | List all techniques for a tactic |
| [`hecate-agent attack gap`](#hecate-agent-attack-gap) | ATT&CK Data | List techniques no hunt covers yet |
| [`hecate-agent investigate new`](#hecate-agent-investigate-new) | Investigation | Create new investigation file for exploratory work |
| [`hecate-agent investigate list`](#hecate-agent-investigate-list) | Investigation | List all investigations with optional filtering |
| [`hecate-agent investigate search`](#hecate-agent-investigate-search) | Investigation | Full-text search across investigations |
| [`hecate-agent investigate validate`](#hecate-agent-investigate-validate) | Investigation | Validate investigation file structure |
| [`hecate-agent investigate promote`](#hecate-agent-investigate-promote) | Investigation | Promote investigation to formal hunt |
| [`hecate-agent context`](#hecate-agent-context) | AI Optimization | Export AI-optimized context bundle (saves ~75% tokens) |
| [`hecate-agent similar`](#hecate-agent-similar) | AI Optimization | Find similar hunts using semantic search |
| [`hecate-agent monitor`](#hecate-agent-monitor) | Monitoring | Live terminal dashboard for pipeline activity, host resources, and usage |
| [`hecate-agent eval`](#hecate-agent-eval) | Model Quality | Score a model against known-answer fixtures |
| [`hecate-agent mcp serve`](#hecate-agent-mcp-serve) | Integration | Serve Hecate operations as MCP tools |

## Table of Contents

- [Installation](#installation)
- [Global Options](#global-options)
- [hecate-agent env](#hecate-agent-env)
- [hecate-agent agent list](#hecate-agent-agent-list)
- [hecate-agent agent info](#hecate-agent-agent-info)
- [hecate-agent agent run](#hecate-agent-agent-run)
- [hecate-agent research new](#hecate-agent-research-new)
- [hecate-agent research list](#hecate-agent-research-list)
- [hecate-agent research view](#hecate-agent-research-view)
- [hecate-agent research link](#hecate-agent-research-link)
- [hecate-agent research search](#hecate-agent-research-search)
- [hecate-agent research stats](#hecate-agent-research-stats)
- [hecate-agent context](#hecate-agent-context)
- [hecate-agent monitor](#hecate-agent-monitor)
- [hecate-agent similar](#hecate-agent-similar)
- [hecate-agent hunt new](#hecate-agent-hunt-new)
- [hecate-agent hunt list](#hecate-agent-hunt-list)
- [hecate-agent hunt validate](#hecate-agent-hunt-validate)
- [hecate-agent hunt stats](#hecate-agent-hunt-stats)
- [hecate-agent hunt search](#hecate-agent-hunt-search)
- [hecate-agent hunt coverage](#hecate-agent-hunt-coverage)
- [hecate-agent hunt new-baseline](#hecate-agent-hunt-new-baseline)
- [hecate-agent hunt new-model-assisted](#hecate-agent-hunt-new-model-assisted)
- [hecate-agent hunt update](#hecate-agent-hunt-update)
- [hecate-agent hunt promote](#hecate-agent-hunt-promote)
- [hecate-agent hunt operationalize](#hecate-agent-hunt-operationalize)
- [hecate-agent hunt brief](#hecate-agent-hunt-brief)
- [hecate-agent hunt export](#hecate-agent-hunt-export)
- [hecate-agent investigate new](#hecate-agent-investigate-new)
- [hecate-agent investigate list](#hecate-agent-investigate-list)
- [hecate-agent investigate search](#hecate-agent-investigate-search)
- [hecate-agent investigate validate](#hecate-agent-investigate-validate)
- [hecate-agent investigate promote](#hecate-agent-investigate-promote)
- [hecate-agent attack gap](#hecate-agent-attack-gap)
- [hecate-agent eval](#hecate-agent-eval)
- [hecate-agent mcp serve](#hecate-agent-mcp-serve)
- [Configuration](#configuration)
- [Exit Codes](#exit-codes)

---

## Installation

```bash
git clone https://github.com/BrizoSec/Hecate-Core.git
cd Hecate-Core
pip install -e .
```

See [INSTALL.md](https://github.com/BrizoSec/Hecate-Core/blob/main/docs/INSTALL.md) for detailed installation instructions.

---

## Global Options

These options work with any `hecate-agent` command:

```bash
hecate-agent --version          # Show version and exit
hecate-agent --help             # Show help message
hecate-agent <command> --help   # Show help for specific command
```

---

## hecate-agent monitor

Open a live, htop-style terminal dashboard for the Hecate Runner pipeline.

### Synopsis

```bash
hecate-agent monitor [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--workspace` | Path | detected workspace | Workspace containing the Runner `logs/` directory |
| `--interval` | Number | `1.0` | Screen refresh interval in seconds (0.5–30) |

The dashboard follows `logs/orchestrator.log` for the live cycle, pipeline
stage, and action stream. It reads `logs/stage_metrics.jsonl` for the latest
completed cycle's model calls, tokens, and reported cost. Token metrics are
written at cycle completion, so live calls show as pending until then. On
wider terminals the usage panel also breaks token counts down by pipeline
stage. System panels display CPU, memory, Hecate workspace storage, and NVIDIA
GPU metrics when available. Storage includes the filesystem containing the
workspace and any separate filesystems mounted inside it; unrelated mounted
drives, pseudo-filesystems, and duplicate bind mounts are omitted. Unsupported
hardware is shown as unavailable. Credential panels show only
whether a key is configured, never its value. Press Ctrl-C to exit.

When the `hecate-runner-orchestrator` systemd service is installed, the
dashboard also shows service and timer state, a countdown to the timer's next
run, daily draft and research quota, parked items, and total drafts. The
high-signal backlog count comes from the most recent intake trail event and is
timestamped; it is the last observed count, not a live feed query. Compact
terminals show this service summary in the footer. The service panel is omitted
when the systemd unit is not installed.

### Example

```bash
hecate-agent monitor
hecate-agent monitor --workspace /path/to/Hecate-Core --interval 2
```

---

## hecate-agent env

Manage Python virtual environment for Hecate development.

### Synopsis

```bash
hecate-agent env [COMMAND] [OPTIONS]
```

### Description

Provides commands for managing Python virtual environments, including setup, information display, and cleanup. Simplifies dependency management and ensures consistent development environments.

### Subcommands

| Command | Description |
|---------|-------------|
| `setup` | Setup virtual environment with dependencies |
| `info` | Show virtual environment information |
| `clean` | Remove virtual environment |
| `activate` | Show command to activate virtual environment |
| `deactivate` | Show command to deactivate virtual environment |
| `check` | Run a dependency health checklist for the workspace |

### hecate-agent env setup

Setup Python virtual environment with dependencies.

**Synopsis:**
```bash
hecate-agent env setup [OPTIONS]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--python` | String | python3 | Python interpreter to use |
| `--dev` | Flag | False | Install development dependencies |
| `--clean` | Flag | False | Remove existing venv before setup |

**Examples:**

```bash
# Basic setup
hecate-agent env setup

# Setup with dev dependencies
hecate-agent env setup --dev

# Clean install
hecate-agent env setup --clean

# Use specific Python version
hecate-agent env setup --python python3.11 --dev
```

### hecate-agent env info

Show virtual environment information.

**Synopsis:**
```bash
hecate-agent env info
```

**Examples:**

```bash
hecate-agent env info
```

**Output:**
```
Virtual Environment Info:

  Location: /path/to/.venv
  Python: Python 3.11.5
  Packages: 42 installed
  hecate: ✓ Installed (version 0.2.1)
  scikit-learn: ✓ Installed (required for hecate-agent similar)
```

### hecate-agent env clean

Remove virtual environment.

**Synopsis:**
```bash
hecate-agent env clean
```

**Examples:**

```bash
hecate-agent env clean
```

### hecate-agent env activate

Show command to activate virtual environment.

**Synopsis:**
```bash
hecate-agent env activate
```

**Examples:**

```bash
# Show activation command
hecate-agent env activate

# Copy and run the printed command
source .venv/bin/activate
```

**Note:** Cannot activate directly (subprocesses can't modify parent shell). Copy and run the printed command.

### hecate-agent env deactivate

Show command to deactivate virtual environment.

**Synopsis:**
```bash
hecate-agent env deactivate
```

**Examples:**

```bash
# Show deactivation command
hecate-agent env deactivate

# Copy and run the printed command
deactivate
```

### Exit Codes

- `0`: Success
- `1`: Environment operation failed

---

## hecate-agent context

Export AI-optimized context bundle to reduce token usage.

### Synopsis

```bash
hecate-agent context [OPTIONS]
```

### Description

Combines relevant files into a single structured output for AI assistants. Reduces context-loading from ~5 tool calls to 1, saving ~2,000 tokens per hunt (~75% reduction). Includes environment.md, hunts/INDEX.md, hunt files, and domain knowledge.

**Token Savings:**
- **Without context**: ~5 Read operations, ~3,000 tokens
- **With context**: 1 command, ~1,000 tokens
- **Savings**: ~2,000 tokens per hunt (~$0.03 per hunt)

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--hunt` | String | - | Hunt ID to export context for (e.g., H-0013) |
| `--tactic` | String | - | MITRE tactic to filter hunts (e.g., credential-access) |
| `--platform` | String | - | Platform to filter hunts (e.g., macos, windows, linux) |
| `--full` | Flag | False | Export full repository context (use sparingly) |
| `--format` | Choice | json | Output format: `json`, `markdown`, `yaml` |
| `--output` | Path | - | Output file path (default: stdout) |

**Note:** Must specify exactly one of: `--hunt`, `--tactic`, `--platform`, or `--full`.

### Examples

**Export context for specific hunt:**

```bash
hecate-agent context --hunt H-0013 --format json
```

**Export context for all credential access hunts:**

```bash
hecate-agent context --tactic credential-access --format json
```

**Export context for macOS platform hunts:**

```bash
hecate-agent context --platform macos --format json
```

**Export as markdown:**

```bash
hecate-agent context --hunt H-0013 --format markdown
```

**Save to file:**

```bash
hecate-agent context --hunt H-0013 --format json --output context.json
```

**Export full repository context** (large output):

```bash
hecate-agent context --full --format json
```

### Output Structure (JSON)

```json
{
  "metadata": {
    "generated_by": "hecate-agent context",
    "filters": {
      "hunt": "H-0013",
      "tactic": null,
      "platform": null,
      "full": false
    }
  },
  "environment": "# Tech stack, data sources...",
  "hunt_index": "# Hunt metadata index...",
  "hunts": [
    {
      "hunt_id": "H-0013",
      "content": "---\nhunt_id: H-0013\ntitle: ..."
    }
  ],
  "domain_knowledge": [
    {
      "file": "knowledge/hunting-knowledge.md",
      "content": "# Hunting knowledge..."
    }
  ]
}
```

### Use Cases

- **AI assistants**: Reduce context-loading from ~5 tool calls to 1
- **Token optimization**: Pre-filtered, structured content only
- **Hunt planning**: Get all relevant context in one shot
- **Query generation**: Include past hunt lessons and data sources

### Exit Codes

- `0`: Success
- `1`: Invalid filter options or missing files

---

## hecate-agent similar

Find hunts similar to a query or hunt ID using semantic search.

### Synopsis

```bash
hecate-agent similar [QUERY] [OPTIONS]
hecate-agent similar --hunt HUNT_ID [OPTIONS]
```

### Description

Uses semantic similarity (TF-IDF) to find related hunts even when terminology differs. Better than keyword search for discovering patterns and avoiding duplicate hunts. Requires `scikit-learn` to be installed.

**Why This Helps:**
- Semantic search (not just keyword matching)
- Find related hunts with different terminology
- Discover patterns across hunt history
- Identify similar hunts to avoid duplication

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `QUERY` | String (optional) | Search query text |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--hunt` | String | - | Hunt ID to find similar hunts for (e.g., H-0013) |
| `--limit` | Integer | 10 | Maximum number of results |
| `--format` | Choice | table | Output format: `table`, `json`, `yaml` |
| `--threshold` | Float | 0.1 | Minimum similarity score (0-1) |
| `--sessions` | Flag | False | Include session logs as separate results |

**Note:** Must provide either `QUERY` or `--hunt` option.

### Examples

**Find hunts similar to text query:**

```bash
hecate-agent similar "password spraying via RDP"
```

**Find hunts similar to specific hunt:**

```bash
hecate-agent similar --hunt H-0013
```

**Limit results to top 5:**

```bash
hecate-agent similar "kerberos" --limit 5
```

**Export as JSON:**

```bash
hecate-agent similar "credential theft" --format json
```

**Set minimum similarity threshold:**

```bash
hecate-agent similar "reconnaissance" --threshold 0.3
```

### Output (Table Format)

```
Similar to: password spraying

Found 3 similar hunts

Score  Hunt ID    Title                Status       Tactics
─────────────────────────────────────────────────────────────
0.421  H-0014     Password Spraying    📋 planning  credential-access
0.318  H-0015     Brute Force Login    ✅ completed credential-access
0.251  H-0022     Account Takeover     🔄 in-progress initial-access

Similarity Score Legend:
  ≥0.50 = Very similar  |  0.30-0.49 = Similar  |  0.15-0.29 = Somewhat similar
```

### Output (JSON Format)

```json
[
  {
    "hunt_id": "H-0014",
    "similarity_score": 0.421,
    "title": "Password Spraying Detection",
    "status": "planning",
    "tactics": ["credential-access"],
    "techniques": ["T1110.003"],
    "platform": ["windows"]
  }
]
```

### Similarity Score Interpretation

| Score Range | Meaning | Recommendation |
|-------------|---------|----------------|
| ≥0.50 | Very similar | Likely duplicate or closely related |
| 0.30-0.49 | Similar | Same domain or tactic |
| 0.15-0.29 | Somewhat similar | Related concepts |
| <0.15 | Low similarity | Different topics |

### Installation

Requires `scikit-learn`:

```bash
pip install -e ".[similarity]"
```

Or install scikit-learn separately:

```bash
pip install scikit-learn
```

### Exit Codes

- `0`: Success
- `1`: Missing query/hunt option, scikit-learn not installed, or hunt not found

---

## hecate-agent hunt new

Create a new hunt from template with auto-generated ID.

### Synopsis

```bash
hecate-agent hunt new [OPTIONS]
```

### Description

Creates a new hunt file with proper YAML frontmatter and LOCK structure. Automatically assigns the next available hunt ID and generates a complete template.

### Options

**Basic Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--non-interactive` | Flag | False | Skip interactive prompts |
| `--technique` | String | Required* | MITRE ATT&CK technique (e.g., T1003.001) |
| `--title` | String | Required* | Hunt title |
| `--tactic` | String | - | MITRE tactic; repeatable |
| `--platform` | String | - | Target platform; repeatable |
| `--data-source` | String | - | Data source; repeatable |
| `--hunter` | String | config, then `Analyst` | Your name or handle |
| `--assignee` | String | - | Assign the hunt to a team member |
| `--test` | Flag | False | Create under `hunts/test/` instead of production |
| `--clone` | String | - | Clone metadata from an existing hunt (e.g., H-0013) |

`--tactic`, `--platform` and `--data-source` are singular and repeatable —
`--platform Windows --platform Linux`. Passing one comma-separated value also
lands as separate entries, but repeating the flag is the supported form.

**Rich Content Options (for AI assistants & automation):**

| Option | Type | Description |
|--------|------|-------------|
| `--hypothesis` | String | Full hypothesis statement |
| `--threat-context` | String | Threat intel or context motivating the hunt |
| `--actor` | String | Threat actor description (for ABLE framework) |
| `--behavior` | String | Behavior description (for ABLE framework) |
| `--location` | String | Location/scope description (for ABLE framework) |
| `--evidence` | String | Evidence description (for ABLE framework) |
| `--research` | String | Research document ID (e.g., R-0001) to link to this hunt |
| `--hypothesis-duration` | Float | Hypothesis generation time in minutes, for automated callers |

\* Required in non-interactive mode

### Examples

**Interactive mode** (recommended):

```bash
hecate-agent hunt new
```

Prompts:
```
1. MITRE ATT&CK Technique (e.g., T1003.001): T1558.003
2. Hunt Title: Kerberoasting Detection via Unusual TGS Requests
   Tactics [credential-access]: credential-access
   Platforms [Windows]: Windows
   Data Sources [SIEM, EDR]: windows-event-logs,edr-telemetry
```

**Non-interactive mode**:

```bash
hecate-agent hunt new \
  --technique T1558.003 \
  --title "Kerberoasting Detection" \
  --tactic credential-access \
  --platform Windows \
  --data-source windows-event-logs --data-source edr-telemetry \
  --hunter "Jane Doe" \
  --non-interactive
```

**Minimal example** (non-interactive):

```bash
hecate-agent hunt new \
  --technique T1003.001 \
  --title "LSASS Memory Dumping" \
  --non-interactive
```

**Link to pre-hunt research document**:

```bash
hecate-agent hunt new \
  --research R-0001 \
  --technique T1003.001 \
  --title "LSASS Memory Dumping Hunt" \
  --tactic credential-access \
  --platform Windows \
  --non-interactive
```

This links the hunt to research document `R-0001` (created via `hecate-agent research new`). The hunt file will include:
- `spawned_from: R-0001` in YAML frontmatter
- Link to research document in the "Threat Intel & Research" section

**AI-friendly one-liner with rich content** (full hypothesis + ABLE framework):

```bash
hecate-agent hunt new \
  --title "macOS Unix Shell Abuse for Reconnaissance" \
  --technique "T1059.004" \
  --tactic execution --tactic defense-evasion \
  --platform macOS \
  --data-source "EDR process telemetry" \
  --hypothesis "Adversaries execute malicious commands via native macOS shells to perform reconnaissance and staging activities" \
  --threat-context "macOS developer workstations are high-value targets for supply chain attacks and credential theft" \
  --actor "Generic adversary (malware droppers, supply chain attackers, insider threats)" \
  --behavior "Shell execution from unusual parents performing reconnaissance or accessing sensitive files" \
  --location "macOS endpoints (developer workstations, CI/CD infrastructure)" \
  --evidence "EDR process telemetry - Fields: process.name, process.parent.name, process.command_line" \
  --hunter "Your Name" \
  --non-interactive
```

**Benefits of rich content flags:**
- ✅ AI assistants can create fully-populated hunt files in one command
- ✅ No manual file editing required for basic hunts
- ✅ All LOCK template fields can be populated via CLI
- ✅ Backwards compatible (all new flags are optional)

### Output

```
✓ Created new hunt: H-0023
  File: /path/to/hunts/H-0023.md
  Title: Kerberoasting Detection
  Technique: T1558.003

Next steps:
  1. Edit hunts/H-0023.md
  2. Fill in the LOCK sections
  3. Execute your hunt
  4. Document findings
```

### Generated File Structure

```yaml
---
hunt_id: H-0023
title: "Kerberoasting Detection"
status: in-progress
date: 2025-12-02
updated: 2025-12-02
hunter: "Jane Doe"
techniques:
  - T1558.003
tactics:
  - credential-access
platforms:
  - windows
data_sources:
  - windows-event-logs
  - edr-telemetry
severity: high
tags: []
true_positives: 0
false_positives: 0
---

## LEARN
...
```

### Exit Codes

- `0`: Success
- `1`: Missing required options (non-interactive mode)
- `2`: Invalid technique format

---

## hecate-agent hunt list

List all hunts with optional filtering.

### Synopsis

```bash
hecate-agent hunt list [OPTIONS]
```

### Description

Display all hunts in a formatted table. Supports filtering by status, tactic, technique, and platform. Output formats include table (default), JSON, and YAML.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--status` | String | - | Filter by status: `planning`, `active`, `in_review`, `completed` |
| `--tactic` | String | - | Filter by MITRE ATT&CK tactic |
| `--technique` | String | - | Filter by technique (e.g., T1003.001) |
| `--platform` | String | - | Filter by platform |
| `--type` | Choice | - | Filter by hunt type: `hypothesis-driven`, `baseline`, `model-assisted` |
| `--assignee` | String | - | Filter by assigned team member |
| `--directory` | Choice | - | Filter by environment directory: `test`, `production` |
| `--output` | Choice | table | Output format: `table`, `json`, `yaml` |

`--type` is how you isolate the hunts made by
[`hunt new-baseline`](#hecate-agent-hunt-new-baseline) and
[`hunt new-model-assisted`](#hecate-agent-hunt-new-model-assisted).

### Examples

**List all hunts**:

```bash
hecate-agent hunt list
```

Output:
```
Hunt ID  Title                          Status      Technique   Findings
─────────────────────────────────────────────────────────────────────────
H-0001   macOS Information Stealer      completed   T1005       1 (1 TP)
H-0002   Kerberoasting Detection        in-progress T1558.003   -
H-0015   LSASS Memory Access            completed   T1003.001   3 (2 TP)
H-0023   Cloud Persistence via Lambda   paused      T1098       -
```

**Filter by status**:

```bash
hecate-agent hunt list --status completed
```

**Filter by tactic**:

```bash
hecate-agent hunt list --tactic credential-access
```

**Filter by technique**:

```bash
hecate-agent hunt list --technique T1003.001
```

**Filter by environment directory**:

```bash
hecate-agent hunt list --directory test
hecate-agent hunt list --directory production
```

**Multiple filters**:

```bash
hecate-agent hunt list --status completed --platform windows
hecate-agent hunt list --directory production --tactic credential-access
```

**JSON output** (for scripts/automation):

```bash
hecate-agent hunt list --output json
```

Output:
```json
[
  {
    "hunt_id": "H-0001",
    "title": "macOS Information Stealer Detection",
    "status": "completed",
    "techniques": ["T1005"],
    "tactics": ["collection"],
    "platforms": ["macos"],
    "true_positives": 1,
    "false_positives": 0
  }
]
```

**YAML output**:

```bash
hecate-agent hunt list --output yaml
```

### Exit Codes

- `0`: Success
- `1`: No hunts directory found (run `hecate-agent hunt new` to create one)

---

## hecate-agent hunt validate

Validate hunt file structure and metadata.

### Synopsis

```bash
hecate-agent hunt validate [HUNT_ID]
```

### Description

Validates hunt files against the Hecate format specification. Checks YAML frontmatter, required fields, LOCK sections, and ATT&CK technique format.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `HUNT_ID` | String (optional) | Specific hunt to validate (e.g., H-0001). If omitted, validates all hunts. |

### Examples

**Validate specific hunt**:

```bash
hecate-agent hunt validate H-0001
```

Output (success):
```
✓ Hunt H-0001 is valid
  - YAML frontmatter: OK
  - Required fields: OK
  - ATT&CK technique: OK
  - LOCK sections: OK
```

Output (errors):
```
✗ Hunt H-0023 has validation errors:
  - Missing required field: hunter
  - Invalid technique format: T1003 (expected: T1003.001)
  - Missing LOCK section: CHECK
```

**Validate all hunts**:

```bash
hecate-agent hunt validate
```

Output:
```
Validating 4 hunts...

✓ H-0001: Valid
✗ H-0002: 1 error
  - Missing required field: hunter
✓ H-0015: Valid
✓ H-0023: Valid

Summary: 3 valid, 1 invalid
```

### Validation Rules

**Required frontmatter fields**:
- `hunt_id`
- `title`
- `status`
- `date`
- `hunter`
- `techniques`

**ATT&CK technique format**:
- Pattern: `T1234.001` (technique + subtechnique)
- Must start with `T`
- Must be in techniques list

**LOCK sections**:
- All four sections must be present: LEARN, OBSERVE, CHECK, KEEP
- Sections must be Markdown H2 headers: `## LEARN`

**Status values**:
- Must be one of: `in-progress`, `completed`, `paused`, `archived`

### Exit Codes

- `0`: All hunts valid
- `1`: Validation errors found

---

## hecate-agent hunt stats

Display hunt statistics and success metrics.

### Synopsis

```bash
hecate-agent hunt stats [OPTIONS]
```

### Description

Calculate and display statistics about your hunts, including success rates, true positive/false positive ratios, and hunt velocity.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--trend` | Flag | False | Show a quarterly breakdown of hunt activity |
| `--save-context` | Flag | False | Append a hunt-program metrics block to `knowledge/environment.md` for agent context |

### Examples

**Overall statistics**:

```bash
hecate-agent hunt stats
```

Output:
```
Hunt Statistics
───────────────────────────────────────
Total Hunts:              23
Completed:                15 (65%)
In Progress:              5 (22%)
Paused:                   2 (9%)
Archived:                 1 (4%)

Success Metrics
───────────────────────────────────────
Hunts with Findings:      12 (80% of completed)
True Positives:           18
False Positives:          7
TP/FP Ratio:              2.6:1

Average per Hunt
───────────────────────────────────────
True Positives:           1.2
False Positives:          0.5
Time to Complete:         4.2 days

Coverage
───────────────────────────────────────
Unique Techniques:        15
Unique Tactics:           8
Platforms Covered:        4 (Windows, Linux, macOS, AWS)
```

**Quarterly breakdown**:

```bash
hecate-agent hunt stats --trend
```

**Write a metrics block into `knowledge/environment.md`** so agents pick the
figures up as context:

```bash
hecate-agent hunt stats --save-context
```

Output:
```json
{
  "total_hunts": 23,
  "completed": 15,
  "in_progress": 5,
  "success_rate": 0.80,
  "true_positives": 18,
  "false_positives": 7,
  "tp_fp_ratio": 2.6,
  "unique_techniques": 15,
  "unique_tactics": 8
}
```

### Exit Codes

- `0`: Success
- `1`: No hunts found

---

## hecate-agent hunt search

Full-text search across all hunts.

### Synopsis

```bash
hecate-agent hunt search QUERY [OPTIONS]
```

### Description

Search hunt content (including frontmatter, LOCK sections, queries, and findings) for a specific term or phrase.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `QUERY` | String | Search query (supports regex) |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--directory` | Choice | - | Filter by environment directory: `test`, `production` |

### Examples

**Simple search**:

```bash
hecate-agent hunt search kerberoasting
```

Output:
```
Found 3 matches:

H-0002: Kerberoasting Detection via Unusual TGS Requests
  Match in LEARN section:
    "...technique to detect kerberoasting attacks by identifying unusual..."

H-0015: Service Account Reconnaissance
  Match in OBSERVE section:
    "...similar patterns to kerberoasting but focuses on enumeration..."

H-0012: Golden Ticket Detection
  Match in title:
    "Kerberoasting and Golden Ticket Detection"
```

**Filter by environment directory**:

```bash
hecate-agent hunt search "credential" --directory test
hecate-agent hunt search "kerberoasting" --directory production
```

**Search for technique ID**:

```bash
hecate-agent hunt search "T1003.001"
```

**Restrict to test or production hunts**:

```bash
hecate-agent hunt search kerberoasting --directory production
```

Search is a plain case-insensitive substring match across hunt files; there is
no regex, case-sensitivity or output-format flag. For anything more selective,
use `grep -r` over `hunts/` directly.

Output:
```json
[
  {
    "hunt_id": "H-0002",
    "title": "Kerberoasting Detection",
    "matches": [
      {
        "section": "LEARN",
        "line": 15,
        "context": "...technique to detect kerberoasting attacks..."
      }
    ]
  }
]
```

### Exit Codes

- `0`: Matches found
- `1`: No matches found

---

## hecate-agent hunt coverage

Show MITRE ATT&CK technique coverage across hunts with visual progress bars.

### Synopsis

```bash
hecate-agent hunt coverage [OPTIONS]
```

### Description

Displays a comprehensive visual coverage heatmap of all 14 MITRE ATT&CK tactics, showing which techniques you've hunted and which represent blind spots. Uses progress bars to visualize coverage percentage per tactic.

**Features:**
- Visual progress bars for all 14 ATT&CK tactics
- Coverage percentages (X/Y techniques covered)
- Overall coverage statistic across the entire matrix
- Detailed view showing technique-to-hunt mapping

**Use Cases:**
- Identify blind spots in your hunting program
- Prioritize future hunt topics
- Demonstrate coverage to stakeholders
- Align hunting with threat intelligence priorities
- Balance hunt portfolio across tactics

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--tactic` | String | - | Filter by specific tactic (or 'all' for all tactics) |
| `--detailed` | Flag | False | Show detailed technique coverage with hunt references |
| `--output` | Choice | table | Output format: `table`, `json`, `yaml` |

### Examples

**Show coverage for all tactics (default):**

```bash
hecate-agent hunt coverage
```

**Show all tactics explicitly:**

```bash
hecate-agent hunt coverage --tactic all
```

**Filter by specific tactic:**

```bash
hecate-agent hunt coverage --tactic credential-access
```

**Output:**
```
MITRE ATT&CK Coverage
──────────────────────────────────────────────────────────────────────

Reconnaissance            ░░░░░░░░░░░░░░░░░░░░  0/10 techniques (0%)
Resource Development      ░░░░░░░░░░░░░░░░░░░░  0/7 techniques (0%)
Initial Access            ░░░░░░░░░░░░░░░░░░░░  0/9 techniques (0%)
Execution                 ░░░░░░░░░░░░░░░░░░░░  0/12 techniques (0%)
Persistence               ███████░░░░░░░░░░░░░  7/19 techniques (37%)
Privilege Escalation      ████░░░░░░░░░░░░░░░░  3/13 techniques (23%)
Defense Evasion           ░░░░░░░░░░░░░░░░░░░░  0/42 techniques (0%)
Credential Access         ░░░░░░░░░░░░░░░░░░░░  0/15 techniques (0%)
Discovery                 ░░░░░░░░░░░░░░░░░░░░  0/30 techniques (0%)
Lateral Movement          ░░░░░░░░░░░░░░░░░░░░  0/9 techniques (0%)
Collection                ███░░░░░░░░░░░░░░░░░  3/17 techniques (18%)
Command and Control       ░░░░░░░░░░░░░░░░░░░░  0/16 techniques (0%)
Exfiltration              ░░░░░░░░░░░░░░░░░░░░  0/9 techniques (0%)
Impact                    ░░░░░░░░░░░░░░░░░░░░  0/13 techniques (0%)

Overall: 10/221 techniques (5%)
```

**Show detailed technique breakdown (all tactics):**

```bash
hecate-agent hunt coverage --detailed
```

**Filter by tactic with detailed view:**

```bash
hecate-agent hunt coverage --tactic persistence --detailed
```

**Detailed Output:**
```
MITRE ATT&CK Coverage - Persistence
────────────────────────────────────────────────────────────

Persistence              2 hunts, 7 techniques

🔍 Detailed Technique Coverage

Persistence (2 hunts, 7 unique techniques)
  • T1027 - H-0002
  • T1053.003 - H-0002
  • T1059.004 - H-0002
  • T1071.001 - H-0002
  • T1078.004 - H-0003
  • T1098 - H-0003
  • T1546.004 - H-0003
```

**Valid tactic names:**
- `reconnaissance`, `resource-development`, `initial-access`, `execution`
- `persistence`, `privilege-escalation`, `defense-evasion`, `credential-access`
- `discovery`, `lateral-movement`, `collection`, `command-and-control`
- `exfiltration`, `impact`

### Progress Bar Legend

- `█` = Covered technique
- `░` = Uncovered technique (blind spot)

### Exit Codes

- `0`: Success
- `1`: No hunts found

---

## hecate-agent hunt new-baseline

Create a baseline (EDA) hunt — PEAK's hypothesis-free hunt type.

### Synopsis

```bash
hecate-agent hunt new-baseline [OPTIONS]
```

### Description

A baseline hunt has no hypothesis. Instead of testing a claim, it characterizes
what "normal" looks like for one dimension — a field, a behavior pattern — so
that candidate anomalies can be identified and spun out into hypothesis-driven
follow-up hunts later.

It shares the `H-XXXX` ID sequence and LOCK section headings with every other
hunt type, so `hunt list`, `hunt validate`, `hunt export` and `hunt brief` all
work on it unchanged. Filter to just these with `hunt list --type baseline`.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--title` | String | prompted | Baseline hunt title |
| `--dimension` | String | prompted | Field or behavior being characterized |
| `--platform` | String | — | Target platforms (repeatable) |
| `--data-source` | String | — | Data sources (repeatable) |
| `--objective` | String | — | Why this baseline matters |
| `--hunter` | String | config, then `Analyst` | Hunter name |
| `--test` | Flag | False | Create under `hunts/test/` |
| `--non-interactive` | Flag | False | Skip interactive prompts |

### Examples

```bash
hecate-agent hunt new-baseline --title "Parent-Child Process Baseline" \
    --dimension "parent_process -> child_process pairs" \
    --platform Windows --data-source EDR --non-interactive
```

### Workflow after creation

1. Run frequency, cardinality and rarity queries; document what is normal.
2. Record candidate anomalies in the KEEP section.
3. For anomalies worth pursuing, run `hecate-agent hunt new`, set its
   `spawned_from` to this baseline's ID, and add the new hunt's ID to this
   baseline's `related_hunts`.

### Exit Codes

- `0`: Hunt created

---

## hecate-agent hunt new-model-assisted

Create a model-assisted (M-ATH) hunt — PEAK's third Execute-phase hunt type.

### Synopsis

```bash
hecate-agent hunt new-model-assisted [OPTIONS]
```

### Description

Where a baseline hunt characterizes normal by hand, a model-assisted hunt runs a
statistical or ML model (clustering, z-score, IQR, isolation forest) over
telemetry to surface anomalies at scale — for when data volume makes manual EDA
impractical. Anomalies it surfaces become leads for hypothesis-driven follow-ups.

Uses the same `H-XXXX` sequence and LOCK headings as other hunt types; filter
with `hunt list --type model-assisted`.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--title` | String | prompted | Hunt title |
| `--model-type` | String | prompted | `clustering`, `z-score`, `IQR`, `isolation-forest`, `other` |
| `--features` | String | — | Comma-separated fields fed into the model |
| `--anomaly-threshold` | String | — | Anomaly score cutoff |
| `--dataset` | String | — | Table, index or data source being modeled |
| `--platform` | String | — | Target platforms (repeatable) |
| `--data-source` | String | — | Data sources (repeatable) |
| `--objective` | String | — | Why model-assisted rather than manual EDA |
| `--hunter` | String | config, then `Analyst` | Hunter name |
| `--test` | Flag | False | Create under `hunts/test/` |
| `--non-interactive` | Flag | False | Skip interactive prompts |

### Examples

```bash
hecate-agent hunt new-model-assisted --title "Process Execution Clustering" \
    --model-type clustering \
    --features "process.name,parent.process.name,user.name" \
    --dataset "endpoint_events" --platform Windows --data-source EDR \
    --non-interactive
```

### Exit Codes

- `0`: Hunt created

---

## hecate-agent hunt update

Patch YAML frontmatter fields in a hunt file in place.

### Synopsis

```bash
hecate-agent hunt update HUNT_ID [OPTIONS]
```

### Description

Updates frontmatter without touching the markdown body. This is the sanctioned
way to change a hunt's status or record its findings — hand-editing frontmatter
is what the CLI-first rule in `AGENTS.md` exists to prevent.

Technique IDs passed with `--technique` are validated against the ATT&CK matrix.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `HUNT_ID` | String | Hunt ID (e.g., H-0042) |

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--status` | String | `planning`, `active`, `in_review`, `completed`, `archived` |
| `--title` | String | Update hunt title |
| `--hunter` | String | Update hunter name |
| `--assignee` | String | Assign to a team member |
| `--reviewer` | String | Set the reviewer |
| `--true-positives` | Integer | Set true positive count |
| `--false-positives` | Integer | Set false positive count |
| `--findings-count` | Integer | Set findings count |
| `--add-tag` | String | Add tag(s) (repeatable) |
| `--remove-tag` | String | Remove tag(s) (repeatable) |
| `--technique` | String | Set technique ID(s), **replacing** any existing (repeatable) |
| `--tactic` | String | Set tactic(s), **replacing** any existing (repeatable) |
| `--platform` | String | Set platform(s), **replacing** any existing (repeatable) |

Note that `--technique`, `--tactic` and `--platform` replace rather than append,
unlike `--add-tag`.

### Examples

```bash
# Mark a hunt completed
hecate-agent hunt update H-0042 --status completed

# Record findings
hecate-agent hunt update H-0042 --true-positives 3 --false-positives 1

# Add tags
hecate-agent hunt update H-0042 --add-tag lateral-movement --add-tag rdp

# Correct an ATT&CK mapping (IDs are checked against the matrix)
hecate-agent hunt update H-0042 --technique T1219 --technique T1071 \
    --tactic command-and-control

# Fill in a platform an auto-generated draft left empty
hecate-agent hunt update H-0042 --platform Windows
```

### Exit Codes

- `0`: Always — including when the hunt is not found or a technique ID fails
  validation. Both print an `Error:` line to stdout but do not set a non-zero
  status, so a script must check the output rather than the exit code.

---

## hecate-agent hunt promote

Promote a hunt from test to production.

### Synopsis

```bash
hecate-agent hunt promote HUNT_ID [OPTIONS]
```

### Description

Moves a hunt file out of `hunts/test/{YYYY}/{QX}/` into the production directory
`hunts/{YYYY}/{QX}/`, preserving the hunt ID — there is no renumbering.

The destination year and quarter come from **today's date, not the hunt's
original ones**, so a hunt created in Q1 and promoted in Q3 lands under `Q3`.
The command refuses rather than overwrites if the destination file already
exists.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `HUNT_ID` | String | Hunt ID (e.g., H-0042) |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-y`, `--yes` | Flag | False | Skip the confirmation prompt |

### Examples

```bash
# Promote a test hunt, with confirmation
hecate-agent hunt promote H-0042

# Skip the prompt
hecate-agent hunt promote H-0042 --yes
```

### Exit Codes

- `0`: Promoted, cancelled at the prompt, or refused because the destination exists

---

## hecate-agent hunt operationalize

Generate a Sigma detection rule stub from a completed hunt.

### Synopsis

```bash
hecate-agent hunt operationalize HUNT_ID [OPTIONS]
```

### Description

Extracts the hunt's query from its CHECK section and writes a Sigma YAML stub to
`detections/<hunt_id>.yml`.

This is a stub, not a finished rule: the original detection logic is preserved as
a comment and the `detection.selection` block is a placeholder. A hunter
translates it into real Sigma field conditions. Unless `--no-patch` is given, the
hunt's frontmatter is updated with the `detection_rule` path.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `HUNT_ID` | String | Hunt ID (e.g., H-0042) |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--query-index` | Integer | prompted | 1-based index of the query to use when the hunt has several |
| `--output` | Path | `detections/<hunt_id>.yml` | Sigma rule output path |
| `--no-patch` | Flag | False | Leave the hunt frontmatter's `detection_rule` alone |

### Examples

```bash
# Interactive — pick a query when several are found
hecate-agent hunt operationalize H-0042

# Non-interactive — take the first query
hecate-agent hunt operationalize H-0042 --query-index 1

# Custom output path
hecate-agent hunt operationalize H-0042 --output sigma/lsass-dump.yml
```

### Workflow after generation

1. Open `detections/<hunt_id>.yml`.
2. Replace the placeholder `detection.selection` block with real conditions.
3. Validate with `sigma check detections/<hunt_id>.yml`.

### Exit Codes

- `0`: Always — including when the hunt is not found or no query could be
  extracted from the CHECK section. As with `hunt update`, failures are printed
  rather than signalled through the exit status.

---

## hecate-agent hunt brief

Render a condensed, stakeholder-facing summary of a hunt.

### Synopsis

```bash
hecate-agent hunt brief HUNT_ID [OPTIONS]
```

### Description

The PEAK framework's "Brief" step. Emits the hypothesis, executive summary,
findings and detection/automation outcome — deliberately omitting the
query-iteration detail and lessons-learned notes, which are written for the
hunter rather than the audience.

Writes to stdout unless `--output` is given.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `HUNT_ID` | String | Hunt ID (e.g., H-0027) |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--output` | Path | stdout | Write the brief to a file |

### Examples

```bash
hecate-agent hunt brief H-0027
hecate-agent hunt brief H-0027 --output brief-0027.md
```

### Exit Codes

- `0`: Brief rendered
- `1`: Hunt not found

---

## hecate-agent hunt export

Export hunt data as structured JSON.

### Synopsis

```bash
hecate-agent hunt export [HUNT_ID] [OPTIONS]
```

### Description

Exports frontmatter, LOCK sections and associated session data (decisions,
findings, queries) as JSON — for feeding dashboards, analytics pipelines, graph
databases, or archival in a machine-readable form.

Pass a `HUNT_ID` for one hunt, or `--all` for the whole program.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `HUNT_ID` | String | Hunt ID to export (omit when using `--all`) |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--all` | Flag | False | Export every hunt |
| `--output` | Path | stdout | Write to a file |
| `--include-content` | Flag | False | Include the raw markdown body |
| `--no-sessions` | Flag | False | Exclude session data |
| `--status` | String | — | Filter by status when using `--all` |

### Examples

```bash
# One hunt, to stdout
hecate-agent hunt export H-0027

# Everything
hecate-agent hunt export --all

# To a file, with the raw markdown included
hecate-agent hunt export H-0027 --include-content --output hunt-0027.json

# Only completed hunts
hecate-agent hunt export --all --status completed
```

### Exit Codes

- `0`: Export written
- `1`: Hunt not found

---

## hecate-agent investigate new

Create a new investigation file for exploratory work and ad-hoc analysis.

### Synopsis

```bash
hecate-agent investigate new [OPTIONS]
```

### Description

Creates investigation files for work that should NOT be tracked in hunt metrics. Investigations are perfect for alert triage, data source baselining, query sandboxing, and exploratory analysis. Investigations use a flexible LOCK structure and can be promoted to formal hunts if they prove valuable.

**When to use investigations:**
- Alert triage and finding investigation
- Baseline new data sources
- Explore query logic before formal hunt
- Ad-hoc analysis without metrics pollution
- Sandbox work for uncertain hypotheses

**Key differences from hunts:**
- NOT tracked in metrics (no TP/FP counts)
- Flexible LOCK structure (sections optional)
- Lightweight validation
- Can be promoted to formal hunts

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--title` | String | Required* | Investigation title |
| `--type` | Choice | exploratory | Type: `finding`, `baseline`, `exploratory`, `other` |
| `--tags` | String | - | Comma-separated tags (e.g., alert-triage,powershell) |
| `--data-source` | String | - | Data sources (can specify multiple with multiple flags) |
| `--related-hunt` | String | - | Related hunt IDs (can specify multiple with multiple flags) |
| `--investigator` | String | Hecate | Investigator name |
| `--non-interactive` | Flag | False | Skip interactive prompts |

\* Required in non-interactive mode

### Examples

**Interactive mode** (recommended):

```bash
hecate-agent investigate new
```

**Non-interactive with all options:**

```bash
hecate-agent investigate new \
  --title "Alert Triage - PowerShell Execution" \
  --type finding \
  --tags alert-triage,powershell,customer-x \
  --data-source "EDR Telemetry" \
  --data-source "ClickHouse" \
  --related-hunt H-0013 \
  --investigator "Jane Doe" \
  --non-interactive
```

**Create baseline investigation:**

```bash
hecate-agent investigate new \
  --title "Baseline AWS CloudTrail Events" \
  --type baseline \
  --tags baseline,cloudtrail,aws \
  --data-source "CloudTrail" \
  --non-interactive
```

**Create exploratory investigation:**

```bash
hecate-agent investigate new \
  --title "Credential Access Pattern Exploration" \
  --type exploratory \
  --tags sandbox,credential-access \
  --non-interactive
```

### Output

```
🔍 Creating new investigation

Investigation ID: I-0001

✅ Created I-0001: Alert Triage - PowerShell Execution

Next steps:
  1. Edit investigations/I-0001.md to document your investigation
  2. Use LOCK pattern sections (optional/flexible)
  3. View all investigations: hecate-agent investigate list
  4. Promote to hunt if valuable: hecate-agent investigate promote I-0001
```

### Generated File Structure

```yaml
---
investigation_id: I-0001
title: "Alert Triage - PowerShell Execution"
date: 2025-12-17
investigator: "Jane Doe"
type: finding
related_hunts:
  - H-0013
data_sources:
  - EDR Telemetry
  - ClickHouse
tags:
  - alert-triage
  - powershell
  - customer-x
---

# I-0001: Alert Triage - PowerShell Execution

...LOCK sections (optional)...
```

### Exit Codes

- `0`: Success
- `1`: Missing required options (non-interactive mode)

---

## hecate-agent investigate list

List all investigations with optional filtering.

### Synopsis

```bash
hecate-agent investigate list [OPTIONS]
```

### Description

Display all investigations in a formatted table. Supports filtering by type, tags, and multiple output formats.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--type` | Choice | - | Filter by type: `finding`, `baseline`, `exploratory`, `other` |
| `--tags` | String | - | Filter by tags (comma-separated) |
| `--output` | Choice | table | Output format: `table`, `json`, `yaml` |

### Examples

**List all investigations:**

```bash
hecate-agent investigate list
```

Output:
```
                    Investigations
╭──────┬─────────────────┬─────────────┬──────────────┬────────────╮
│ ID   │ Title           │ Type        │ Tags         │ Date       │
├──────┼─────────────────┼─────────────┼──────────────┼────────────┤
│ I-01 │ Alert Triage    │ finding     │ alert-triage │ 2025-12-17 │
│ I-02 │ CloudTrail      │ baseline    │ baseline,aws │ 2025-12-17 │
│      │ Baseline        │             │              │            │
│ I-03 │ Credential      │ exploratory │ sandbox      │ 2025-12-17 │
│      │ Patterns        │             │              │            │
╰──────┴─────────────────┴─────────────┴──────────────┴────────────╯

Total: 3 investigations
```

**Filter by type:**

```bash
hecate-agent investigate list --type finding
```

**Filter by tags:**

```bash
hecate-agent investigate list --tags alert-triage
```

**JSON output:**

```bash
hecate-agent investigate list --output json
```

Output:
```json
[
  {
    "file_path": "investigations/I-0001.md",
    "investigation_id": "I-0001",
    "frontmatter": {
      "investigation_id": "I-0001",
      "title": "Alert Triage - PowerShell Execution",
      "date": "2025-12-17",
      "type": "finding",
      "tags": ["alert-triage", "powershell"]
    }
  }
]
```

### Exit Codes

- `0`: Success
- `1`: No investigations directory found

---

## hecate-agent investigate search

Full-text search across all investigation files.

### Synopsis

```bash
hecate-agent investigate search QUERY
```

### Description

Performs full-text search across all investigation files, including frontmatter, LOCK sections, and findings.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `QUERY` | String | Search query (case-insensitive) |

### Examples

**Search for PowerShell:**

```bash
hecate-agent investigate search "PowerShell"
```

Output:
```
Found 2 investigation(s) matching "PowerShell":

I-0001: Alert Triage - PowerShell Execution
  investigations/I-0001.md

I-0005: Process Execution Baseline
  investigations/I-0005.md
```

**Search for customer-specific findings:**

```bash
hecate-agent investigate search "customer-x"
```

**Search for baseline work:**

```bash
hecate-agent investigate search "baseline CloudTrail"
```

### Exit Codes

- `0`: Matches found
- `1`: No matches found

---

## hecate-agent investigate validate

Validate investigation file structure.

### Synopsis

```bash
hecate-agent investigate validate INVESTIGATION_ID
```

### Description

Validates investigation files against the Hecate format specification. Uses lightweight validation checking only minimal required fields. Does NOT validate LOCK sections (which are optional/flexible for investigations) or findings counts.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `INVESTIGATION_ID` | String | Investigation to validate (e.g., I-0001) |

### Examples

**Validate specific investigation:**

```bash
hecate-agent investigate validate I-0001
```

Output (success):
```
✅ I-0001 is valid
```

Output (errors):
```
❌ I-0001 has validation errors:
  • Missing required frontmatter field: title
  • Invalid investigation_id format: I-001 (expected format: I-0001)
```

### Validation Rules

**Required frontmatter fields** (minimal):
- `investigation_id`
- `title`
- `date`

**Investigation ID format:**
- Pattern: `I-0001` (I- prefix + 4 digits)
- Must match filename

**Type values** (if present):
- Must be one of: `finding`, `baseline`, `exploratory`, `other`

**Note:** Unlike hunt validation, investigation validation is lightweight and does NOT check:
- LOCK section structure (sections are optional/flexible)
- Findings counts (investigations not tracked in metrics)
- Tactics/techniques (optional metadata)

### Exit Codes

- `0`: Investigation valid
- `1`: Validation errors found

---

## hecate-agent investigate promote

Promote investigation to formal hunt with hunt-required metadata.

### Synopsis

```bash
hecate-agent investigate promote INVESTIGATION_ID [OPTIONS]
```

### Description

Converts an investigation to a formal hunt, adding hunt-required metadata (tactics, techniques, platform) and enabling metrics tracking. The investigation file remains in the investigations directory, and both files cross-reference each other.

**What promotion does:**
1. Creates new hunt file (H-XXXX.md) in hunts/ directory
2. Copies investigation content to hunt file
3. Adds required hunt metadata (tactics, techniques, platform)
4. Adds hunt tracking fields (findings_count, true_positives, false_positives)
5. Creates bidirectional references:
   - Hunt includes `spawned_from: I-XXXX`
   - Investigation updated with promotion note

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `INVESTIGATION_ID` | String | Investigation to promote (e.g., I-0001) |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--technique` | String | Required* | MITRE ATT&CK technique (e.g., T1003.001) |
| `--tactic` | String | - | MITRE tactics (can specify multiple with multiple flags) |
| `--platform` | String | - | Target platforms (can specify multiple with multiple flags) |
| `--status` | Choice | in-progress | Hunt status: `planning`, `in-progress`, `completed`, `archived` |
| `--non-interactive` | Flag | False | Skip interactive prompts |

\* Required in non-interactive mode

### Examples

**Interactive promotion** (prompts for details):

```bash
hecate-agent investigate promote I-0042
```

**Non-interactive with all options:**

```bash
hecate-agent investigate promote I-0042 \
  --technique T1059.001 \
  --tactic execution \
  --tactic defense-evasion \
  --platform Windows \
  --status in-progress \
  --non-interactive
```

### Output

```
🔄 Promoting investigation to hunt

Investigation: I-0042 - PowerShell Execution Analysis

Hunt ID: H-0023

✅ Promoted I-0042 to H-0023
Updated investigations/I-0042.md with promotion note

Next steps:
  1. Edit hunts/H-0023.md to refine hunt hypothesis
  2. Add MITRE ATT&CK coverage if needed
  3. Validate hunt: hecate-agent hunt validate H-0023
  4. View hunt: hecate-agent hunt list --status in-progress
```

### After Promotion

- **Hunt file created:** hunts/H-0023.md (tracked in metrics)
- **Investigation updated:** investigations/I-0042.md (promotion note added)
- **Investigation remains:** Still NOT tracked in metrics
- **Cross-references:** Both files link to each other

### Exit Codes

- `0`: Success
- `1`: Investigation not found or parsing error
- `2`: Missing required options (non-interactive mode)

---

## hecate-agent agent list

List the agents available in this installation.

### Synopsis

```bash
hecate-agent agent list
```

### Description

Shows each agent's name, type, availability and description. All four agents are
LLM-backed and resolve their provider through the layered configuration
described under [Configuration](#configuration); `hunt-researcher` and
`pivot-suggester` additionally have heuristic fallbacks that run without an LLM.

| Agent | Purpose |
|-------|---------|
| `hypothesis-generator` | Generates hunt hypotheses from threat intelligence |
| `hunt-researcher` | Conducts pre-hunt research using the 5-skill methodology |
| `sigma-generator` | Drafts portable Sigma rules for a hunt, before operator review |
| `pivot-suggester` | Suggests next pivot queries given a suspicious finding |

### Examples

```bash
hecate-agent agent list
```

### Exit Codes

- `0`: Success

---

## hecate-agent agent info

Show detailed information about one agent.

### Synopsis

```bash
hecate-agent agent info AGENT_NAME
```

### Description

Prints the agent's type, availability, description, capabilities and worked
usage examples.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `AGENT_NAME` | String | One of the agents from `hecate-agent agent list` |

### Examples

```bash
hecate-agent agent info hypothesis-generator
hecate-agent agent info pivot-suggester
```

**Output:**
```
Agent: pivot-suggester
Type: LLM (auto-detect)
Status: available

Description:
  Suggests next pivot queries given a suspicious finding

Capabilities:
  • Finding characterisation and ATT&CK technique mapping
  • 3-5 prioritised, actionable next pivot queries
  • Rationale grounded in adversary behaviour patterns
  • Past hunt cross-reference via full-text search
  • Environment context from knowledge/environment.md
  • Heuristic fallback mode (no LLM required)
  • Multi-provider support (Claude, GPT, Gemini, Ollama)
```

### Exit Codes

- `0`: Success

---

## hecate-agent agent run

Run one agent directly.

### Synopsis

```bash
hecate-agent agent run AGENT_NAME [OPTIONS]
```

### Description

Runs a single agent with the inputs it needs. Every option below lives on
`agent run` itself — which ones apply depends on the agent, as noted in the
table.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `AGENT_NAME` | String | Agent to run (see `hecate-agent agent list`) |

### Options

| Option | Type | Default | Applies to | Description |
|--------|------|---------|-----------|-------------|
| `--threat-intel` | String | - | hypothesis-generator | Threat intelligence context |
| `--indicators-only` | Flag | False | hypothesis-generator | Threat intel is a bare indicator list with no narrative (a ThreatFox/Maltrail dump); keeps the hypothesis to indicator presence instead of inferring delivery, actor or technique |
| `--topic` | String | - | hunt-researcher | Research topic |
| `--depth` | Choice | basic | hunt-researcher | `basic` (~5 min) or `advanced` (~15-20 min) |
| `--no-web-search` | Flag | False | hunt-researcher | Offline mode — skip web search |
| `--technique` | String | - | hunt-researcher, pivot-suggester | MITRE ATT&CK technique |
| `--finding` | String | - | pivot-suggester | Suspicious finding, as JSON or plain text |
| `--hunt` | String | - | pivot-suggester | Current hunt ID, for context |
| `--input-json` | File | - | sigma-generator | JSON file of `SigmaGenerationInput` fields (hypothesis, techniques, indicators, indicator_records, detection_guidance, platforms, references) — a file rather than a dozen flags, since the indicator map is nested and can be long |
| `--out-dir` | Directory | - | sigma-generator | Where to write generated `.yml` rules |
| `--research` | String | - | any | Research document ID to load context from |
| `--tactic` | String | - | any | MITRE tactic filter |
| `--llm` / `--no-llm` | Flag | `--llm` | any | Enable or disable the LLM; the no-LLM path uses heuristic fallbacks |
| `--output-format` | Choice | table | any | `table` or `json` |

Note the flag is `--output-format`, not `--output` as elsewhere in the CLI.

### Examples

**Generate a hypothesis from threat intel:**

```bash
hecate-agent agent run hypothesis-generator \
  --threat-intel "APT29 using WMI for lateral movement and persistence" \
  --technique T1047
```

**Generate a hypothesis from a bare indicator dump:**

```bash
hecate-agent agent run hypothesis-generator \
  --threat-intel "$(cat threatfox-dump.txt)" \
  --indicators-only
```

**Run pre-hunt research:**

```bash
hecate-agent agent run hunt-researcher \
  --topic "LSASS dumping" --technique T1003.001 --depth advanced
```

**Suggest pivots from a finding:**

```bash
hecate-agent agent run pivot-suggester \
  --finding '{"process": "powershell.exe", "parent": "winword.exe"}'

hecate-agent agent run pivot-suggester \
  --finding "suspicious outbound DNS to rare domain" --hunt H-0042
```

**Draft Sigma rules:**

```bash
hecate-agent agent run sigma-generator \
  --input-json sigma-input.json --out-dir queries/H-0042
```

### Exit Codes

- `0`: Success
- `1`: Agent execution failed
- `2`: Invalid arguments

---

## hecate-agent research new

Create new research document with web search and LLM analysis.

### Synopsis

```bash
hecate-agent research new [OPTIONS]
```

### Description

Conducts deep pre-hunt research using a 5-skill methodology: System Internals, Adversary Tradecraft, Telemetry Mapping, Historical Analysis, and Environmental Factors. Uses web search (Tavily API) and LLM analysis (auto-detected provider: Claude, GPT, Gemini, Ollama, etc.) to generate comprehensive research documents.

**Research Depth:**
- **Advanced** (default): 15-20 minutes, thorough 5-skill methodology
- **Basic**: 5 minutes, rapid research for urgent hunts

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--topic` | String | Required | Research topic (e.g., "LSASS dumping", "Pass-the-Hash") |
| `--technique` | String | - | MITRE ATT&CK technique (e.g., T1003.001) |
| `--depth` | Choice | advanced | Research depth: `basic` (~5 min), `advanced` (~15-20 min) |
| `--no-web-search` | Flag | False | Skip web search (offline mode) |
| `--output` | Choice | table | Output format: `table`, `json` |

### Examples

**Deep research (default):**

```bash
hecate-agent research new --topic "LSASS dumping" --technique T1003.001
```

**Quick research for urgent hunts:**

```bash
hecate-agent research new --topic "Pass-the-Hash" --depth basic
```

**Research without technique mapping:**

```bash
hecate-agent research new --topic "Cloud IAM enumeration"
```

### Output

```
🔬 Starting research: LSASS dumping

Research ID: R-0003

⏳ Conducting research (this may take 15-20 minutes)...

✅ Research complete!

Created: research/R-0003.md

Next steps:
  1. Review research/R-0003.md
  2. Create hunt: hecate-agent hunt new --research R-0003
  3. Link to hunt in frontmatter
```

### Generated File Structure

```yaml
---
research_id: R-0003
title: "LSASS Dumping Research"
topic: "LSASS dumping"
technique: T1003.001
depth: advanced
date: 2026-01-13
status: completed
---

# R-0003: LSASS Dumping Research

## Executive Summary
...

## System Internals
...

## Adversary Tradecraft
...

## Telemetry Mapping
...

## Historical Analysis
...

## Environmental Factors
...

## Recommendations
...
```

### Requirements

**Optional but Recommended:**
- `TAVILY_API_KEY`: Web search for adversary tradecraft (get from <https://tavily.com>)
- **LLM Provider** (any one of the following):
  - `ANTHROPIC_API_KEY`: Anthropic API directly
  - `OPENAI_API_KEY`: OpenAI or compatible endpoint
  - `AWS_PROFILE` or `AWS_ACCESS_KEY_ID`: AWS Bedrock
  - `OLLAMA_HOST`: Local Ollama instance
  - Override with `HECATE_LLM_PROVIDER` and `HECATE_LLM_MODEL` (see `.env.example`)
  - Without LLM: Falls back to template-based research
  - With LLM: Enhanced analysis using your configured model

### Exit Codes

- `0`: Success
- `1`: Research failed
- `2`: Missing required options

---

## hecate-agent research list

List all research documents.

### Synopsis

```bash
hecate-agent research list [OPTIONS]
```

### Description

Displays all research documents with filtering options.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--status` | String | - | Filter by status: `draft`, `in_progress`, `completed` |
| `--technique` | String | - | Filter by MITRE technique |
| `--output` | Choice | table | Output format: `table`, `json` |

### Examples

```bash
# List all research
hecate-agent research list

# Filter by status
hecate-agent research list --status completed

# JSON output
hecate-agent research list --output json
```

### Exit Codes

- `0`: Success

---

## hecate-agent research view

View research document content.

### Synopsis

```bash
hecate-agent research view RESEARCH_ID
```

### Description

Displays the full content of a research document.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `RESEARCH_ID` | String | Research ID (e.g., R-0001) |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--output` | Choice | markdown | Output format: `markdown`, `json` |

### Examples

```bash
hecate-agent research view R-0001
```

### Exit Codes

- `0`: Success
- `1`: Research not found

---

## hecate-agent attack update

Download or refresh MITRE ATT&CK STIX data for enhanced technique metadata.

### Synopsis

```bash
hecate-agent attack update [OPTIONS]
```

### Description

Downloads the Enterprise ATT&CK STIX bundle from the official MITRE repository and caches it locally. Once downloaded, Hecate automatically switches from the hardcoded fallback data (14 tactics, approximate counts) to live STIX data (835+ techniques with full metadata including platforms, data sources, and sub-techniques).

**Prerequisites:** Requires `mitreattack-python` — install with `pip install -e ".[attack]"`.

**Cache locations (checked in order):**
1. `HECATE_STIX_CACHE` environment variable
2. `{workspace}/.hecate/stix-data/` if `.hecateconfig.yaml` exists in cwd
3. `~/.hecate/stix-data/` (global default)

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--force` | Flag | False | Re-download even if cache already exists |

### Examples

```bash
# Download STIX data (first time)
hecate-agent attack update

# Force re-download to get latest version
hecate-agent attack update --force
```

### Exit Codes

- `0`: Success
- `1`: mitreattack-python not installed or download failed

---

## hecate-agent attack status

Show ATT&CK data provider status and cache information.

### Synopsis

```bash
hecate-agent attack status
```

### Description

Displays the active data provider (STIX or fallback), ATT&CK version, tactic count, cache file location, size, and age. Useful for verifying that STIX data is loaded and current.

### Examples

```bash
hecate-agent attack status
```

**Output (with STIX):**
```
ATT&CK Data Status

  Provider:  STIX (mitreattack-python)
  Version:   v16.1 (STIX)
  Tactics:   14
  Cache:     /Users/you/.hecate/stix-data/enterprise-attack.json
  Size:      12.3 MB
  Age:       3 days
  Library:   mitreattack-python installed
```

**Output (fallback):**
```
ATT&CK Data Status

  Provider:  Fallback (hardcoded v14)
  Version:   v14 (hardcoded fallback)
  Tactics:   14
  Cache:     Not found (/Users/you/.hecate/stix-data/enterprise-attack.json)
  Library:   mitreattack-python not installed
```

### Exit Codes

- `0`: Success

---

## hecate-agent attack lookup

Look up an ATT&CK technique by its ID and display metadata.

### Synopsis

```bash
hecate-agent attack lookup TECHNIQUE_ID
```

### Description

Shows technique metadata including name, platforms, data sources, tactics, type (technique vs sub-technique), parent technique, description, and sub-techniques. Requires STIX data — run `hecate-agent attack update` first.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `TECHNIQUE_ID` | String | ATT&CK technique ID (e.g., T1003, T1003.001) |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--json` | Flag | False | Print technique metadata as JSON instead of a formatted table |

### Examples

```bash
# Look up a parent technique
hecate-agent attack lookup T1003

# Look up a sub-technique
hecate-agent attack lookup T1003.001
```

**Output:**
```
T1003.001 - LSASS Memory

  URL:           https://attack.mitre.org/techniques/T1003/001
  Platforms:     Windows
  Tactics:       credential-access
  Data Sources:  Process: OS API Execution, Process: Process Access, ...
  Type:          Sub-technique
  Parent:        T1003

  Adversaries may attempt to access credential material stored in ...
```

### Exit Codes

- `0`: Success (or technique not found with message)

---

## hecate-agent attack techniques

List all techniques mapped to a specific ATT&CK tactic.

### Synopsis

```bash
hecate-agent attack techniques TACTIC_KEY
```

### Description

Displays a table of all techniques (including sub-techniques) for the given tactic, showing ID, name, sub-technique status, and platforms. Requires STIX data — run `hecate-agent attack update` first.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `TACTIC_KEY` | String | Tactic shortname (e.g., credential-access, lateral-movement) |

### Examples

```bash
# List credential access techniques
hecate-agent attack techniques credential-access

# List lateral movement techniques
hecate-agent attack techniques lateral-movement
```

**Output:**
```
Credential Access (17 techniques)

┌──────────────┬──────────────────────────────┬──────┬───────────────────┐
│ ID           │ Name                         │ Sub? │ Platforms         │
├──────────────┼──────────────────────────────┼──────┼───────────────────┤
│ T1003        │ OS Credential Dumping        │      │ Windows, Linux... │
│ T1003.001    │ LSASS Memory                 │ Yes  │ Windows           │
│ T1003.002    │ Security Account Manager     │ Yes  │ Windows           │
│ ...          │ ...                          │ ...  │ ...               │
└──────────────┴──────────────────────────────┴──────┴───────────────────┘
```

**Valid tactic names:**
- `reconnaissance`, `resource-development`, `initial-access`, `execution`
- `persistence`, `privilege-escalation`, `defense-evasion`, `credential-access`
- `discovery`, `lateral-movement`, `collection`, `command-and-control`
- `exfiltration`, `impact`

### Exit Codes

- `0`: Success (or no techniques found with message)

---

## hecate-agent research link

Link a hunt to its source research document.

### Synopsis

```bash
hecate-agent research link RESEARCH_ID --hunt HUNT_ID
```

### Description

`hecate-agent hunt new --research R-XXXX` already creates this link. This exposes
the same operation on its own, for a caller that generated the hunt itself and
still owes the research document its back-link.

Without it the link is one-directional: the hunt names the document in
`spawned_from`, but the document still reports `linked_hunts: []`.

The operation is idempotent — linking an already-linked hunt succeeds and
changes nothing.

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `RESEARCH_ID` | String | Research document ID (e.g., R-0001) |

### Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `--hunt` | String | Yes | Hunt ID to link (e.g., H-0612) |

### Examples

```bash
hecate-agent research link R-0611 --hunt H-0612
```

### Exit Codes

- `0`: Linked, or already linked
- `1`: Research document or hunt not found

---

## hecate-agent research search

Full-text search across research documents.

### Synopsis

```bash
hecate-agent research search QUERY [OPTIONS]
```

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `QUERY` | String | Search term |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--output` | Choice | table | `table` or `json` |

### Examples

```bash
hecate-agent research search "kerberoasting"
hecate-agent research search "infostealer" --output json
```

### Exit Codes

- `0`: Success, including when nothing matches

---

## hecate-agent research stats

Show research program statistics.

### Synopsis

```bash
hecate-agent research stats [OPTIONS]
```

### Description

Totals across all research documents: how many exist, how many are complete,
accumulated LLM cost, and total, average and linked-hunt figures.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--output` | Choice | table | `table` or `json` |

### Examples

```bash
hecate-agent research stats
```

**Output:**
```
Research Program Statistics
Total Research: 42
Completed: 38
Total Cost: $1.8400
Total Duration: 612 min
Avg Duration: 14.6 min
Linked Hunts: 31
```

### Exit Codes

- `0`: Success

---

## hecate-agent attack gap

Show ATT&CK techniques not yet covered by any hunt.

### Synopsis

```bash
hecate-agent attack gap [OPTIONS]
```

### Description

The inverse of `hecate-agent hunt coverage`: instead of what you have hunted,
this lists what you have not. Requires STIX data — run `hecate-agent attack
update` first.

With `--generate` it goes a step further and drafts hunt files for the uncovered
techniques via the hypothesis-generator agent. That makes one LLM call per
technique, which is why `--limit` defaults to 5.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--tactic` | String | all | Limit to one tactic (e.g., `credential-access`) |
| `--platform` | String | all | Only techniques for this platform |
| `--no-subtechniques` | Flag | False | Exclude sub-techniques |
| `--output` | Choice | table | `table` or `json` |
| `--generate` | Flag | False | Draft hunt files for uncovered techniques |
| `--limit` | Integer | 5 | Max hunt files to generate with `--generate` |

### Examples

```bash
# Everything uncovered
hecate-agent attack gap

# Narrow to a tactic and platform
hecate-agent attack gap --tactic persistence --platform Windows

# JSON, for scripting
hecate-agent attack gap --output json

# Draft hunts for the top 5 uncovered credential-access techniques
hecate-agent attack gap --tactic credential-access --generate

# Draft up to 10
hecate-agent attack gap --generate --limit 10
```

### JSON Output

```json
[
  {
    "tactic": "credential-access",
    "id": "T1003",
    "name": "OS Credential Dumping",
    "is_subtechnique": false,
    "platforms": ["Linux", "macOS", "Windows"]
  }
]
```

### Exit Codes

- `0`: Success (or no STIX data, with a message)

---

## hecate-agent eval

Run known-answer fixtures against an LLM provider and score the result.

### Synopsis

```bash
hecate-agent eval [OPTIONS]
```

### Description

Scores a model against 10 unambiguous, known-answer fixtures — 8 MITRE ATT&CK
technique-ID recall questions and 2 concept questions. It exists to catch
confident hallucination, such as a model answering "System Information
Discovery" for `T1003.001` instead of "OS Credential Dumping: LSASS Memory".

This is a spot check, not a general capability benchmark. One LLM call is made
per fixture, so a local model may take a few minutes.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--provider` | String | configured | Override the LLM provider (e.g. `ollama`, `litellm`, `bedrock`) |
| `--model` | String | configured | Override the model |
| `--output` | Choice | table | `table` or `json` |
| `--temperature` | Float | 0.0 | Sampling temperature; the default keeps runs reproducible |
| `--grounded` | Flag | False | Score STIX-grounded fixtures instead of cold recall |
| `--tier` | Choice | unset | Eval the dual-router `simple` or `complex` backend |
| `--fail-under` | Float | unset (`0.8` with `--write-gate`) | Exit 1 when the score is below this threshold |
| `--write-gate` | String | unset | On pass, write a demotion gate stamp unlocking this locked capability for simple routing |

### Cold recall vs. grounded

By default the fixtures ask the model to recall a technique unaided. `--grounded`
instead hands it MITRE's real technique name and description (from the same STIX
data `hecate-agent attack lookup` uses — no LLM involved) and asks it to
summarize.

The two scores answer different questions: whether the model *knows* a fact, and
whether it can correctly *use* one it is given. A pipeline that looks techniques
up via STIX before prompting only depends on the second. A large gap between the
scores says to fix retrieval and prompting; a low grounded score says the model
itself is the limit.

### Examples

**Score the configured provider and model**:

```bash
hecate-agent eval
```

**Score a specific model without editing `.env`**:

```bash
hecate-agent eval --provider ollama --model qwen2.5:14b-instruct-q4_K_M
```

**Compare two models**:

```bash
hecate-agent eval --model qwen2.5:7b-instruct-q4_K_M  --output json > 7b.json
hecate-agent eval --model qwen2.5:14b-instruct-q4_K_M --output json > 14b.json
```

**Separate knowing a fact from using one**:

```bash
hecate-agent eval --grounded
```

**Gate demoting a locked capability onto the simple tier**:

```bash
hecate-agent eval --tier simple --write-gate research_synthesize --fail-under 0.8
```

### JSON Output

```json
{
  "provider": "ollama",
  "model": "qwen2.5:14b-instruct-q4_K_M",
  "score": 0.9,
  "passed": 9,
  "total": 10,
  "duration_ms": 41230,
  "results": [
    {
      "id": "T1003.001",
      "category": "mitre-technique",
      "description": "OS Credential Dumping: LSASS Memory",
      "passed": true,
      "duration_ms": 3910,
      "response_text": "...",
      "error": null
    }
  ]
}
```

### Exit Codes

- `0`: Eval ran (including when fixtures fail — the score is the result, not the exit status)
- `1`: No LLM provider could be created

---

## hecate-agent mcp serve

Start the Hecate MCP server, exposing Hecate operations as tools an AI assistant
can call directly.

### Synopsis

```bash
hecate-agent mcp serve [OPTIONS]
hecate-agent-mcp [OPTIONS]        # standalone entry point, same server
```

### Description

Serves the MCP tools that mirror the CLI — hunts, investigations, research,
agents, ATT&CK lookups and search — over the Model Context Protocol, so an
assistant such as Claude Code can call them without shelling out.

The server is built on `FastMCP` and therefore requires `mcp[cli]<2.0.0`; the
2.0.0 release removed `mcp.server.fastmcp`. Install it with the `[mcp]` extra.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--workspace` | String | auto-detected | Explicit workspace path |
| `--transport` | Choice | stdio | `stdio`, `sse`, or `streamable-http` |
| `--port` | Integer | 3100 | HTTP port, for the SSE and streamable-http transports |

Workspace resolution order: `--workspace`, then `HECATE_WORKSPACE`, then the
first ancestor of the current directory containing `.hecateconfig.yaml`.

### Examples

**Stdio, the transport Claude Code uses**:

```bash
hecate-agent mcp serve --workspace /path/to/hunts
```

**HTTP, for a web UI**:

```bash
hecate-agent mcp serve --transport streamable-http --port 3100
```

### Registering with Claude Code

In `~/.claude/mcp-servers.json`:

```json
{
  "hecate": {
    "command": "hecate-agent-mcp",
    "args": ["--workspace", "/path/to/hunts"]
  }
}
```

### Exit Codes

- `0`: Server shut down cleanly
- `1`: The `mcp` extra is not installed (clean error message)
- `1`: The workspace could not be resolved — currently surfaces as an uncaught
  `FileNotFoundError` traceback rather than a formatted error

---

## Configuration

Hecate reads `.hecateconfig.yaml` from `config/.hecateconfig.yaml`, falling back
to the workspace root. The file is optional — every key has a default — and you
write it by hand.

```yaml
# Default data sources suggested for new hunts. Free text, not an enum:
# use whatever names your stack actually goes by.
siem: Splunk
edr: CrowdStrike

# Hunt ID prefix. Generates H-0001, H-0002, ...
hunt_prefix: H-

# Default hunter name recorded on new hunts
hunter: Analyst
```

Those four keys are the ones any command reads. Other keys are preserved but
ignored, so a workspace carrying `workspace_name` or `hunt_retention_days` from
an older layout is valid and simply has no effect.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HECATE_CONFIG` | Path to config file | `.hecateconfig.yaml` |
| `HECATE_HUNTS_DIR` | Path to hunts directory | `./hunts` |
| `HECATE_TEMPLATE_DIR` | Path to templates | `./templates` |

Example:

```bash
export HECATE_HUNTS_DIR="/opt/threat-hunting/hunts"
hecate-agent hunt list
```

---

## Exit Codes

All `hecate-agent` commands use standard exit codes:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (file not found, validation failed, etc.) |
| `2` | Invalid arguments or options |
| `130` | Interrupted by user (Ctrl+C) |

Use in scripts:

```bash
if hecate-agent hunt validate H-0001; then
    echo "Hunt is valid"
else
    echo "Hunt has errors"
    exit 1
fi
```

---

## Tips and Tricks

### Use with Grep and Awk

```bash
# List only completed hunts
hecate-agent hunt list --output json | jq '.[] | select(.status=="completed")'

# Count hunts by tactic
hecate-agent hunt list --output json | jq -r '.[].tactics[]' | sort | uniq -c

# Find high-severity hunts
hecate-agent hunt list --output json | jq '.[] | select(.severity=="high")'
```

### Automation with Shell Scripts

```bash
#!/bin/bash
# Create weekly hunt report

WEEK=$(date +%Y-W%V)
REPORT="reports/hunt-report-$WEEK.md"

echo "# Weekly Hunt Report - $WEEK" > "$REPORT"
echo "" >> "$REPORT"

echo "## Statistics" >> "$REPORT"
hecate-agent hunt stats >> "$REPORT"

echo "" >> "$REPORT"
echo "## Completed Hunts" >> "$REPORT"
hecate-agent hunt list --status completed --output json | \
  jq -r '.[] | "- \(.hunt_id): \(.title)"' >> "$REPORT"

echo "Report generated: $REPORT"
```

### CI/CD Integration

```yaml
# .github/workflows/validate-hunts.yml
name: Validate Hunts

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install "git+https://github.com/BrizoSec/Hecate-Core.git"
      - run: hecate-agent hunt validate
```

### Batch Operations

```bash
# Create multiple hunts from a list
cat techniques.txt | while read tech title; do
  hecate-agent hunt new \
    --technique "$tech" \
    --title "$title" \
    --non-interactive
done

# Validate all hunts and save results
for hunt in hunts/H-*.md; do
  hunt_id=$(basename "$hunt" .md)
  hecate-agent hunt validate "$hunt_id" 2>&1 | tee "validation-$hunt_id.log"
done
```

---

## See Also

- [Getting Started Guide](getting-started.md)
- [Installation Guide](https://github.com/BrizoSec/Hecate-Core/blob/main/docs/INSTALL.md)
- [Hunt Format Guidelines](https://github.com/BrizoSec/Hecate-Core/blob/main/hunts/FORMAT_GUIDELINES.md)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## Need Help?

- **CLI help**: `hecate-agent --help` or `hecate-agent <command> --help`
- **GitHub Issues**: [Report bugs or request features](https://github.com/BrizoSec/Hecate-Core/issues)
- **Documentation**: [docs/getting-started.md](getting-started.md)
