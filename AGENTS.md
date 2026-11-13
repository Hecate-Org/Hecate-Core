# AGENTS.md - Context for AI Assistants Using Hecate

**Purpose:** This file provides AI assistants with context about threat hunting repositories using Hecate.

---

## Repository Overview

This repository contains threat hunting investigations using the LOCK pattern (Learn → Observe → Check → Keep).

**AI assistants should:**

- Use the installed `hecate-agent` command. In a source checkout, activate `.venv` first only when using that checkout’s virtual environment.
- **Read [knowledge/hunting-knowledge.md](knowledge/hunting-knowledge.md)** - Expert hunting frameworks and analytical methods
- **Browse past hunts** - Search hunt history before suggesting new hypotheses
- Reference lessons learned when generating queries
- Use [knowledge/environment.md](knowledge/environment.md) to understand available data sources
- **Focus on behaviors and TTPs (top of Pyramid of Pain), not indicators**

---

## 🚨 MANDATORY: Use Hecate CLI Commands & Agents

**CRITICAL REQUIREMENT:** AI assistants MUST use `hecate-agent` CLI commands or `hecate-agent agent run` for ALL tasks that have corresponding CLI functionality. Direct file manipulation is prohibited for framework-managed operations.

### ✅ ALWAYS Use CLI For

| Task Category              | CLI Command                                                | ❌ Never Use                   |
| -------------------------- | ---------------------------------------------------------- | ----------------------------- |
| **Hunt creation**          | `hecate-agent hunt new --non-interactive`                          | Write tool, Edit tool         |
| **Baseline hunt creation** | `hecate-agent hunt new-baseline --non-interactive`                 | Write tool, Edit tool         |
| **Model-assisted hunt**    | `hecate-agent hunt new-model-assisted --non-interactive`           | Write tool, Edit tool         |
| **Investigation creation** | `hecate-agent investigate new --non-interactive`                   | Write tool, Edit tool         |
| **Research execution**     | `hecate-agent research new --topic "..."`                          | Manual web search, Write tool |
| **Hypothesis generation**  | `hecate-agent agent run hypothesis-generator --threat-intel "..."` | Manual hypothesis drafting    |
| **Duplicate checking**     | `hecate-agent similar "keywords"`                                  | Grep, manual search           |
| **Context loading**        | `hecate-agent context --hunt H-XXXX`                               | Multiple Read operations      |
| **Coverage analysis**      | `hecate-agent hunt coverage`                                       | Manual ATT&CK counting        |
| **Hunt validation**        | `hecate-agent hunt validate H-XXXX`                                | Manual YAML parsing           |
| **Hunt search**            | `hecate-agent hunt search "keyword"`                               | Grep, manual file search      |

### 🎯 CLI-First Policy

**Why this matters:**

- ✅ CLI provides proper validation and error checking
- ✅ Auto-generates correct YAML frontmatter and LOCK structure
- ✅ Maintains hunt ID sequences and file naming conventions
- ✅ Ensures consistency across all hunt documents
- ✅ Reduces token costs (single command vs. multiple tool calls)
- ✅ Prevents malformed hunt files that break CI/CD pipelines

**Enforcement:**

- ❌ NEVER use Write/Edit tools to create hunt or investigation files
- ❌ NEVER manually construct YAML frontmatter
- ❌ NEVER bypass CLI for hunt management operations
- ✅ ALWAYS verify virtual environment is activated (`which hecate-agent`)
- ✅ ALWAYS use CLI for file generation and validation

### 📋 When Manual Tools Are Acceptable

You MAY use Read, Edit, Grep, Glob tools for:

- Reading existing hunt/investigation/research files
- Editing hunt file content AFTER creation (query results, findings, lessons learned)
- Searching file contents (complement to `hecate-agent hunt search`)
- Exploring codebase structure
- Reading knowledge/environment.md and knowledge files

**Rule of thumb:** If `hecate-agent` has a command for it, use the command. Manual tools are for content, not structure.

---

## 🎯 TOKEN OPTIMIZATION: Structured Output Rules

**CRITICAL**: Use structured output formats for query analysis to reduce token costs by 75%.

**Three Output Modes:**

1. **JSON Format** (Use 80% of time) - For security findings, event logs, structured data
   - Rules: JSON only, suspicion_score > 30 only, one-sentence reasons, no preambles
2. **Table Format** (Quick triage) - Columnar data for rapid scanning
3. **Narrative** (Sparingly) - Final hunt reports, deliverables, hypothesis generation

**Impact**: Verbose output ~2,000 tokens vs. Structured ~500 tokens = significant cost savings

---

## Repository Structure

### Framework Source Code (`hecate_agent/`)

```text
hecate_agent/                     # Python package and CLI source
├── agents/                       # Agent implementations
├── commands/                     # Click command groups
├── core/                         # Managers, parsers, and shared logic
├── orchestrator/                 # Agentic workflow
├── mcp/                          # MCP server and tools
└── data/                         # Bundled docs, examples, prompts, templates
```

### User Workspace

The CLI uses the current directory or configured workspace. It creates `hunts/`,
`research/`, and `queries/` as needed. Other content such as `knowledge/`,
`integrations/`, templates, and this `AGENTS.md` is supplied or maintained by
workspace owners; it is not guaranteed to exist in every workspace.

```text
workspace/
├── .hecateconfig.yaml          # Optional settings
├── AGENTS.md                   # Optional assistant guidance
├── hunts/                      # Hunt records
├── research/                   # Research records
├── queries/                    # Query files
├── knowledge/                  # Environment and hunting knowledge
└── integrations/               # Optional integration guidance
```

---

## Nested AGENTS.md Files

This repository can use nested AGENTS.md files for specialized context. The closest file in the directory hierarchy takes precedence.

| Directory | Context | When to Load |
|-----------|---------|--------------|
| Root `/` | General hunting methodology | Default context |
| `integrations/<datasource>/` | Query execution, data source specifics | Writing queries for that data source |
| `hunts/` | Hunt execution workflow, LOCK pattern | Creating/executing hunts |
| `research/` | Research-first workflow | Pre-hunt research |
| `queries/` | Query library, parameterized queries | Alert triage |
| `investigations/` | Investigation workflow | Exploratory analysis |

**Note:** Nested AGENTS.md files are optional. Organizations can add them to provide context-specific guidance.

---

## Hunting Knowledge Base

### knowledge/hunting-knowledge.md

The file [knowledge/hunting-knowledge.md](knowledge/hunting-knowledge.md) contains expert threat hunting knowledge that AI should apply when generating hypotheses:

**Core Sections:**
1. **Hypothesis Generation** - Pattern-based generation, quality criteria, examples
2. **Behavioral Models** - ATT&CK TTP → observable mappings, behavior-to-telemetry translation
3. **Pivot Logic** - Artifact chains, pivot playbooks, decision criteria
4. **Analytical Rigor** - Confidence scoring, evidence strength, bias checks
5. **Framework Mental Models** - Pyramid of Pain, Diamond Model, Hunt Maturity, Data Quality

**Key Principle:** All hunts must focus on **behaviors and TTPs (top half of Pyramid of Pain)**. Never build hunts solely around hashes, IPs, or domains.

**When to consult:**
- Before generating hypotheses (review Section 1 and Section 5)
- During hunt execution (review Section 3 for pivot logic)
- When analyzing findings (review Section 4 for confidence scoring)

---

## Data Sources

See [knowledge/environment.md](knowledge/environment.md) for documenting your organization's data sources:

- SIEM/log aggregation platforms
- EDR/endpoint telemetry coverage
- Network visibility capabilities
- Cloud logging (AWS CloudTrail, Azure Activity Logs, GCP Audit Logs)
- Identity and authentication logs
- Known visibility gaps and blind spots

**AI Note:** Always verify data sources exist in the user's knowledge/environment.md before generating queries or hunt hypotheses.

**Supported Integrations:** Any data source with query capabilities

**Common Examples:** Splunk, Elasticsearch, Athena, BigQuery, PostgreSQL, Microsoft Sentinel, Sumo Logic, etc.

**Integration-Specific Guidance:** Organizations should create `integrations/<datasource>/AGENTS.md` files for data source-specific query syntax, field naming, and best practices.

---

## Hunting Methodology

This repository follows the **LOCK pattern**:

1. **Learn** - Gather context (CTI, alert, anomaly, threat intel)
2. **Observe** - Form hypothesis about adversary behavior
3. **Check** - Test with bounded, safe query
4. **Keep** - Record decision and lessons learned

**AI assistants should:**
- Generate hypotheses in LOCK format (see [templates/HUNT_LOCK.md](templates/HUNT_LOCK.md))
- Ensure queries are bounded by time, scope, and impact
- Document lessons learned after hunt execution
- Reference past hunts when suggesting new ones

---

## Investigation vs Hunt

**Purpose:** Investigations (I-XXXX) are for exploratory work, alert triage, and ad-hoc analysis that **does NOT contribute to hunt metrics**.

**Use investigations when:** Alert triage, exploring new data sources, testing queries, uncertain hypothesis, avoiding metrics pollution

**Use hunts when:** Testable hypothesis, repeatable detection logic, tracking metrics, deliverables, ATT&CK coverage

**Key Differences:**

| Aspect | Hunts (H-XXXX) | Investigations (I-XXXX) |
|--------|----------------|-------------------------|
| **Purpose** | Hypothesis-driven hunting | Exploratory analysis |
| **Metrics** | Tracked (TP/FP/costs) | **NOT tracked** |
| **Directory** | `hunts/` | `investigations/` |
| **Validation** | Strict (CI/CD enforced) | Lightweight |

**CLI Commands:**
- `hecate-agent investigate new` - Create investigation (interactive or --non-interactive)
- `hecate-agent investigate list [--type finding]` - List/filter investigations
- `hecate-agent investigate search "keyword"` - Full-text search
- `hecate-agent investigate validate I-XXXX` - Lightweight validation
- `hecate-agent investigate promote I-XXXX` - Promote to formal hunt

**Cross-Referencing:**
- Investigations → Hunts: Use `related_hunts: [H-0013]` field
- Hunts → Investigations: Use `spawned_from: I-0042` field

---

## Query Guardrails

### Universal Rules (Apply to All Data Sources)

**Mandatory Rules:**
- ✅ Always include time bounds (7 days max initially for exploratory queries)
- ✅ Always start with `LIMIT 100` or equivalent (progressive strategy)
- ✅ Use `hecate-agent validate query --sql "..."` before executing (if supported by your data source)
- ✅ **COUNT-FIRST:** Count baseline → Count filtered → Analyze → Pull results only if justified
- ✅ **Sequential execution:** ONE query at a time, STOP for user feedback
- ❌ Never omit LIMIT or time constraints
- ❌ Never execute multiple queries in parallel without user approval

**COUNT-FIRST Decision Tree:**
- count = 0 → Skip (no results)
- count < 100 → LIMIT 100
- count 100-1000 → LIMIT 1000
- count > 1000 → Refine filters first, then proceed

**If timeout or slow query:** Reduce time range → Add filters → Simplify aggregations

### Data Source-Specific Guidance

Query syntax, field naming, and performance optimization vary by data source. Refer to integration-specific AGENTS.md files in your workspace:

- `integrations/clickhouse/AGENTS.md` - ClickHouse query syntax, field escaping, timeout prevention
- `integrations/splunk/AGENTS.md` - SPL query patterns, search modes
- `integrations/elasticsearch/AGENTS.md` - Query DSL, aggregations
- `integrations/athena/AGENTS.md` - Presto SQL, partition optimization

**See your workspace `integrations/` directory for deployed data source guidance.**

### Hypothesis Validation

- **Check if we've hunted this before** - Use `hecate-agent similar "hypothesis keywords"` to find duplicate hunts
- **Verify data source availability** - Reference knowledge/environment.md
- **Ensure hypothesis is testable** - Can be validated with a query
- **Consider false positive rate** - Will this hunt generate noise?

### Documentation

- **Use LOCK structure** for all hunt documentation
- **Capture negative results** - Hunts that found nothing are still valuable
- **Record lessons learned** - What worked, what didn't, what to try next
- **Link related hunts** - Reference past work

---

## CLI Commands (Recommended Workflow)

**Purpose:** Hecate includes CLI tools (`hecate-agent` command) that automate common hunt management tasks. When available, these commands are faster and more reliable than manual file operations.

### Environment Setup

For a source checkout, `hecate-agent env setup` can create the project virtual
environment. Activate it when you need the checkout’s installed command:

```bash
source .venv/bin/activate
which hecate-agent
hecate-agent --version
```

For a normal package installation, use the command in the environment where
`hecate-agent` was installed. Optional features may require extras; see
[`docs/INSTALL.md`](docs/INSTALL.md).

---

### Useful Context and Search Commands

Use these commands when they fit the task and are available:

1. **`hecate-agent similar "hypothesis keywords"`** - BEFORE creating hunt hypothesis
   - Prevents duplicate hunts
   - Finds related past work
   - Saves time and token costs
   - Example: `hecate-agent similar "password spraying"`

2. **`hecate-agent context --hunt H-XXXX`** - BEFORE executing hunt queries
   - Loads all context in one command (~5 Read operations → 1 command)
   - Saves ~75% token usage
   - Returns JSON/YAML/Markdown with knowledge/environment.md + past hunts + domain knowledge
   - Example: `hecate-agent context --tactic credential-access --format json`

**Failure to use these tools will result in:**
- Duplicate hunts (wasted effort)
- Excessive token costs
- Slower hunt execution

---

### Suggested Hunt Workflow

| Step | Command | When | Purpose |
|------|---------|------|---------|
| 1 | `hecate-agent similar "keywords"` | BEFORE hypothesis | Check for duplicate hunts |
| 2 | `hecate-agent research new --topic "..."` | REQUIRED before an AI-generated hypothesis; optional when a human writes it | Research grounded in available sources and configuration |
| 3 | `hecate-agent agent run hypothesis-generator --threat-intel "..."` | AFTER research | Generate structured hypothesis |
| 4 | `hecate-agent hunt new --technique T1XXX --title "..." --non-interactive` | WHEN creating hunt | Auto-generate hunt file (⚠️ NEVER use Write tool) |
| 5 | `hecate-agent context --hunt H-XXXX --format json` | BEFORE executing queries | Load all context efficiently |

---

### Hunt Execution Steps

1. **Check duplicates:** `hecate-agent similar "hypothesis keywords"`
2. **Deep research (required before step 3):** `hecate-agent research new --topic "..."` (creates R-XXXX.md with 5-skill methodology). Optional only when a human writes the hypothesis and step 3 is skipped
3. **Generate hypothesis:** `hecate-agent agent run hypothesis-generator --threat-intel "..."`
4. **Create hunt file:** `hecate-agent hunt new --research R-XXXX --non-interactive ...` (link to research)
5. **Load context:** `hecate-agent context --hunt H-XXXX --format json`
6. **Present hypothesis to user** - ABLE scoping table + threat context
7. **Execute queries** - Use appropriate data source tools (ClickHouse CLI, SIEM interface, etc.)
8. **STOP after each query** - Wait for user feedback before next query
9. **Document findings** - Update hunt file with results and conclusions

---

### Additional Commands

```bash
# Agent management
hecate-agent agent list                       # List available agents
hecate-agent agent info hypothesis-generator  # Get info about specific agent
hecate-agent agent run hunt-researcher --topic "LSASS dumping"

# Hunt management
hecate-agent hunt coverage                    # ATT&CK coverage analysis
hecate-agent hunt coverage --tactic credential-access
hecate-agent hunt search "credential dumping" # Full-text search across hunts
hecate-agent hunt validate H-0001             # Validate hunt file structure

# Research management
hecate-agent research list                    # List research documents
hecate-agent research view R-0001             # View specific research
hecate-agent research search "credential access"  # Search research documents
hecate-agent research stats                   # Show research metrics

# ATT&CK data management (optional: pip install -e ".[attack]")
hecate-agent attack update                    # Download/refresh STIX data
hecate-agent attack status                    # Show provider type, version, cache info
hecate-agent attack lookup T1003.001          # Look up technique metadata
hecate-agent attack techniques credential-access  # List techniques for a tactic

# Similarity search
hecate-agent similar "LSASS dumping"          # Find similar hunts by query
hecate-agent similar --hunt H-0001            # Find hunts similar to H-0001
```

---

### Research Commands

```bash
# Deep research before hunting (15-20 min, uses web search + LLM) - DEFAULT
hecate-agent research new --topic "LSASS dumping" --technique T1003.001

# Quick research for urgent hunts (5 min)
hecate-agent research new --topic "Pass-the-Hash" --depth basic

# Offline mode (no web search)
hecate-agent research new --topic "Credential Access" --no-web-search

# List and view research documents
hecate-agent research list
hecate-agent research list --status completed
hecate-agent research view R-0001
hecate-agent research search "kerberos"

# Statistics
hecate-agent research stats

# Link research to hunt during creation (do this whenever research was run)
hecate-agent hunt new --research R-0001 --non-interactive
```

**Research is required before an AI assistant generates a hypothesis, and optional when a human writes one.** Ungrounded generation measured about 30% accuracy on known-answer ATT&CK fixtures (`hecate-agent eval`), which is why the automated pipeline refuses to draft without research. If research cannot run (no LLM or no web search configured), say so and let the human decide; do not silently generate an ungrounded hypothesis. What research provides:

- Deep understanding of system internals before hunting (Skill 1: System Research)
- Adversary tradecraft is mapped to available telemetry (Skill 2: Adversary Tradecraft via web search)
- Telemetry gaps identified early (Skill 3: OCSF Field Mapping)
- Past hunts are reviewed to avoid duplication (Skill 4: Related Work)
- Hunt hypotheses are informed by structured research (Skill 5: Synthesis)

**5-Skill Research Methodology:**

1. **System Research** - How does this technology normally work?
2. **Adversary Tradecraft** - Attack techniques (web search via Tavily)
3. **Telemetry Mapping** - OCSF field availability analysis
4. **Related Work** - Past hunt correlation via semantic search
5. **Research Synthesis** - Key findings, gaps, recommended hypothesis

**Time investment:**

- Advanced (default): 15-20 minutes - thorough 5-skill methodology
- Basic (urgent): 5 minutes - rapid research for time-sensitive hunts

**Environment:**

- Configure the chosen model with `HECATE_LLM_PROVIDER` / `HECATE_LLM_MODEL` and its required credentials.
- Tavily web search requires `TAVILY_API_KEY` when enabled; `--no-web-search` disables that lookup.
- AWS profile/role credentials are required only for a chosen AWS-backed feature, not every provider.

---

### AI-Friendly Hunt Creation (One-Liner Support)

`hecate-agent hunt new` supports rich content flags for fully-populated hunt files without manual editing.

**Basic Usage:**
```bash
hecate-agent hunt new --title "Hunt Title" --technique T1003.001 --non-interactive
```

**AI-Friendly One-Liner (Full Hypothesis + ABLE Framework):**
```bash
hecate-agent hunt new \
  --title "macOS Unix Shell Abuse for Reconnaissance" \
  --technique "T1059.004" \
  --tactic "execution" \
  --platform "macOS" \
  --data-source "EDR process telemetry" \
  --hypothesis "Adversaries execute malicious commands via native macOS shells..." \
  --threat-context "macOS developer workstations are high-value targets..." \
  --actor "Generic adversary (malware droppers, supply chain attackers...)" \
  --behavior "Shell execution from unusual parents performing reconnaissance..." \
  --location "macOS endpoints (developer workstations)..." \
  --evidence "EDR process telemetry - Fields: process.name, parent.process.name..." \
  --hunter "Your Name" \
  --non-interactive
```

**Benefits:**
✅ AI assistants can create fully-populated hunt files in one command
✅ No manual file editing required for basic hunts
✅ All LOCK template fields can be populated via CLI
✅ Backwards compatible (all flags are optional)

**Available Rich Content Flags:**
- `--hypothesis` - Full hypothesis statement
- `--threat-context` - Threat intel or context motivating the hunt
- `--actor` - Threat actor (for ABLE framework)
- `--behavior` - Behavior description (for ABLE framework)
- `--location` - Location/scope (for ABLE framework)
- `--evidence` - Evidence description (for ABLE framework)
- `--research` - Research document ID (e.g., R-0001) to link to hunt
- `--hunter` - Hunter name (default: "AI Assistant")

---

### Common Mistakes

| ❌ Wrong | ✅ Correct |
|---------|-----------|
| Write tool → hunt file | `hecate-agent hunt new --non-interactive` |
| Skip duplicate check | `hecate-agent similar "keywords"` first |
| Skip research before an AI-generated hypothesis | `hecate-agent research new --topic "..."` first |
| Manual hypothesis | `hecate-agent agent run hypothesis-generator --threat-intel "..."` |
| Multiple Read operations | `hecate-agent context --hunt H-XXXX` |

**Full CLI Reference:** [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)

---

## Domain-Specific Knowledge

Hecate includes bundled hunting knowledge files to inform hunt hypotheses and query generation.

**Example domain-specific knowledge files organizations can add:**

| Domain | Example File Path | Use Case |
|--------|-------------------|----------|
| **MITRE ATT&CK** | `knowledge/mitre-attack.md` | TTP mapping, coverage analysis, prioritization |
| **Endpoint Security** | `knowledge/domains/endpoint-security.md` | Process execution, LOTL, credential access, persistence |
| **IAM Security** | `knowledge/domains/iam-security.md` | Password spraying, MFA fatigue, impossible travel |
| **Insider Threat** | `knowledge/domains/insider-threat.md` | Data exfiltration, bulk file access, sabotage |
| **Cloud Security** | `knowledge/domains/cloud-security.md` | AWS/Azure/GCP, CloudTrail, IAM manipulation |

**Note:** These are example paths. Organizations should create custom domain knowledge files in their workspace `knowledge/` directory as needed.

---

## Hunt Idea Generation

**When user requests hunt ideas:**

1. **Analyze coverage gaps:** `hecate-agent hunt coverage --tactic all` or `hecate-agent context --tactic all --format json`
2. **Validate data sources:** Check user's knowledge/environment.md for available telemetry
3. **Present Top 3 ranked options** with MITRE technique, data source, priority reason
4. **Wait for user selection** before creating hunt

**Full workflow:** [prompts/ai-workflow.md](prompts/ai-workflow.md)

---

## Priority TTPs

**How to Define Organizational Priorities:**

1. Review threat model (ransomware, insider threat, nation-state, supply chain, etc.)
2. Map high-risk TTPs from MITRE ATT&CK framework
3. Prioritize based on detection coverage gaps and business impact
4. Document priorities in your workspace knowledge/environment.md

**Example Priorities (Customize for Your Organization):**
- TA0006 - Credential Access
- TA0004 - Privilege Escalation
- TA0008 - Lateral Movement
- TA0003 - Persistence
- TA0010 - Exfiltration

**AI Note:** Prioritize hunt suggestions based on org's threat model and TTPs documented in knowledge/environment.md. High-priority TTPs should guide coverage gap analysis.

---

## Memory and Search

**Maturity Level:** Level 4 (Agentic) - AI assistants can autonomously execute hunt workflows using CLI tools

**AI capabilities:**

- Execute queries via data source integrations
- Semantic similarity search (`hecate-agent similar`)
- **Pre-hunt research with web search** (`hecate-agent research new`) - 5-skill methodology
- **LLM-powered agents** (`hecate-agent agent run`) - Hypothesis generation, hunt research
- Automated hypothesis generation (`hecate-agent agent run hypothesis-generator`)
- Automated hunt research (`hecate-agent agent run hunt-researcher`)
- ATT&CK coverage analysis (`hecate-agent hunt coverage`)
- **ATT&CK STIX data** (`hecate-agent attack update/status/lookup/techniques`) - live technique metadata
- Context loading optimization (`hecate-agent context`)
- MCP integrations (Notion, GitHub, custom tools)

**Data sources AI can access:**
- `hunts/` folder and past hunt files
- `research/` folder (R-XXXX.md documents)
- Data sources via integrations (Splunk, etc. - via CLI or MCP)
- Web search via Tavily API (`hecate-agent research new`)
- User's knowledge/environment.md

**Agent Infrastructure:**

- **LLM Agents:** AI-powered agents
- **Agent Types:**
  - `hypothesis-generator` - Generates creative hunt hypotheses from threat intel
  - `hunt-researcher` - Conducts thorough 5-skill pre-hunt research
- **Execution Modes:** Interactive (default, step-by-step execution with user approval)

**MCP Server Integration:** Organizations can extend AI capabilities by installing MCP servers. See [integrations/MCP_CATALOG.md](integrations/MCP_CATALOG.md) for available integrations.

---

## CLI Context Export & Semantic Search

**Purpose:** Two commands designed specifically for AI assistants to reduce token usage and avoid duplicate hunts.

### `hecate-agent context` - AI-Optimized Context Loading

**Why this helps AI:**
- **Reduces context-loading from ~5 tool calls to 1** - Single command replaces multiple Read operations
- **Saves ~2,000 tokens per hunt**
- **Pre-filtered, structured content** - Only relevant files included
- **Easier parsing** - JSON/YAML output formats

**Usage examples:**
```bash
# Export context for specific hunt
hecate-agent context --hunt H-0013 --format json

# Export context for all credential access hunts
hecate-agent context --tactic credential-access --format json

# Export context for macOS platform hunts
hecate-agent context --platform macos --format json

# Combine filters: persistence hunts on Linux platform
hecate-agent context --tactic persistence --platform linux --format json

# Export full repository context (use sparingly)
hecate-agent context --full --format json
```

**What's included:**
- User's knowledge/environment.md - Tech stack, data sources
- Past hunts - Filtered by hunt ID, tactic, platform, or combinations
- Domain knowledge - Relevant domain files based on tactic

**When to use:**
- **Before generating hunt hypothesis** - Get environment, past hunts, domain knowledge
- **Before generating queries** - Get data sources, past query examples
- **When user asks about specific hunt** - Load hunt content + context
- **When exploring tactics** - Get all hunts for a specific tactic

### `hecate-agent similar` - Semantic Hunt Search

**Why this helps AI:**
- **Find similar hunts even with different terminology** - Semantic search, not keyword matching
- **Avoid duplicate hunts** - Check if similar hunt already exists
- **Discover patterns** - Find related hunts across history
- **Better than grep** - Conceptual matching, not string matching

**Usage examples:**
```bash
# Find hunts similar to text query
hecate-agent similar "password spraying via RDP"

# Find hunts similar to specific hunt
hecate-agent similar --hunt H-0013

# Limit results to top 5
hecate-agent similar "kerberos" --limit 5

# Export as JSON for parsing
hecate-agent similar "credential theft" --format json

# Set minimum similarity threshold
hecate-agent similar "reconnaissance" --threshold 0.3
```

**Similarity scoring:**
- **≥0.50** = Very similar (likely duplicate or closely related)
- **0.30-0.49** = Similar (same domain or tactic)
- **0.15-0.29** = Somewhat similar (related concepts)
- **<0.15** = Low similarity (different topics)

**When to use:**
- **Before creating new hunt** - Check if similar hunt already exists
- **When user describes hunt** - Find existing hunts matching description
- **When exploring patterns** - Discover hunt clusters by topic
- **After hypothesis generation** - Verify not duplicating work

**Combined workflow (context + similar):**
```
User: "Help me hunt for Kerberoasting"
AI: 1. hecate-agent similar "kerberoasting" --format json
       → Check for similar hunts first
    2. If similar hunt exists (score > 0.3):
       - hecate-agent context --hunt H-XXXX --format json
       - Suggest continuing existing hunt
    3. If no similar hunt:
       - hecate-agent context --tactic credential-access --format json
       - Generate new hypothesis with context
       - Create new hunt
```

**Requirements:**
- `scikit-learn` must be installed for `hecate-agent similar`
- Install with: `pip install scikit-learn`

---

## Hypothesis Generation Workflow

**Core Process:**

1. **Consult Hunting Brain** - Read [knowledge/hunting-knowledge.md](knowledge/hunting-knowledge.md) Section 1 (Hypothesis Generation) and Section 5 (Pyramid of Pain)
2. **Search Memory First** - Use `hecate-agent similar "your hypothesis keywords"` when semantic duplicate checking is available (saves time and avoids redundant work)
3. **Validate Environment** - Read user's knowledge/environment.md to confirm data sources exist
4. **Generate LOCK Hypothesis** - Create testable hypothesis following [templates/HUNT_LOCK.md](templates/HUNT_LOCK.md)
5. **Apply Quality Criteria** - Use quality checklist (Falsifiable, Scoped, Observable, Actionable, Contextual)
6. **Suggest Next Steps** - Offer to create hunt file or draft query

**Key Requirements:**

- **Focus on behaviors/TTPs (top of Pyramid of Pain)** - Never build hypothesis around hashes or IPs alone
- Match hypothesis format: "Adversaries use [behavior] to [goal] on [target]"
- Reference past hunts by ID (e.g., "Building on H-0022 lessons...")
- Specify data sources from user's knowledge/environment.md
- Include bounded time range with justification
- Consider false positives from similar past hunts
- Apply hypothesis quality rubric from hunting-knowledge.md

**Output Must Follow:** [templates/HUNT_LOCK.md](templates/HUNT_LOCK.md) structure

**Complete workflow details:** [prompts/ai-workflow.md](prompts/ai-workflow.md)

---

## Maintenance

**Review this file when:**
- Adding new data sources (update "Data Sources" section or user's knowledge/environment.md)
- Changing priority TTPs (update "Priority TTPs" section or user's knowledge/environment.md)
- Discovering AI generates incorrect assumptions (add to "Guardrails" or "Common Mistakes")
- New integrations or MCP servers added (update "Memory and Search")
- Team practices change (update CLI workflow or hunt execution steps)

**Last reviewed:** 2026-11-13
**Maintained By:** Hecate Framework Team
