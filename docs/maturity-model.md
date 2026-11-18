# The Five Levels of Agentic Hunting

Use this model to choose your next capability. Levels 1–2 are sufficient for many
teams; integrations and unattended workflows are optional. These levels describe
operating practices, not capabilities enabled by installing a package.

## Overview

| Level | Capability | Evidence that it works |
| --- | --- | --- |
| **0: Ad-hoc** | Hunts live in tickets, chat and analyst notes | Individual investigations can be recovered, but history is fragmented |
| **1: Documented** | Persistent LOCK-format hunt records | Another analyst can understand what was tested and learned |
| **2: Searchable** | Assistants retrieve relevant history and environment context | Suggestions cite existing hunts and verified telemetry |
| **3: Generative** | Assistants use configured tools under analyst direction | Approved, bounded queries and resulting actions have an audit trail |
| **4: Agentic** | Scheduled workflows prepare work within defined limits | Drafts, review gates, failures and recovery remain observable |

## How Hecate CLI Commands Support Each Level

The commands remain the same as responsibility shifts from the analyst to a
reviewed workflow. Reading the Markdown documentation needs no installation;
use the CLI to create managed records and preserve IDs and metadata.

| Task | Command |
| --- | --- |
| Create a hunt | `hecate-agent hunt new` |
| Retrieve history | `hecate-agent hunt search "keywords"` |
| Load context | `hecate-agent context --hunt H-0001 --format json` |
| Check structure | `hecate-agent hunt validate` |
| Review coverage | `hecate-agent hunt coverage` |

See [Getting Started](getting-started.md) for installation links and a first hunt.

## Level 1: Documented Hunts

Record each hunt using [LOCK](lock-pattern.md): motivation, expected behavior,
bounded checks, findings and lessons. Include the author, date, scope, data sources
and ATT&CK mappings in the generated frontmatter. Record negative findings and
unresolved questions as well as confirmed results.

Start with a few recent hunts and establish peer review. A structurally valid
record can still contain an unsupported claim or an ineffective query.

## Level 2: Searchable Memory

Provide three kinds of context in the selected workspace:

- `knowledge/environment.md`: actual sources, field mappings, coverage and gaps.
- `knowledge/hunting-knowledge.md`: analytical methods and local lessons.
- `AGENTS.md`: assistant workflow, permissions and review requirements.

Use search and context export to reuse past work. Similarity search can suggest
related hunts, but a score alone does not establish duplication or coverage.
AI-generated hypotheses require prior research and review of source support.

Progress when an assistant can cite relevant history without inventing available
telemetry. Neither context files nor a model replace verification.

## Level 3: Generative Capabilities

Connect one approved SIEM, endpoint, intelligence or ticketing integration at a
time. The analyst directs the workflow; configured tools perform authorized actions.
See [integration setup](../integrations/README.md) and the [MCP catalog](../integrations/MCP_CATALOG.md).

Verify credentials, query syntax and field mappings. Require time bounds, a
count-first gate and result limits. Keep live execution, ticket creation and
publication behind their respective approval boundaries. An integration mentioned
in a guide is not automatically installed or authorized.

Progress when results and actions are reproducible and traceable to the approved
request, with failures reported accurately.

## Level 4: Agentic Workflows

Schedule reviewed intake, drafting or existing-hunt sweeps within quotas and
credential boundaries. Separate drafting, validation, notification and execution.
Models propose content; deterministic checks and analyst review govern its use.

[Level 4 workflows](level4-agentic-workflows.md) distinguishes conceptual agent
roles from implemented Runner processes. Start with one isolated workflow and
exercise provider failure, retry, interruption and recovery before expanding it.

A maturity level grants no additional permissions. Synthetic replay, local BAS
observation, native query matches and correlated fired alerts remain separate
forms of evidence.

## Choosing Your Level

Choose the smallest change that addresses an observed problem:

| Problem | Next step |
| --- | --- |
| Hunt history is lost | Adopt LOCK records and ownership |
| Analysts repeat past work | Improve search and environment context |
| Manual tool handoffs dominate | Add one approved integration |
| Reviewed workflows repeat reliably | Add scheduling, quotas and recovery |

Measure review effort, rejected claims, useful findings and recovery behavior
against your own baseline. Adoption time depends on access, data quality and team
capacity; a fixed timetable or draft count is not a maturity test.
