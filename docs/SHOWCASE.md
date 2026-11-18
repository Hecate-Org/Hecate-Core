# Hecate Hunt Showcase

These [bundled sample hunts](../hecate_agent/data/hunts/) illustrate LOCK records.
Their actors, findings and metrics are sample content, not verified customer
incidents, measured product performance or production-ready detections.

## AI-Assisted Workflow Examples

Run research before asking a model to generate a hypothesis, then review its
source support and telemetry assumptions. See [Getting Started](getting-started.md)
for commands and [operating recipes](HOW_TO.md) for exports and validation.

## Hunt #1: macOS Information Stealer Detection

[Full record: H-0001](../hecate_agent/data/hunts/2026/Q1/H-0001.md)

| LOCK stage | What the example records |
| --- | --- |
| Learn | Browser/document collection creates a visibility gap around unsigned processes |
| Observe | A process accesses several sensitive directories rapidly and attempts a network connection |
| Check | Refine broad file-access searches using signature, process, path and timing context |
| Keep | Record supporting events, benign developer activity, remaining gaps and follow-up scope |

The lesson is to combine independent observations rather than equating unsigned
execution with compromise. A small sample with few false positives does not
establish a production false-positive rate.

## Hunt #2: Linux Crontab Persistence Detection

[Full record: H-0002](../hecate_agent/data/hunts/2026/Q1/H-0002.md)

| LOCK stage | What the example records |
| --- | --- |
| Learn | Cron changes are a possible persistence mechanism; legitimate jobs also need a baseline |
| Observe | Look for unexplained schedule changes, download commands and execution from temporary paths |
| Check | Correlate file changes, command contents, account context and maintenance windows |
| Keep | Separate the suspected miner from authorized backup activity and document missing telemetry |

The example shows why command names or account filters alone are insufficient.
Verify ownership and context before treating a cron job as attacker persistence.

## Hunt #3: AWS Lambda Persistence Detection

[Full record: H-0003](../hecate_agent/data/hunts/2026/Q1/H-0003.md)

| LOCK stage | What the example records |
| --- | --- |
| Learn | Unexpected functions, permissions and triggers warrant review against deployment baselines |
| Observe | Correlate function changes with IAM changes, API exposure and scheduled triggers |
| Check | Review the complete event chain, account provenance and known deployment automation |
| Keep | Preserve findings, uncertainty, logging gaps and planned control changes |

Adapt behavior mappings to the verified actions in your source. A cloud service
name or permission alone does not establish a specific ATT&CK technique.

## Key Takeaways Across All Hunts

Start with a baseline, refine the scope using observed behavior, and record why
filters were added. Preserve benign alternatives, negative results and gaps.
Use lessons from previous hunts without assuming their findings apply to a new run.

## Try These Hunts in Your Environment

1. Read the full example and identify its assumptions.
2. Verify your data sources, fields, ingestion and retention.
3. Adapt the queries and validate supported syntax; example pseudocode is not an executable query.
4. Obtain approval and run count-first, time-bounded checks with result limits.
5. Record your own evidence and review the outcome before any deployment.

Use the CLI to create new managed records. See [Getting Started](getting-started.md)
and the [LOCK template](../templates/HUNT_LOCK.md).
