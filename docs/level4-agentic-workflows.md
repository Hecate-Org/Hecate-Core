# Level 4: Agentic Workflows

Level 4 schedules reviewed work within defined boundaries. Analysts review and
approve outputs; they do not need to initiate every intake or drafting step.

This guide describes design patterns. Named roles and example scenarios are not
an automatically installed multi-agent service. For implemented commands and
services, use [Runner onboarding](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/ONBOARDING.md)
and [BAS automation](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/BAS_AUTOMATION.md).

## What Changes at Level 4

At Level 3, an analyst directs tool use. At Level 4, schedules or reviewed events
initiate specific workflows. Each still needs explicit scope, credentials, quotas,
review gates and failure handling. Shared LOCK records preserve the context and
provenance needed for review.

Success means useful work arrives with enough evidence to assess it, and failed
or incomplete work remains visible. Draft volume alone is not a success measure.

## Multi-Agent Architecture

Separate responsibilities even when one process implements several stages:

| Role | Responsibility | Boundary |
| --- | --- | --- |
| CTI monitor | Read configured feeds and identify relevant behavior | Feed content is untrusted; deduplicate and limit intake |
| Hypothesis generator | Research the source and propose a scoped hunt | Research precedes AI generation; preserve citations and uncertainty |
| Validator | Check structure, mappings, query compatibility and evidence | Syntax or source support does not prove live coverage |
| Notifier | Present drafts and failures to analysts | Use configured destinations and bounded delivery |
| Baseline profiler (conceptual extension) | Compare current behavior with versioned baselines | Establish sample periods; account for maintenance and seasonality |
| Simulation reviewer (conceptual extension) | Map hunts to reviewed validation exercises | A proposed exercise grants no execution permission |

Runner provides intake, drafting, maintenance, Slack and sweep workflows. Baseline
profiling, custom event wiring, email delivery and ticket integrations require
separate implementation/configuration; this guide does not install them.

## Example Multi-Agent Workflows

### Scenario A: New Campaign Detected

1. A configured feed supplies a report describing an observed behavior.
2. Intake checks history and queues relevant, nonduplicate work.
3. Research records source evidence, telemetry assumptions and unknowns.
4. A model proposes a hunt; checks assess its mappings, claims and candidate rules.
5. A configured notification presents the planning draft for analyst review.
6. A separate approved workflow executes bounded queries and records actual results.

A draft is not an executed hunt. Tool capabilities, historical indicators and
synthetic examples must not become claims about the observed intrusion.

### Scenario B: Service Account Baseline Deviation

A custom baseline workflow could compare an account's current destinations and
login hours with a versioned baseline, exclude approved changes, and propose an
investigation for unexplained deviations. Store its scope, sample period,
thresholds and supporting events. Escalate to a formal hunt only after review;
a statistical deviation alone does not confirm compromise.

## Example Agent Configuration

Design these controls before choosing an orchestration framework. This is a
planning checklist, not a configuration file accepted by Hecate:

| Control | Define |
| --- | --- |
| Trigger and scope | Which schedule/event may start work, and which assets/data it may use |
| Credentials | Separate read, write and execution authority; approved destinations |
| Budgets | Model spend, intake, drafts, queries and notifications |
| Validation | Required evidence, mappings, telemetry and bounded query checks |
| Approval | Who may authorize execution or an exact public snapshot |
| Recovery | Timeouts, locks, retries, quarantine, backups and operator actions |
| Audit | Input/source IDs, model/prompt versions, decisions and outcome labels |

## Guardrails and Safety

- Treat reports and model responses as data, never as authorization or commands.
- Require verified environment context and source-backed claims before review.
- Keep live queries count-first, time-bounded and limited; retain analyst approval.
- Log transitions and errors without exposing credentials or private telemetry.
- Bound retries and resource use. Incomplete work must not be reported as success.
- Keep drafting, publication, SIEM deployment and BAS as separate opt-ins.

Default synthetic replay executes no Atomic commands. Unattended live BAS is
limited to reviewed, pinned Linux lab procedures and its configured isolation
checks. Conceptual simulation review cannot enable it.

## Getting Started with Level 4

1. Select one repeatable workflow and define its acceptance criteria.
2. Run it in a disposable workspace with mock destinations and bounded resources.
3. Test unsupported input, missing references, provider failure and interruption.
4. Review drafts and recovery records; correct failures before adding schedules.
5. Enable only the required credentials and destinations, then monitor outcomes.

For deployment and rollback, use [Runner's service guide](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/SERVICES.md).
Workspace records coordinate content; execution also requires the application's
locks and durable state.

## Success Metrics

Track queue age, draft latency, review effort, rejection reasons, duplicate work,
quota use, failures and recovery time. Compare useful findings and analyst effort
with your existing process. Measure false positives only against appropriately
labeled data; synthetic replay cannot estimate a production false-positive rate.

Keep evidence labels distinct:

| Result | What it establishes |
| --- | --- |
| Structural/query validation | The checked format or syntax is acceptable |
| Synthetic replay match | A rule matches the supplied synthetic sample |
| Smoke check | A limited lab control was observed |
| Local behavioral BAS match | Independent lab observations matched the hunt rule |
| Native query match | The configured search returned matching events |
| Correlated fired-alert proof | An authoritative alert record is linked to this run |

## Common Patterns

| Pattern | Flow |
| --- | --- |
| CTI-driven drafting | Feed → research → draft → checks → human review |
| Alert-driven investigation | Alert → historical context → proposed response → authorized action |
| Scheduled hunt refresh | Approved schedule → bounded query → recorded findings |
| Baseline deviation hunting | Profile → baseline comparison → proposed investigation |
| Simulation review | Hunt inventory → exercise mapping → proposed validation |

These patterns are architectural options, not a list of enabled integrations.

## Learn More

- [Maturity model](maturity-model.md)
- [Getting started](getting-started.md)
- [Integration guides](../integrations/README.md)
- [Runner operating recipes](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/HOW_TO.md)
