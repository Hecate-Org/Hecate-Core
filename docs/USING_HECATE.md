# Using Hecate in Your Organization

Use LOCK records to preserve hunt context and lessons. Add search, models and
automation where they solve an operational problem. LOCK can document work done
under PEAK, SQRRL or another hunting methodology.

## How to Adopt Hecate

1. Follow [onboarding](ONBOARDING.md) and select a private enterprise workspace.
2. Copy reviewed catalog content and starter knowledge into it.
3. Complete `knowledge/environment.md` with verified telemetry and field mappings.
4. Adapt `AGENTS.md` and `knowledge/hunting-knowledge.md` to your review process.
5. Document a few hunts, review their usefulness, then add capabilities using the
   [maturity model](maturity-model.md).

Use the CLI to create managed records and allocate IDs. Search past work before
creating a new hunt. AI-generated hypotheses require prior research; model output
and generic reference data are not evidence of enterprise coverage.

Keep credentials, private telemetry, findings, `.hecate/` and logs out of public
Git history. Core and Runner use the same selected workspace; they do not
combine it automatically with Public or a sibling directory.

## Maintaining Environmental Context

| Content | Owner | Review trigger |
| --- | --- | --- |
| Tools, architecture and telemetry contracts | Infrastructure and security owners | Quarterly and after significant changes |
| Field mappings, coverage gaps and hunt lessons | Threat hunters | Findings, ingestion changes and newly identified gaps |
| Assistant permissions and workflows | Security/workflow owner | New tools, credentials or approval policies |
| Hunting methods | Hunting lead | Changes in team practice or analytical standards |

Record the source and date of coverage claims. Asset inventories and CMDB links
can help maintain the profile; automated imports still need review.

## Search and Team Scale

Start with `hunt list`, `hunt search` and `context`. Add similarity search when
keyword retrieval misses related work. Establish ownership and peer review before
introducing another index or automated workflow. Choose tooling based on measured
retrieval and review effort rather than a fixed hunt-count threshold.

## Customizing the LOCK Loop

Add peer review, management approval or a detection-engineering handoff where
needed. Preserve the distinction between a proposal, an executed query and a
supported finding. Follow the selected workspace's query limits and approval
policy before execution.

Put business scope, classification, owners and threat priorities in the workspace
profile or template. Use [template configuration](CONFIGURATION.md#hunt-template-hunt_templatej2)
for supported fields; retain IDs and metadata needed by validation and metrics.

## Integration Patterns

For catalog sweeps, CTI intake, Slack, publishing and BAS, follow
[Runner onboarding](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/ONBOARDING.md).
Each live integration needs its own credentials, destinations and approval boundary.
Keep mock execution while verifying setup.

Export reviewed hunt content with `hecate-agent hunt promote`; use Core's
`transpile_sigma_rule` API for native Sigma conversion. Exports do not deploy or
execute detections. Custom HEARTH, SOAR or ticketing adapters require separate
implementation; the repository does not supply generic conversion scripts.

## Sharing Back

Share redacted examples or reproducible issues when useful. Review privacy,
source attribution and redistribution rights before publishing any snapshot.
See [LICENSES.md](../LICENSES.md), [operating recipes](HOW_TO.md) and the
[CLI reference](CLI_REFERENCE.md).
