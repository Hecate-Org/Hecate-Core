# Compatibility and workspace contracts

## Core and Runner coupling

Runner imports Core in-process and declares `hecate-agent[all]` as a dependency.
That declaration is not a tested compatibility matrix for every historical Core
release. Use Core and Runner revisions tested together in one environment; record
commit IDs and resolved dependency versions for deployment. Current metadata is in
`pyproject.toml` and `hecate_agent/__version__.py`, not a manually maintained version
table. Installation does not require assuming that matching wheels are published.

For development, use the shared editable installation in [onboarding](ONBOARDING.md).
For reproducible deployment, pin reviewed source/artifact revisions and retain the
resolved environment. Verify your selected workflows before upgrading.

## Responsibility boundaries

| Workflow | Component |
| --- | --- |
| Hunt/research management, grounding, Sigma tools, monitor | Core |
| CTI generation cycle | Runner `run` / `daemon` plus Core |
| Existing-hunt sweeps without generation | Runner `sweep` plus a configured backend |
| BAS, Slack, publication and maintenance | Runner |
| Enterprise knowledge, credentials, content and private results | Selected workspace |

## Workspace format

Hunts use YAML frontmatter and LOCK sections. `hunt_id` is the canonical hunt ID
field. Validation depends on the command and document type; use
`hecate-agent hunt validate H-0001` rather than assuming a short field list covers
all requirements. Research IDs are `R-XXXX`; native queries and Sigma rules live
under the selected workspace's `queries/` layout. Current parsers discover dated
and flat hunt layouts; newly created paths depend on workspace configuration.

Optional/additive metadata is common. Do not remove unknown fields when updating
a document. Old verification labels are not proof of current alert firing;
readers require the relevant provider, fidelity and correlated evidence.

## Upgrade verification

- Review source/CLI changes and configuration stubs before updating.
- Run the default offline suites from each repo and check packaged docs with
  `python scripts/sync_docs.py --check` in Core.
- Revalidate provider/backend support and destination policies for enabled features.
- Restart long-running services and reopen terminal monitors after updates.
- Keep private runtime state and backups outside public release artifacts.

A GitHub release or wheel should be used only when that exact artifact exists
and has been reviewed; do not assume an unversioned `latest` wheel filename.
