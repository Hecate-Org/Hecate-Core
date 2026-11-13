# Hecate Documentation

New to the project? Start with the [onboarding guide](ONBOARDING.md).

## Core Framework Docs

The guides in this directory are the GitHub source of truth. Matching files in
`hecate_agent/data/docs/` ship with the Python package so installed workspaces
can use them. When a guide changes, copy it to the matching package-data path.
Run `python scripts/sync_docs.py` to update all mirrored framework guides, or
`python scripts/sync_docs.py --check` to report drift.

Only the guides listed below are mirrored. The repository's own `prompts/`,
`templates/` and `integrations/` are this workspace's working copies and may
differ from the defaults bundled under `hecate_agent/data/`.

- [Getting Started](getting-started.md)
- [The LOCK Pattern](lock-pattern.md)
- [Maturity Model](maturity-model.md)
- [Level 4: Agentic Workflows](level4-agentic-workflows.md)
- [CLI Reference](CLI_REFERENCE.md)
- [Environment Setup](environment.md)
- [Why Hecate?](why-hecate.md)

## Supplementary Docs (this directory)

Files here are GitHub/developer-facing and are not deployed into workspaces:

- [Onboarding](ONBOARDING.md) — What Hecate is for, how the two repositories fit, and a first run
- [Core architecture](ARCHITECTURE.md) and [system architecture](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/ARCHITECTURE.md) — Engine boundaries and Runner operating paths
- [Installation](INSTALL.md) — Install options and requirements
- [Configuration Reference](CONFIGURATION.md) — All config keys and environment variables
- [Using Hecate](USING_HECATE.md) — Adoption guide for teams
- [Hunt Showcase](SHOWCASE.md) — Illustrative sample hunts and workflows
