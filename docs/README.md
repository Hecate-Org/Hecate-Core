# Hecate Documentation

Start with [onboarding](ONBOARDING.md) for installation or
[Getting Started](getting-started.md) for your first workspace and hunt.

## Choose a Guide

| Need | Guide |
| --- | --- |
| Install Core or choose extras | [Installation](INSTALL.md) |
| Set providers, credentials, workspace or templates | [Configuration](CONFIGURATION.md) |
| Find commands and options | [CLI reference](CLI_REFERENCE.md) |
| Follow common command sequences | [Operating recipes](HOW_TO.md) |
| Adopt Hecate as a team | [Using Hecate](USING_HECATE.md) |
| Understand the hunt record | [LOCK pattern](lock-pattern.md) |
| Choose the next capability | [Maturity model](maturity-model.md) |
| Design scheduled workflows | [Level 4 patterns](level4-agentic-workflows.md) |
| Review illustrative records | [Showcase](SHOWCASE.md) |
| Understand package/workspace boundaries | [Architecture](ARCHITECTURE.md), [compatibility](COMPATIBILITY.md) |
| Configure Runner operations | [Runner onboarding](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/ONBOARDING.md) |

## Core Framework Docs

This directory is the source of truth for framework guides. The following have
matching copies under `hecate_agent/data/docs/` for installed packages:

- [Getting Started](getting-started.md)
- [LOCK pattern](lock-pattern.md)
- [Maturity model](maturity-model.md)
- [Level 4 workflows](level4-agentic-workflows.md)
- [CLI reference](CLI_REFERENCE.md)
- [Environment profile](environment.md)
- [Why Hecate?](why-hecate.md)

After editing one of these, run `python scripts/sync_docs.py`, then
`python scripts/sync_docs.py --check`. Other guides here are repository-facing.
Workspace copies under `prompts/`, `templates/` and `integrations/` may intentionally
differ from the defaults shipped in `hecate_agent/data/`.
