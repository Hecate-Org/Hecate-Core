# Core onboarding

Core is the engine and CLI. Runner adds orchestration; Public is a shared catalog
and starter workspace. A private enterprise workspace holds your real environment
profile, credentials and findings. The organization `.github` repository is
optional and is not an application dependency.

## Source setup

For the full developer setup, use one environment and sibling repositories:

```bash
mkdir hecate-dev
cd hecate-dev
git clone https://github.com/Hecate-Org/Hecate-Core.git
git clone https://github.com/Hecate-Org/Hecate-Runner.git
git clone https://github.com/Hecate-Org/Hecate-Public.git
uv venv .venv
source .venv/bin/activate
uv pip install -e './Hecate-Core[all,dev]' -e './Hecate-Runner[dev]'
export HECATE_WORKSPACE="$PWD/Hecate-Public"
export HECATE_BIN="$PWD/.venv/bin/hecate-agent"
cd Hecate-Public
hecate-runner demo
hecate-agent hunt list
```

For Core-only installation and optional extras, see [INSTALL.md](INSTALL.md).
The complete shared-shell setup and existing-hunt/generation paths are documented
in [Runner onboarding](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/ONBOARDING.md).

## What Core reads and writes

Export `HECATE_WORKSPACE` to an absolute directory before running commands. Core
uses its `knowledge/environment.md` and `knowledge/hunting-knowledge.md`; changing
cwd to the Core source checkout does not replace an explicit workspace. Selected
workspace content includes `hunts/`, `research/`, `queries/`, investigations and
runtime records. Core also ships generic reference/templates in package data.
These references are not evidence of enterprise telemetry coverage.

Both applications consume user-provided credentials. Use the ignored workspace
`.env`, process environment or a secret store. Existing environment values win;
a cwd `.env` is a developer override. A symlink is optional and never created
by installation. Restart long-running applications after configuration updates.

## Start without models

```bash
hecate-agent hunt list
hecate-agent hunt search "credential access"
hecate-agent context --hunt H-0001 --format json
hecate-agent attack status
hecate-agent monitor
```

Use IDs from your workspace. A separate Core demo can be initialized with
`hecate-agent demo init --path /path/to/new-demo`; it creates example files.
The Runner demo above instead uses a temporary workspace.

## Add models only when needed

Configure `HECATE_LLM_PROVIDER`, `HECATE_LLM_MODEL` and provider credentials in the
selected workspace. Use `HECATE_LLM_BASE_URL` for the relevant endpoint. Research
web search has its own configuration. See [CONFIGURATION.md](CONFIGURATION.md).

```bash
hecate-agent research new --topic "Your source-backed topic"
hecate-agent agent run hypothesis-generator --threat-intel "Source-backed behavior" --research R-0001
hecate-agent hunt new --title "Reviewed hypothesis" --technique T1003.001 --research R-0001 --non-interactive
```

Review the generated output in the selected workspace. It is planning content;
synthetic matching, a promotion check or native query export does not prove live
coverage. To run existing catalog hunts without generating new ones, use Runner's
`sweep` workflow and a separately configured query provider.

## Tests and docs

```bash
# From Hecate-Core, with the development venv active
python -m pytest tests/ -q
python scripts/sync_docs.py --check
```

The default suite blocks operator dotenv files and unmocked external calls.
External-service checks require explicit `-m network` selection. See the
[documentation index](README.md) for canonical guides and package mirrors.
