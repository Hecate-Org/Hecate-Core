# Hecate-Core

Hecate-Core (`hecate_agent`, installed as `hecate-agent`) supplies hunt management,
LLM agents, research, grounding checks, Sigma tooling, ATT&CK lookup and the
terminal monitor. Models propose candidates; deterministic checks grade their
structure, source support and query compatibility. These checks do not establish
that a production detection fired.

## Where things belong

| Component | Responsibility |
| --- | --- |
| Hecate-Core | Functional engine, CLI, Python API and bundled reference material |
| [Hecate-Runner](https://github.com/Hecate-Org/Hecate-Runner) | Scheduling, feeds, execution approvals, BAS, Slack and publication |
| [Hecate-Public](https://github.com/Hecate-Org/Hecate-Public) | Shared content catalog and starter workspace |
| Your private workspace | Enterprise knowledge, ignored credentials, operational results and state |

`HECATE_WORKSPACE` selects the workspace. Its `knowledge/environment.md` describes
verified telemetry, and its `knowledge/hunting-knowledge.md` supplies local hunting
guidance. Core's own reference files do not override those files just because
repositories are siblings. Credentials come from your environment, selected
workspace `.env`, or secret store; repositories do not supply working keys.

## Install from source

Use Python 3.11+ and uv. For Core alone:

```bash
git clone https://github.com/Hecate-Org/Hecate-Core.git
cd Hecate-Core
uv venv .venv
source .venv/bin/activate
uv pip install -e '.[all,dev]'
hecate-agent --version
```

For Core and Runner together, follow the shared environment instructions in
[onboarding](docs/ONBOARDING.md). No API keys are needed for hunt management,
reading the catalog or the offline demos. Model generation and external services
require their respective configuration. See [installation](docs/INSTALL.md).

## Explore a workspace

```bash
export HECATE_WORKSPACE=/absolute/path/to/Hecate-Public
hecate-agent hunt list
hecate-agent hunt search "credential access"
hecate-agent context --hunt H-0001 --format json
hecate-agent attack status
hecate-agent monitor
```

Replace `H-0001` with an ID in your workspace. `context --hunt` provides hunt
details; there is no `hunt show` command. ATT&CK metadata can be downloaded with
`hecate-agent attack update` and inspected with `attack lookup T1003.001`.

For an isolated Core example, use `hecate-agent demo init --path /path/to/new-demo`.
That command creates example files; do not initialize over operational content.
The separate `hecate-runner demo` uses an ephemeral fixture workspace.

## Generate or promote content

```bash
hecate-agent research new --topic "Your research topic"
hecate-agent agent run hypothesis-generator --threat-intel "Source-backed behavior" --research R-0001
hecate-agent hunt new --title "Reviewed hypothesis" --technique T1003.001 --research R-0001 --non-interactive
hecate-agent hunt promote --hunt H-0001 --output sigma
```

Research and model calls require configuration. Use actual research/hunt IDs
from the selected workspace. `hunt promote` supports `sigma`, `spl`, `kql` and
`detection` output modes; this is content export, not live SIEM deployment.
For native Sigma conversion to supported backends, use the Python API below.

## Python API

See [hecate_agent/api.py](hecate_agent/api.py) for current signatures. For example,
transpile a reviewed Sigma rule, replacing the example path:

```python
from pathlib import Path
from hecate_agent.api import transpile_sigma_rule

rule_yaml = Path("path/to/reviewed-rule.yml").read_text(encoding="utf-8")
results = transpile_sigma_rule(rule_yaml, targets=["splunk_spl", "sentinel_kql"])
print(results)
```

Conversion requires the corresponding pySigma extras/backends. It validates
syntax and compatibility, not ingestion, field mappings or production coverage.
`generate_hypothesis(threat_intel=..., workspace=...)` is model-assisted;
Sigma generation uses the API's `SigmaGenerationInput`/output contract and the
registered `sigma-generator` agent. Check the implementation before extending it.

## Tests and documentation

```bash
python -m pytest tests/ -q
python scripts/sync_docs.py --check
```

Unit test suites run offline with isolated operator environments. Explicit external
checks use `-m network`. Mock transports remain available for unit tests.

- [Onboarding](docs/ONBOARDING.md)
- [Installation](docs/INSTALL.md)
- [Configuration](docs/CONFIGURATION.md)
- [CLI reference](docs/CLI_REFERENCE.md)
- [Core architecture](docs/ARCHITECTURE.md)
- [Compatibility and workspace contracts](docs/COMPATIBILITY.md)
- [Documentation index and packaged-guide synchronization](docs/README.md)

Original code/documentation use the MIT license; see [LICENSES.md](LICENSES.md)
for imported content and attribution boundaries.
