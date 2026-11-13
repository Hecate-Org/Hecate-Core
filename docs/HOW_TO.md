# Core operating and developer recipes

Use the installed `hecate-agent` from your active development environment. Export
`HECATE_WORKSPACE` before invoking it; outputs belong to that workspace. See
[onboarding](ONBOARDING.md) and [configuration](CONFIGURATION.md).

## Browse before creating

```bash
hecate-agent hunt list
hecate-agent hunt search "credential access"
hecate-agent context --hunt H-0001 --format json
hecate-agent similar "hypothesis keywords"
```

Replace example IDs with actual workspace IDs. Similarity search needs its extra.

## Create a source-backed hunt

```bash
hecate-agent research new --topic "Your topic"
hecate-agent agent run hypothesis-generator --threat-intel "Observed source behavior" --research R-0001
hecate-agent hunt new --title "Reviewed hypothesis" --technique T1003.001 --research R-0001 --non-interactive
hecate-agent hunt validate H-0001
```

Configure the model/search features first. Link the actual research ID returned
by the command. Inspect generated source claims and scope before execution.

## Export detection content

```bash
hecate-agent hunt promote --hunt H-0001 --output sigma
hecate-agent hunt promote --hunt H-0001 --output spl
hecate-agent hunt promote --hunt H-0001 --output kql
```

These export modes are `sigma`, `spl`, `kql` and `detection`. Native Sigma
transpilation uses `hecate_agent.api.transpile_sigma_rule(rule_yaml, targets=[...])`;
there is no top-level `hecate-agent sigma convert` command. Saved-query deployment
and live execution are separate Runner workflows with their own configuration.

## Reference data and monitoring

```bash
hecate-agent attack update
hecate-agent attack status
hecate-agent attack lookup T1003.001
hecate-agent monitor
```

Downloading reference data requires network access. Monitor uses the selected
workspace and must be reopened after source changes.

## Evaluate and contribute

From Hecate-Core with the developer venv active:

```bash
python -m pytest tests/ -q
python scripts/sync_docs.py --check
```

Default tests block operator dotenv files and unmocked network traffic. Explicit
external checks require `-m network`. See [evals/README.md](../evals/README.md) for
reviewed gold scoring; model-assisted pipeline replay can consume tokens and must
use a scratch workspace.

For existing-hunt sweeps, CTI feeds, Slack, service installation, token metrics,
public review and BAS, use [Runner's operating guide](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/HOW_TO.md).
