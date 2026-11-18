# Getting Started with Hecate

Start by selecting a workspace, documenting a hunt and reviewing the result.
Models, live queries and background automation are optional additions.

## Step 1: Choose Your Setup Path

For a source installation, follow [Core onboarding](https://github.com/Hecate-Org/Hecate-Core/blob/main/docs/ONBOARDING.md)
or [Runner onboarding](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/ONBOARDING.md)
for the combined application. [Installation options](https://github.com/Hecate-Org/Hecate-Core/blob/main/docs/INSTALL.md)
cover prerequisites and optional dependencies.

You can read and use the LOCK documentation without Python. Use the CLI when
creating framework-managed records: it allocates IDs and writes the required
frontmatter. Browsing hunts and the offline demo need no model or API keys.

## Step 2: Explore the Structure

With the installed CLI available, select your workspace before running commands:

```bash
export HECATE_WORKSPACE=/absolute/path/to/your/workspace
hecate-agent hunt list
hecate-agent env check
```

Core contains the application code; the workspace contains your content:

| Path | Purpose |
| --- | --- |
| `hunts/`, `research/`, `queries/` | Hunt records, supporting research and detection content |
| `knowledge/environment.md` | Verified telemetry, field mappings, retention and gaps |
| `knowledge/hunting-knowledge.md` | Local hunting methodology and lessons |
| `AGENTS.md` | Assistant instructions and execution guardrails |
| `.env`, `.hecate/`, `logs/` | Private configuration and operational state |

Commands create content directories as needed. Seed an enterprise workspace with
reviewed catalog content and keep real credentials, telemetry and findings private.
A starter environment profile does not establish that a data source is available.

## Step 3: Document Your First Hunt (Level 1)

For a human-authored hypothesis, create a record interactively or supply its scope:

```bash
hecate-agent hunt new \
  --technique T1110.001 \
  --title "SSH Brute Force Detection" \
  --platform Linux \
  --tactic credential-access \
  --non-interactive
hecate-agent hunt validate
```

Complete the [LOCK sections](lock-pattern.md):

- **Learn:** Record the source, motivation and available telemetry.
- **Observe:** State a falsifiable behavior and expected benign alternatives.
- **Check:** Record bounded queries, approvals and actual results.
- **Keep:** Separate supported findings from unknowns and document next steps.

Review [worked examples](https://github.com/Hecate-Org/Hecate-Core/blob/main/docs/SHOWCASE.md)
for complete records. Preserve the generated YAML frontmatter; it supports search,
metrics and ATT&CK coverage. Structural validation does not prove a detection works.

## Step 4: Add AI Context Files (Level 2)

Complete `knowledge/environment.md` before requesting queries or hypotheses.
Adapt `AGENTS.md` and hunting guidance to your team's scope and review process.
Use existing work before creating a duplicate:

```bash
hecate-agent hunt search "credential access"
hecate-agent similar "SSH authentication failures"
hecate-agent context --hunt H-0001 --format json
```

Replace example IDs with IDs returned by `hunt list`. Similarity search needs its
optional dependency. See the [configuration reference](https://github.com/Hecate-Org/Hecate-Core/blob/main/docs/CONFIGURATION.md)
for models, endpoints and credentials.

Research must precede an AI-generated hypothesis. Configure the model and optional
search provider, then use the actual research ID returned by the first command:

```bash
hecate-agent research new --topic "SSH authentication abuse"
hecate-agent agent run hypothesis-generator \
  --threat-intel "Source-backed behavior" --research R-0001
hecate-agent hunt new --title "Reviewed hypothesis" \
  --technique T1110.001 --research R-0001 --non-interactive
```

Review source support, ATT&CK mappings and telemetry assumptions. Research without
web search is source-only synthesis, not independent corroboration. If required
research cannot run, report the limitation rather than silently skipping it.

## Step 5: Connect Tools (Level 3 - Optional)

Start with one integration from the [integration guides](../integrations/README.md).
Verify access and field mappings with a bounded, read-only query. Use count-first
checks, time bounds and result limits; obtain approval before live execution.

For existing catalog hunts, Runner's [sweep workflow](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/ONBOARDING.md#existing-hunt-execution)
is separate from CTI intake and new-hunt generation. Keep its query provider
`mock` while practicing.

## Step 6: Deploy Agents (Level 4 - Optional)

Automate one reviewed workflow at a time. Define its inputs, quotas, credentials,
review gates, failure handling and recovery before scheduling it. See
[Level 4 workflows](level4-agentic-workflows.md) for design patterns and links to
the implemented Runner services.

A generated rule, synthetic match, native query match and fired SIEM alert are
different outcomes. Record the evidence each check actually provides.

## Common Tasks

| Task | Command |
| --- | --- |
| Read a hunt | `hecate-agent context --hunt H-0001 --format json` |
| Validate records | `hecate-agent hunt validate` |
| Review metrics or coverage | `hecate-agent hunt stats` / `hecate-agent hunt coverage` |
| Inspect ATT&CK data | `hecate-agent attack status` / `hecate-agent attack lookup T1003.001` |
| Download reference data | `hecate-agent attack update` |
| Inspect command options | `hecate-agent <command> --help` |

For complete options, use the [CLI reference](CLI_REFERENCE.md). For adoption and
team ownership, see [Using Hecate](https://github.com/Hecate-Org/Hecate-Core/blob/main/docs/USING_HECATE.md).
