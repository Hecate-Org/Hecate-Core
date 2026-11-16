# Gold sets

## Twenty-case model quality suite

The packaged [task suite](../hecate_agent/data/evals/model-quality-v2.yaml)
adds 20 frozen, deterministically scored cases alongside the three full-draft
gold cases below. It tests cold and grounded PowerShell recall, interpreter
disambiguation, Windows/Linux/macOS behavior mapping, benign administration,
authorized lab activity, unsupported claims, historical indicators, missing
telemetry, hostile source instructions, validation evidence, rule semantics,
bounded queries and corrected sources.

These are **task-level gold answers**, including authored synthetic controls and
summaries of existing reviewed cases. They are not 20 new incident reports or
full-pipeline replays. The repository operator approved all 20 expected answers
and question wordings, then approved the minimum score and hard-failure groups.
The [review record](../hecate_agent/data/evals/model-quality-v2-review.json)
binds that approval to the original and reviewed suite hashes. Version 2 keeps
the model-visible prompts, evidence and expected answers identical to version 1;
review metadata and failure severities change. The original version 1 fixture
is frozen for historical reports, including its original review-status snapshot.

Validate without a model, credentials or network:

```bash
hecate-agent eval-suite --validate-only
python -m pytest tests/core/test_model_quality.py -q
```

### Prompt profiles and reference-assisted diagnostics

The default `baseline-v1` system prompt is unchanged. Two opt-in candidate profiles
allow controlled instruction tests: `checked-v2` asks the model to verify the
identity of the observed interpreter/mechanism and include every requested field;
`complete-v3` adds only a short required-field completeness check. Neither supplies
technique IDs, case answers or reviewer notes. The 20 approved questions, source
excerpts and answers stay unchanged. Select a profile with `--prompt-profile` in
`eval-suite` or the comparison helper. Each report records the profile and prompt
hash; reports with different prompts cannot be combined in a model comparison.
Historical rescoring recognizes the original prompt hash and preserves it
automatically; `--rescore` cannot change profiles.

The initial Claude diagnostic missed the required scheduled-task `platform` field.
Both candidates passed 60/60 Claude answers over three repetitions on 2026-11-16.
Qwen scored 48/60 with `checked-v2` and 51/60 with `complete-v3`, including additional
critical failures. Neither candidate is adopted as a shared default. Candidate
profiles are opt-in benchmark instruction changes, not changes to production agent
prompts or model weights. These development-set results must not be presented as
independent evidence of general model improvement; use new cases before broader
adoption.

Qwen's AppleScript ID error persisted with the general instructions and with
reasoning enabled. A separate reference-assisted diagnostic supplies the complete
13-entry interpreter identity table from [MITRE's parent technique](https://attack.mitre.org/techniques/T1059/),
verified on 2026-11-16. It covers the two original failures and authored NSAppleScript
and JavaScript-for-Automation transfer controls. It passed 12/12 Qwen answers with
thinking disabled. The table is reference knowledge, not evidence that a behavior
occurred. It is intentionally supplied to the model, and is not derived from the
gold checks. All 13 sibling entries are included rather than a single suggested ID.

```bash
hecate-agent eval-suite --provider ollama --model qwen3.6:35b-a3b-q4_K_M \
  --suite hecate_agent/data/evals/model-quality-grounding-diagnostic-v1.yaml \
  --prompt-profile checked-v2 --repeats 3 --report grounding-diagnostic.json
```

This additional suite is an **agent-prepared diagnostic, not a reviewed release
suite**. Passing it does not fix or waive an unaided-recall failure in the default
suite, change the approved threshold, or authorize a model promotion. It illustrates
why production mappings should use the existing source-matched ATT&CK candidates
and subsequent evidence validation instead of relying on memorized IDs. Production
grounding requires the ATT&CK extra and an available STIX cache; check those in the
actual service environment. Raising reasoning effort alone did not fix the observed
error and substantially increased diagnostic latency.

Production prompt changes still need the full-pipeline checks below. These task
results alone do not establish production hunt quality or live detection behavior.

Run both configured production model families in isolated scratch processes:

```bash
.venv/bin/python scripts/compare_model_quality.py \
  --repeats 3 --output-root /path/to/private/evaluation-reports
```

The helper uses local `qwen3.6:35b-a3b-q4_K_M` and
`anthropic/claude-sonnet-4-5-20250929`, with no fallback between them. Supply
`ANTHROPIC_API_KEY` in the environment or use
`--credential-env-file /absolute/path/to/private.env`; it reads only that key,
without executing the file or loading its other credentials. `--local-only`
omits Claude. Override the model IDs explicitly when evaluating a replacement.
Install the LLM extras in the evaluation environment for the Claude run.

Each run gets a private directory with per-model reports, progress logs and an
offline `comparison.json`. Reports include per-case/per-repeat results, category
scores, pass/fail variation, wall-clock median/p95 latency including the first
call's loading, input/output token counts, suite/prompt hashes, scorer code hash
and provider model IDs. API cost is a token-price estimate, not an invoice.
Local API charges are zero; local GPU/electricity cost remains unmetered. Small
sample latency percentiles are descriptive, not performance guarantees.
`run-metadata.json` captures the installed Ollama digest and the run's limits;
`evaluator-source/` retains the evaluator, command, fixture and helper sources.

The remote estimate cap defaults to $1. Before each call the harness reserves a
conservative prompt/output estimate against the remaining cap. Unknown pricing,
missing remote usage and provider errors stop further requests. Unexecuted
cases remain in the denominator and cannot yield a passing gate. Rates come
from Core's cost table; validate them when changing models. Sonnet 4.5 standard
rates were checked against [Anthropic pricing](https://platform.claude.com/docs/en/about-claude/pricing)
on 2026-11-15. Discounts, cache billing, taxes, regional premiums and unknown
charges are not measured, so this is not a strict invoice spending guarantee.

Default acceptance requires at least 85% of case/repetition answers to pass,
zero critical failures, and a complete run. Each case passes only when all its
checks pass. The approved policy makes **every wrong ATT&CK mapping**,
unsupported security finding/claim, unsafe action and invalid/missing required
output field a hard failure. Benign/authorized verdicts and validation-proof
claims are included. Other scored metadata errors still lower the overall score.
The reviewed suite refuses a `--fail-under` below 0.85 and refuses to weaken
tagged hard-failure checks. Higher thresholds are allowed. A high aggregate score
cannot override these blockers. One JSON object, optionally
inside a single complete Markdown JSON fence as accepted by production parsing,
is allowed. Duplicate-key, type, missing/extra-field and exact-set checks prevent
keyword/format shortcuts. Arbitrary prose containing JSON is rejected. Accepted
fenced answers are counted separately. The
adversarial case tests the model's answer only; it cannot establish security of
tool authorization or the wider application.

For direct runs with an explicitly prepared evaluation environment:

```bash
hecate-agent eval-suite --provider ollama --model qwen3.6:35b-a3b-q4_K_M \
  --repeats 3 --report qwen.json
hecate-agent eval-suite --provider litellm \
  --model anthropic/claude-sonnet-4-5-20250929 --repeats 3 --report claude.json
hecate-agent eval-compare qwen.json claude.json
```

Direct CLI calls use the selected environment; use the helper for environment
isolation. Reports refuse to overwrite an existing path. Failed reports are
retained. No command changes routing, writes demotion gates, publishes content,
executes BAS or writes into a production workspace when using the helper.

When `--report` is supplied, the destination and its `.progress.jsonl` sidecar
are exclusively created with private permissions **before** provider setup or
calls. Invalid paths and competing writers fail before spending model tokens.
Every result checkpoint is flushed to disk. Ctrl+C or normal termination saves
a failed partial report and exits 130; a hard kill may leave an incomplete report
and its durable checkpoints, which cannot pass comparison. Helper subprocess
timeouts return failure with retained logs and finished metadata; use
`--timeout-seconds` to change the per-model deadline (default 7200).

After correcting a scorer, re-score **both** saved response sets offline rather
than changing answers or paying for new calls:

```bash
hecate-agent eval-suite --rescore old-report.json --report rescored-report.json
```

This requires the exact original suite and system prompt, preserves historical
latency/usage/cost, records the original report digest, and makes zero model
calls. Keep the originals. Scoring version 2 accepts a complete JSON fence,
matching production parsing; version 1 rejected it. Reports with different
scoring versions cannot be compared until both are rescored consistently.
The default suite is now version 2. To rescore a historical version 1 report,
explicitly supply `--suite hecate_agent/data/evals/model-quality-v1.yaml` from
the source checkout. A report cannot silently migrate to a different suite or
policy hash. Re-evaluate both models on the reviewed version 2 suite to create
new release artifacts. An offline analysis of unchanged saved answers may show
policy impact, but it must be labeled as such rather than a new live model run.
Scoring version 3 additionally enforces recursive type equality, bounded inputs
and report consistency. Comparison checks the unique case/repetition schedule,
per-case checks, summary, gate, token/cost totals and timing against each other.
Reports are local evidence, not signed attestations: validation does not prove
authenticity against someone who forges the entire artifact. Both version 1
and version 2 reports can be rescored with their original frozen suite. Live
parameter overrides are rejected during offline rescoring.

Resource limits are 1 MiB per suite, 64 MiB per saved report, 64 KiB per answer,
16 MiB total retained answer text, 1000 cases, 10 repetitions and 32 levels of
suite nesting. Suites reject duplicate keys, YAML aliases, non-finite numbers
and non-JSON expected values. Configured local model context bounds are checked
before calls. Invalid usage, changed model identities or violated token limits
stop further requests; known usage/cost is retained even for rejected answers.

### Offline stress and failure tests

```bash
.venv/bin/python scripts/stress_model_quality.py --output-root /path/to/private/stress-results
```

The repeatable default workload uses 10,000 synthetic provider calls and 50,000
seeded adversarial inputs. Real CLI subprocesses talk only to a temporary fake
Ollama server bound to `127.0.0.1`: eight processes contend for one output, four
run independently, and rate-limit, timeout and termination faults are injected.
No GPU inference, external API credit or production workspace is used. Timings
and Python memory measurements describe evaluator overhead, not model speed.

### Model and prompt release checklist

1. Run the offline suite validation/scorer tests in normal CI. No live model
   calls, model downloads or API credentials are added to regular CI.
2. Review/freeze the cases before a candidate run. Keep candidate evaluation
   cases separate from examples used to tune prompts; expand with new unseen
   cases as the existing set becomes familiar.
3. Run baseline and candidate on the **same** suite, system prompt, temperature,
   token limit and repetition count. For local runs, record the installed
   Ollama model digest as well as its mutable tag. Keep the inference settings
   and hardware/load context with the artifacts.
4. Run `hecate-agent eval-compare baseline.json candidate.json --check` for each
   changed model. Exit 1 means a failed candidate quality gate or a baseline-passing
   case regressed. A failing baseline does not block an improved passing candidate.
   A Qwen-versus-Claude comparison is descriptive; it is not by itself
   an instruction to change model routing.
5. For production prompt/pipeline changes, also replay the **three full-pipeline
   cases below**, using a separately configured scratch environment with live
   publication/deployment/execution disabled. Task-suite prompts do not exercise
   production generation prompts. Inspect the resulting drafts/rules; scalar
   scores alone do not establish source relevance or detection effectiveness.
6. Attach private evaluation artifacts and the reviewed decision to the release
   record. Changes to the suite/scorer require re-running both sides; comparison
   refuses mismatched suite, system-prompt hashes or generation parameters.

Live evaluation remains an explicit local/manual release check. It is not a new
scheduled Actions job or an automatic production model demotion.
The manual LLM demotion workflow now requires the reviewed 20-case suite to pass
before it can write any legacy per-capability stamp. Its default threshold is
0.85; a failed prerequisite leaves the stamping step skipped. Legacy ten-question
spot checks alone are not approval under the reviewed release policy.

## Full-pipeline draft gold sets

A gold set is the reviewed answer for one piece of CTI. Scoring a drafted hunt
against it measures a pipeline change instead of judging it by eye, and
nothing in the scoring calls a model, so two scores are comparable.

| Case | Gold set | Built from | Baseline |
|---|---|---|---|
| VShell via fake-resume lure | `gold/vshell-fake-resume.yaml` | the H-0618 deep-dive review (`docs/H-0618_DEEP_DIVE.md`, removed once its recommendations were implemented; in git history) | 23/71 checks (32.4%), technique recall 1/11 |
| ClickFix macOS stealer (Huntress) | `gold/macos-clickfix-stealer.yaml` | the Huntress report | 39/55 checks (70.9%), technique recall 2/12, on the pipeline as of 2026-09-28 before the macOS/Unix fixes (no pre-change baseline); 53/55 after them; 54/55 with rules from quoted commands. The `history-wiped` detection expected a shell builtin in a process command line, which no process event records; it was replaced on 2026-09-29 by `loader-fetched` (the `curl` fetch of the loader) |
| Redis cryptomining botnet (hunt.io) | `gold/redis-cryptomining-botnet.yaml` | the hunt.io report, written before any run | 40/53 checks (75.5%), technique recall 2/9, on the pipeline as of 2026-09-29; 53/53 on 2026-10-03, after server-side tradecraft joined the technique catalog, ports and cron paths were read from the report's tables, token and fingerprint "hashes" were typed as non-files, the page's second copy of the article was dropped, and sentences about the operator's own machine stopped counting as victim evidence. One of those 53 comes from a scorer change made the same day: see "What is scored" |

The baseline is the H-0618 draft reviewed in the deep dive, frozen in
`tests/fixtures/gold/vshell-fake-resume/` and locked by
`tests/core/test_gold_eval.py`.

## Scoring a draft

```bash
hecate-agent eval-gold evals/gold/vshell-fake-resume.yaml hunts/2026/Q3/H-0618.md
hecate-agent eval-gold GOLD DRAFT --output json > after.json   # for diffing runs
hecate-agent eval-gold GOLD DRAFT --fail-under 0.6             # exit 1 below 60%
```

Rules are read from `<workspace>/queries/<hunt_id>/`, or from the YAML blocks
embedded in the draft when that directory is absent. `--queries DIR` overrides
both.

## Scoring a pipeline change

Replay the gold set's exact CTI through one real cycle in a scratch workspace,
then score the draft it produces. Run it once before the change and once after.

`replay.py` does both. Run it with the Runner's interpreter:

```bash
cd ../Hecate-Runner
.venv/bin/python ../Hecate-Core/evals/replay.py redis-cryptomining-botnet
.venv/bin/python ../Hecate-Core/evals/replay.py vshell-fake-resume --workspace /tmp/gold-vshell --json score.json
```

It builds a blank scratch workspace, runs one cycle on the case, prints the
score with every failed check, and keeps the workspace so the draft, the rules
and `logs/orchestrator.log` can be read. The item comes from the case's saved
OTX pulse in `pulses/`, so it carries the feed's indicator list as a live
cycle would; its text is the gold set's `source.cti`. A cycle fetches the
report and calls the workspace's model: 10 to 20 minutes on the local one.

The same by hand, through the file queue. This passes the text only, without
the feed's indicator list, so its scores are not comparable with `replay.py`'s:

```bash
# 1. A scratch copy of the workspace, reset to a blank state
cp -a Hecate-Core /tmp/gold-ws
HECATE_WORKSPACE=/tmp/gold-ws hecate-runner reset --yes --no-archive

# 2. The gold CTI into the file queue
python -c "import yaml,sys; print(yaml.safe_load(open(sys.argv[1]))['source']['cti'])" \
  evals/gold/vshell-fake-resume.yaml > /tmp/gold-ws/cti_queue/next.txt

# 3. One cycle, reading only the file queue
HECATE_WORKSPACE=/tmp/gold-ws HECATE_RUNNER_CTI_PROVIDER=file hecate-runner run

# 4. Score the draft it wrote
hecate-agent eval-gold evals/gold/vshell-fake-resume.yaml /tmp/gold-ws/hunts/*/*/H-*.md
```

A single run carries model variance: repeat step 3 a few times before reading
a small difference as a real change.

## Saved outputs

`outputs/<case>/` holds one replay's output per case, for review without
running the pipeline: `draft.md` (the drafted hunt), `rules/` (its Sigma
rules), `research.md`, `trail.log` (what each pipeline step decided),
`score.json` (the `eval-gold` report) and `source.txt` (the primary report's
text as the pipeline fetched it). They are from 2026-10-03, on the code
committed as Hecate-Core `907b30c` and Hecate-Runner `3c3fad2`, and each
scores full marks. The Redis and VShell runs predate one fix in that commit:
rules whose titles shortened to the same file name overwrote each other, so
the Redis `rules/` lacks the rules for `/etc/cron.d/.redis-miner`,
`/etc/cron.d/redis-miner` and `/var/spool/cron/root`. To rescore one:

```bash
hecate-agent eval-gold evals/gold/<case>.yaml evals/outputs/<case>/draft.md --queries evals/outputs/<case>/rules
```

## Reviews

`reviews/` holds one file per model that reviewed the saved outputs against
their source reports, named `eval_<model>_<UTC timestamp>.md`. A review finds
what the scorer cannot: a rule that is valid but would not fire, a claim the
source does not support. New reviews go there, not in the repository root.

## What is scored

Every positive and every negative item is one check; the score is checks passed
over checks run.

| Dimension | Positive checks | Negative checks |
|---|---|---|
| techniques | each reviewed observed technique is mapped | each ruled-out technique is absent |
| platform | each expected platform is listed | each unsupported platform is absent |
| claims | required facts appear in the draft's own prose | forbidden assertions do not |
| indicators | artifacts appear where their role requires | artifacts do not appear where their role forbids |
| detections | each expected detection exists, with every field in one selection block | — |
| rule semantics | — | no field outside its log source category, no non-executable process image, no description promising matching the selection lacks |

Claims are checked against the draft's own writing only: rule YAML, the quoted
source CTI, the grounding table and the Primary Source Evidence table are
excluded, so the source can neither satisfy nor violate a claim on the draft's
behalf. The evidence table was excluded on 2026-10-03: it quotes the report
verbatim, and on the Redis case its row for a file from a separate, historical
directory ("deploy_meterpreter.sh Downloads and installs meterpreter.elf") was
scored as the draft claiming Meterpreter was installed. The Technique Evidence
table, which can quote the research document, is still scored.

An indicator that is a host name or an address is placed in a rule only where
it stands by itself, since 2026-10-05: a rule on `c2.example.net` does not
match `example.net`, so it does not place it, while a suffix selector
(`.example.net`) does. Before that the scorer looked for the value anywhere
in the rule's value, and on the Redis case a rule for the live hostname was
scored as carrying its forbidden parent domain. Other artifacts (paths, file
names, hashes) are still matched anywhere in the value.

## Technique recall and its denominator

Technique recall is reported separately, always as hits over a stated
denominator. The denominator is the gold set's `techniques.observed` list:
behaviours the primary source shows in that sample, each with its supporting
passage. It is not the draft's own list, and it excludes tool capability that
was not observed (for VShell, screen capture, persistence and lateral
movement, which the gold set lists as `forbidden`).

A draft ID matches an expected ID when they are equal or the draft ID is a
sub-technique of it. A parent ID matches an expected sub-technique only when
the entry sets `accept_parent: true`. IDs under `acceptable` earn no credit and
no penalty. IDs in none of the lists are reported as unreviewed, for a human to
add to the gold set.

## Writing a gold set

Start from a reviewed draft and its primary source. Keep every entry traceable:
give each observed technique its `evidence` passage, each forbidden item its
`reason`, and each indicator its `role` and `status`. Paste the exact CTI the
pipeline receives under `source.cti`, so reruns start from the same input.
Negative cases matter as much as positive ones: historical indicators,
artifacts that never exist as a process, capability without observed use, and
unsupported platforms are where drafts go wrong.
