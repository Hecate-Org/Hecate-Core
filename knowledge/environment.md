# Environment Profile — Unverified Adopter Template

**Profile status:** unverified-template
**Last verified:** Not verified
**Owner:** Not assigned
**Review cadence:** Set by the adopting team; recheck after sensor/schema changes.

This public starter establishes **no deployed platform, working endpoint, index,
retention period or coverage percentage**. Replace unknowns with locally verified
facts before using the profile to justify live-query scope or negative conclusions.
Keep credentials in the ignored `.env`, and private infrastructure details in an
appropriately controlled workspace. Never store secrets or raw customer events here.

## Workspace ownership and source of truth

The selected workspace owns this file. Core supplies the readers and Runner supplies
execution. Set `HECATE_WORKSPACE` to the absolute adopter workspace path when launching
from elsewhere. A Core checkout or bundled example is not evidence about that estate.
Threat intelligence describes reported targets and procedures; it cannot establish
that local hosts, platforms or telemetry exist.

## Asset and technology scope

| Scope | Verified value | Verification source / date / owner |
|---|---|---|
| Organization / tenant / account boundary | Unknown | Not verified |
| Included hosts, groups and critical assets | Unknown | Not verified |
| Operating systems / versions | Unknown | Not verified |
| Applications / exposed services | Unknown | Not verified |
| Cloud / SaaS / identity platforms | Unknown | Not verified |
| Exclusions and prohibited actions | Unknown | Not verified |
| Threat priorities and business impact | Unknown | Not verified |

## Telemetry availability contract

Use **verified**, **partial**, **unavailable** or **unknown** for each source. A
verified source still needs a window and asset-specific coverage check for a hunt.
Tool installation, API credentials and query conversion are not verification of
collection. Preserve the distinction between missing data and a negative event.

| Source / event family | Status | Index/table + provider/channel | Field mapping | Asset/tenant coverage | Retention + ingestion lag | Evidence / date / owner |
|---|---|---|---|---|---|---|
| Endpoint process and lineage | Unknown | Unknown | Unknown | Unknown | Unknown | Not verified |
| Authentication / identity / Kerberos | Unknown | Unknown | Unknown | Unknown | Unknown | Not verified |
| File events / persistence | Unknown | Unknown | Unknown | Unknown | Unknown | Not verified |
| Registry events / persistence | Unknown | Unknown | Unknown | Unknown | Unknown | Not verified |
| Network connections / DNS / proxy | Unknown | Unknown | Unknown | Unknown | Unknown | Not verified |
| Application / web server | Unknown | Unknown | Unknown | Unknown | Unknown | Not verified |
| Cloud control-plane / data-plane | Unknown | Unknown | Unknown | Unknown | Unknown | Not verified |
| SaaS audit | Unknown | Unknown | Unknown | Unknown | Unknown | Not verified |

For each verified row, record actual provider/channel, sensor/audit configuration,
normalized-to-native field mappings, timestamp semantics/timezone, collection and
ingestion coverage, null-field checks, sampling, truncation and query permissions.
Document real indexes/tables; do not copy names from a guide or from another team.

## Query access and validation

- **Backend / endpoint reference:** Unknown; configure credentials in `.env`.
- **Permitted indexes/tables and role:** Unknown.
- **Known-event control query / expected result:** Not supplied.
- **Last successful authentication/query check:** Not verified.
- **Event counts and required-field population for the relevant window:** Not verified.
- **Exact vs sampled counts / pagination and result limits:** Unknown.
- **Event time vs ingestion time and maximum observed lag:** Unknown.
- **Query time, row, cost and timeout limits:** Configure and verify locally.

Before live hunting, validate a bounded query against a known event, confirm sensor
health and field availability, and record the result and time of validation. Verify
positive and legitimate negative test cases for adapted queries. Log permission,
timeout, parsing and backend errors explicitly; they are not zero-match results.

## Baselines and benign explanations

No baseline is established. For each baseline record population/peer group, role,
timezone, observation window/sample size, seasonality, approved exceptions, last
review and owner. A familiar signer, account, parent, domain, scanner label or
business-hour schedule alone does not establish authorized behavior. Baseline and
suppression updates require the adopting team's review process.

## Visibility gaps and conclusion limits

Until verified above, coverage is **unknown**, not absent and not complete. Record
each gap's affected assets, event families and time window, impact on the hypothesis,
owner, remediation and follow-up. Never infer telemetry availability from a CTI report.

Zero matches in a successful, validated query mean **not observed within the tested
scope**. Missing, stale, inaccessible or insufficient telemetry yields **inconclusive**.
Do not claim an estate is clean, a hypothesis is disproved, or activity is benign on
the basis of a missing event or an unrepresentative/truncated sample.

## Execution and response authorization

- **Hunt owner / approver / escalation contact:** Not assigned.
- **Approved scope and schedule:** Not configured.
- **Read-only query / pivot budgets:** Set in the runner configuration.
- **Containment / BAS / deployment / suppression authorization:** Not granted by this template.
- **Evidence retention / sharing / redaction requirements:** Define locally.

Existing H files can be reviewed and adapted without enabling generation. Before
scheduled execution, verify their status, query compatibility, scope and approval.
Use the approval and execution controls documented in `.env.example`. A query result
or model verdict cannot authorize a response or widen the scope itself.
