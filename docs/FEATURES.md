# Core feature boundaries

| Capability | What it provides | Limit |
| --- | --- | --- |
| Hunt and investigation management | LOCK documents, search, metadata, coverage, exports | Metadata is not live validation evidence |
| Research and hypothesis agents | Source-backed context and model-assisted drafts | Requires configured models; review inferences and missing evidence |
| ATT&CK lookup | Cached STIX metadata and a limited fallback | Download reference data for complete technique details |
| Sigma drafting/review | Candidate rules, syntax/logsource/grounding checks | Does not establish production field mappings or false-positive rates |
| Native conversion | Backend-specific pySigma conversion and validation | Supported targets depend on installed backends and rule constructs |
| Python API | In-process entry points in `hecate_agent/api.py` | Inspect actual input/output signatures rather than assuming CLI parity |
| Monitor | Workspace pipeline, replay, BAS and SIEM state | Reopen after source changes; legacy claims without proof do not count as alerts |
| MCP | Optional server/tool entry points | Requires MCP extras and configured integrations |

Current native target identifiers are `splunk_spl`, `sentinel_kql`,
`crowdstrike_cql`, `rapid7_leql`, `sentinelone_s1ql` and `elastic_eql`.
Conversion, saved-query deployment and live query execution have different
capability matrices; a conversion target is not necessarily an execution provider.

Scheduling, feeds, execution approvals, BAS and publishers are provided by Runner.
See the [platform feature guide](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/FEATURES.md),
[CLI reference](CLI_REFERENCE.md), [configuration](CONFIGURATION.md) and
[Python API](../hecate_agent/api.py).
