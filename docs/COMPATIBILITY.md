# Hecate Compatibility Policy

This document establishes the version compatibility, workspace format guarantees, and coupling policy between **Hecate-Core** (`hecate-agent`) and **Hecate-Runner**.

---

## 1. Version Compatibility Policy

Hecate-Core and Hecate-Runner follow Semantic Versioning (`MAJOR.MINOR.PATCH`):

* **MAJOR (`X.0.0`)**: Incompatible workspace format changes, major architectural redesigns, or breaking API/CLI modifications.
* **MINOR (`0.Y.0`)**: Backwards-compatible additions to CLI commands, new MCP tools, new agents, or additive fields in frontmatter/LOCK schema.
* **PATCH (`0.0.Z`)**: Backwards-compatible bug fixes, performance optimizations, and documentation updates.

### Core and Runner Compatibility Matrix

| Hecate-Core (`hecate-agent`) | Supported Hecate-Runner | Workspace Format Version | Status |
|---|---|---|---|
| `>= 0.17.0, < 0.18.0` | `0.1.x` | `v1` (LOCK + YAML Frontmatter) | Current |
| `>= 0.16.0, < 0.17.0` | `0.1.x` | `v1` (LOCK + YAML Frontmatter) | Supported |
| `< 0.16.0` | Not supported | Pre-standard | Deprecated |

> **Recommendation**: Always run Hecate-Runner with a matching minor branch of Hecate-Core (`pip install "hecate-agent[all]"`).

---

## 2. Division of Labor: Core vs. Runner

| Scenario | Recommended Component |
|---|---|
| **Manually write hunts and conduct research** | **Hecate-Core** (`hecate-agent hunt new`, `hecate-agent research new`) |
| **Automatically pull CTI and draft hunts** | **Hecate-Runner + Core** (`hecate-runner cycle run`) |
| **Want a live monitoring dashboard** | **Core's monitor command** (`hecate-agent monitor`) |
| **Export hunts to detection rules** | **Core's promote command** (`hecate-agent hunt promote --output sigma`) |
| **Assess program maturity level** | **Core's maturity assess** (`hecate-agent maturity assess`) |

---

## 3. Workspace Format Stability Guarantees

Hecate treats workspace content as human-and-machine-readable source of truth. The following guarantees apply:

### 1. Directory Structure
* `hunts/`: Hunt files stored in dated folders `hunts/{YYYY}/{QX}/H-XXXX.md` or flat `hunts/H-XXXX.md`. Both formats are supported for discovery.
* `research/`: Research documents stored as `research/R-XXXX.md`.
* `queries/`: SIEM/EDR query files (`.spl`, `.kql`, `.eql`, `.cql`) and candidate Sigma rules (`sigma.yml`).

### 2. Hunt Document Format (LOCK Pattern)
* **YAML Frontmatter**: Delimited by `---`. Additive fields are permitted without breaking compatibility. Mandatory fields: `id`, `title`, `status`, `tactics`, `techniques`.
* **LOCK Sections**: Markdown headings (`## Learn`, `## Observe`, `## Check`, `## Keep`) must remain present for parser compatibility.
* **Queries in Check**: Extracted from fenced code blocks (```` ```spl ... ``` ```` or ```` ```kql ... ``` ````).

---

## 4. Release Annotation Policy

To avoid silent breakage across independent checkouts and Runner pipelines:

1. **Tagging Breaking Changes**:
   * Any change affecting hunt discovery, frontmatter keys, or LOCK parsing will be prominently tagged in release notes with `[BREAKING: WORKSPACE]`.
   * Any CLI argument signature change or MCP tool schema change will be tagged with `[BREAKING: CLI]` or `[BREAKING: MCP]`.

2. **Deprecation Windows**:
   * Deprecated CLI flags and functions will emit warnings for at least one minor release cycle before removal.

3. **Release Artifacts**:
   * Every GitHub Release attaches tested wheels (`.whl`) and source tarballs (`.tar.gz`) verified via `twine check`.
