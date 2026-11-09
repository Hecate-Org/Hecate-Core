"""Telemetry mapping: normalized OCSF fields, mapped to the environment's fields (deep-dive item #9)."""

from pathlib import Path

import pytest

from hecate_agent.agents.llm.hunt_researcher import ResearchOutput, ResearchSkillOutput
from hecate_agent.commands.research import _generate_research_markdown
from hecate_agent.core.ocsf_fields import clear_cache
from hecate_agent.core.telemetry_mapping import (
    documented_data_sources,
    environment_fields,
    map_findings,
    normalize_field,
)

ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENT = """## Security & Monitoring Tools
### SIEM
- **Product:** Verified test SIEM
- **Coverage:** Process execution, file events and network connections
- **Common Fields:**
  - Endpoint: `process_name`, `parent_process`, `command_line`, `user`, `dest`
  - Network: `src_ip`, `dest_ip`
### EDR
- **Product:** [To be configured - e.g., CrowdStrike Falcon, Microsoft Defender, Carbon Black]
- **Telemetry:** Registry modifications
"""

#: R-0616's Key Fields, as the model wrote them; the validator flagged all six.
R0616 = [
    "process_activity.process.name: execution of the Go loader",
    "process_activity.parent_process.name: the parent that launched it",
    "network_activity.dst_endpoint.ip: connections to 38.207.178.192",
    "network_activity.dst_endpoint.hostname: connections to named hosts",
    "file_activity.file.path: creation of the decoy document",
    "process_activity.process.cmd_line: command-line arguments",
]


@pytest.fixture(autouse=True)
def _workspace(monkeypatch):
    monkeypatch.setenv("HECATE_WORKSPACE", str(ROOT))
    clear_cache()
    yield
    clear_cache()


@pytest.mark.parametrize(
    ("written", "path"),
    [
        ("process_activity.process.name", "process.name"),
        ("process_activity.parent_process.name", "process.parent_process.name"),
        ("network_activity.dst_endpoint.ip", "dst_endpoint.ip"),
        ("file_activity.file.path", "file.path"),
        ("process.cmd_line", "process.cmd_line"),
        ("process.execution.command_line", None),
    ],
)
def test_an_event_class_prefix_is_not_a_reason_to_reject_a_field(written: str, path: str) -> None:
    assert normalize_field(written) == path


def test_r0616s_fields_are_valid_and_mapped_to_the_environments_own_fields() -> None:
    mapped = map_findings(R0616, ENVIRONMENT)
    assert mapped.removed == []
    fields = [f.split(":", 1)[0] for f in mapped.findings]
    assert fields == [
        "`process.name` → `process_name` (Endpoint) (written as `process_activity.process.name`)",
        "`process.parent_process.name` → `parent_process` (Endpoint) (written as `process_activity.parent_process.name`)",
        "`dst_endpoint.ip` → `dest_ip` (Network) (written as `network_activity.dst_endpoint.ip`)",
        "`dst_endpoint.hostname` → unmapped",
        "`file.path` → unmapped",
        "`process.cmd_line` → `command_line` (Endpoint) (written as `process_activity.process.cmd_line`)",
    ]


def test_the_environments_common_fields_are_read() -> None:
    documented = environment_fields(ENVIRONMENT)
    assert documented["Endpoint"] == ["process_name", "parent_process", "command_line", "user", "dest"]
    assert "dest_ip" in documented["Network"]


def test_without_an_environment_profile_every_field_is_unmapped() -> None:
    (finding,) = map_findings(["process.cmd_line: arguments"], "").findings
    assert "unmapped" in finding


def test_availability_counts_only_configured_telemetry_sections() -> None:
    """The template lists registry modifications under an EDR product still "[To be configured]",
    and names registry run keys among its priority TTPs; neither documents registry telemetry."""
    assert documented_data_sources(ENVIRONMENT) == {
        "process_execution": True,
        "file_operations": True,
        "network_connections": True,
        "registry_events": False,
    }


def test_a_configured_edr_section_documents_registry() -> None:
    profile = ENVIRONMENT.replace(
        "[To be configured - e.g., CrowdStrike Falcon, Microsoft Defender, Carbon Black]", "Sysmon 15"
    )
    assert documented_data_sources(profile)["registry_events"] is True


def _skill(name: str, **kwargs) -> ResearchSkillOutput:  # type: ignore
    return ResearchSkillOutput(skill_name=name, summary="s", key_findings=[], sources=[], confidence=0.5, **kwargs)


def test_the_research_document_lists_removed_fields_apart_and_says_unknown() -> None:
    mapped = map_findings([*R0616[:1], "process.execution.command_line: invented"], ENVIRONMENT)
    telemetry = _skill("telemetry_mapping", removed_fields=mapped.removed)
    telemetry.key_findings = mapped.findings
    output = ResearchOutput(
        research_id="R-0001",
        topic="t",
        mitre_techniques=[],
        system_research=_skill("system_research"),
        adversary_tradecraft=_skill("adversary_tradecraft"),
        telemetry_mapping=telemetry,
        related_work=_skill("related_work"),
        synthesis=_skill("synthesis"),
        data_source_availability=documented_data_sources(ENVIRONMENT),
        data_source_basis="environment",
    )
    markdown = _generate_research_markdown(output)
    section = markdown.split("## 3. Telemetry Mapping", 1)[1].split("## 4.", 1)[0]
    assert "NOT AN OCSF FIELD" not in section
    assert "- `process.name` → `process_name` (Endpoint)" in section
    assert "### Fields Removed (not in the OCSF reference)" in section
    assert "- `process.execution.command_line` (closest documented field: `process.cmd_line`)" in section
    assert "- Registry Events: Unknown: not documented in the environment profile" in section
    assert "Limited/Unavailable" not in section


def test_a_bare_network_endpoint_maps_to_both_sides() -> None:
    """The #9 replay's model wrote network_endpoint.ip, the object path, not an event's."""
    (finding,) = map_findings(["network_endpoint.ip: the C2 address"], ENVIRONMENT).findings
    assert finding.startswith("`network_endpoint.ip` → `dest_ip` / `src_ip` (Network; destination / source endpoint)")


def test_a_class_prefix_before_a_bare_attribute_means_the_class_object() -> None:
    """The A3 replay wrote file_activity.path for file.path."""
    assert normalize_field("file_activity.path") == "file.path"
    assert normalize_field("network_activity.path") is None  # no single object to assume


def test_unverified_starter_does_not_claim_any_telemetry_or_fields() -> None:
    starter = (ROOT / "knowledge" / "environment.md").read_text(encoding="utf-8")
    assert not any(documented_data_sources(starter).values())
    assert environment_fields(starter) == {}


def test_contract_requires_verified_status_and_complete_metadata() -> None:
    profile = """## Telemetry availability contract
| Source / event family | Status | Index/table + provider/channel | Field mapping | Asset/tenant coverage | Retention + ingestion lag | Evidence / date / owner |
|---|---|---|---|---|---|---|
| Endpoint process and lineage | verified | test-events / test-provider | `process_name`, `command_line` | test hosts | 7d / 5m | known-event query Q1 / 2026-11-09 / test owner |
| Registry events | verified | Unknown | `registry_value` | Unknown | Unknown | Not verified |
| Network connections | unknown | test-net | `dest_ip` | all test hosts | 1d | query Q2 |
"""
    assert documented_data_sources(profile) == {
        "process_execution": True,
        "file_operations": False,
        "network_connections": False,
        "registry_events": False,
    }
    assert environment_fields(profile) == {"Endpoint process and lineage": ["process_name", "command_line"]}
