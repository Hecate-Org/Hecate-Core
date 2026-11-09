"""Tests for atomic_red_team mapping and markdown rendering."""

import pytest
from hecate_agent.core.atomic_red_team import (
    ATOMIC_TESTS_MAP,
    get_atomic_tests,
    format_atomic_tests_markdown,
)


@pytest.mark.unit
class TestAtomicRedTeam:
    def test_get_atomic_tests_curated_technique(self):
        tests = get_atomic_tests("T1003.001")
        assert len(tests) >= 1
        assert any("lsass" in t["command"].lower() for t in tests)
        assert any("Sysmon" in t["telemetry"] for t in tests)

    def test_get_atomic_tests_base_technique_fallback(self):
        # T1055 has subtechniques, but T1055 itself is mapped
        tests = get_atomic_tests("T1055.001")
        assert len(tests) >= 1
        assert "T1055" in tests[0]["test_id"]

    def test_get_atomic_tests_unmapped_technique(self):
        assert get_atomic_tests("T9999.001") == []

    def test_an_unmapped_technique_is_named_not_given_a_placeholder_step(self):
        """H-0021 listed "# Execute controlled simulation of ..." as a test to run."""
        md = format_atomic_tests_markdown(["T9999.001"], platforms=["Containers", "Linux"])
        assert "No Atomic Red Team test is mapped for `T9999.001` on Containers/Linux" in md
        assert "Execute controlled simulation" not in md
        assert "| Technique |" not in md

        mixed = format_atomic_tests_markdown(["T1059.001", "T9999.001"])
        assert "`T1059.001`" in mixed and "| Technique |" in mixed
        assert "No Atomic Red Team test is mapped for `T9999.001`." in mixed

    def test_format_atomic_tests_markdown_empty(self):
        assert format_atomic_tests_markdown([]) == ""

    def test_format_atomic_tests_markdown_renders_table(self):
        md = format_atomic_tests_markdown(["T1059.001", "T1053.005"])
        assert "### Validation Procedure (Atomic Red Team)" in md
        assert "| Technique | Test ID | Procedure / Command | Expected Telemetry |" in md
        assert "`T1059.001`" in md
        assert "`T1053.005`" in md
        assert "schtasks" in md

    def test_format_atomic_tests_markdown_escapes_pipes(self, monkeypatch):
        # Even if command or telemetry has pipes, it should escape them for markdown tables
        monkeypatch.setitem(
            ATOMIC_TESTS_MAP,
            "T9999",
            [
                {
                    "name": "Pipe Test",
                    "test_id": "ART T9999 #1",
                    "command": "cmd1 | cmd2",
                    "telemetry": "Event 1 | Event 2",
                }
            ],
        )
        md = format_atomic_tests_markdown(["T9999"])
        assert "`T9999`" in md
        assert "cmd1 \\| cmd2" in md
        assert "Event 1 \\| Event 2" in md

    def test_attack_metadata_alone_does_not_make_a_test(self, monkeypatch):
        monkeypatch.setattr(
            "hecate_agent.core.attack_matrix.get_technique",
            lambda tid: (
                {
                    "name": "Brute Force",
                    "platforms": ["Linux", "Windows"],
                    "data_sources": ["Logon Session: Logon Session Creation"],
                }
                if "T1110" in tid
                else None
            ),
        )
        assert get_atomic_tests("T1110") == []

    def test_get_atomic_tests_workspace_custom_tests(self, tmp_path):
        import json

        knowledge = tmp_path / "knowledge"
        knowledge.mkdir()
        custom_file = knowledge / "atomic_tests.json"
        custom_file.write_text(
            json.dumps(
                {
                    "T9998": [
                        {
                            "name": "Custom In-House Test",
                            "test_id": "ORG-T9998-01",
                            "command": "custom_tool.exe --run",
                            "telemetry": "Custom EDR log",
                        }
                    ]
                }
            )
        )
        tests = get_atomic_tests("T9998", workspace=tmp_path)
        assert len(tests) == 1
        assert tests[0]["name"] == "Custom In-House Test"
        assert tests[0]["test_id"] == "ORG-T9998-01"

    def test_synthesize_atomic_telemetry_powershell_and_service(self):
        from hecate_agent.core.atomic_red_team import synthesize_atomic_telemetry

        # T1059.001 - PowerShell
        ps_events = synthesize_atomic_telemetry("T1059.001")
        assert "process_creation" in ps_events
        assert any("powershell.exe" in e.get("Image", "").lower() for e in ps_events["process_creation"])
        assert any("Invoke-WebRequest" in e.get("CommandLine", "") for e in ps_events["process_creation"])
        assert "file_event" in ps_events
        assert any("p.ps1" in e.get("TargetFilename", "") for e in ps_events["file_event"])
        assert "network_connection" in ps_events

        # T1543.003 - Windows Service Creation
        srv_events = synthesize_atomic_telemetry("T1543.003")
        assert "process_creation" in srv_events
        assert any("sc.exe" in e.get("Image", "") for e in srv_events["process_creation"])
        assert "registry_set" in srv_events
        assert any("Services" in e.get("TargetObject", "") for e in srv_events["registry_set"])
        assert "file_event" in srv_events

    def test_synthesize_atomic_telemetry_cron_and_containers(self):
        from hecate_agent.core.atomic_red_team import synthesize_atomic_telemetry

        # T1053.003 - Linux Cron
        cron_events = synthesize_atomic_telemetry("T1053.003")
        assert "file_event" in cron_events
        assert any("cron" in e.get("TargetFilename", "") for e in cron_events["file_event"])

        # T1610 - Container deployment / escape
        k8s_events = synthesize_atomic_telemetry("T1610")
        assert "container_runtime" in k8s_events
        assert any(e.get("Privileged") == "true" for e in k8s_events["container_runtime"])
        assert "kubernetes_audit" in k8s_events

    def test_run_dynamic_atomic_emulation(self):
        from hecate_agent.api import run_dynamic_atomic_emulation

        res = run_dynamic_atomic_emulation("T1059.001", backend="simulation")
        assert res.success is True
        assert res.backend == "simulation"
        assert len(res.events) > 0
        assert any(e.get("category") == "process_creation" for e in res.events)
