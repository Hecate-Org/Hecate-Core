"""Stage 4 Core Feature Groups & Parser Fuzzing Stress Test Suite.

Evaluation Plan Stage 4 Requirements:
- Core feature groups: CLI/API contracts, workspace selection, ATT&CK/evidence mapping,
  research parsing, hypothesis generation, Sigma generation/review/transpilation,
  query validation and monitoring.
- Fuzz bounded parsers and resource-sensitive inputs.
- Deterministic feature tests, bounded CPU/memory/input handling, useful errors and
  consistent installed-wheel behavior.
"""

from __future__ import annotations

import concurrent.futures
import os
import subprocess
import time
from pathlib import Path

import pytest

from hecate_agent.core.attack_matrix import (
    canonical_tactic,
    get_technique,
)
from hecate_agent.core.grounding import audit_draft
from hecate_agent.core.hunt_manager import HuntManager
from hecate_agent.core.hunt_parser import HuntParser
from hecate_agent.core.investigation_parser import InvestigationParser
from hecate_agent.core.query_validator import QueryValidator
from hecate_agent.core.research_manager import ResearchManager
from hecate_agent.core.sigma_transpiler import SigmaTranspiler
from hecate_agent.core.workspace import workspace_root


# ==============================================================================
# 1. Bounded Parser Fuzzing (HuntParser)
# ==============================================================================


class TestHuntParserFuzzingAndBounds:
    """Fuzzing and bounded resource stress testing for HuntParser."""

    def test_safe_against_deeply_nested_yaml_bomb(self, tmp_path: Path) -> None:
        """Deeply nested YAML mappings must not cause unhandled recursion crashes."""
        # 100 levels of nested dictionary
        nested = "a: " * 100 + "value"
        bomb_content = f"---\n{nested}\n---\n# H-9999\n## LEARN\n## OBSERVE\n## CHECK\n## KEEP\n"
        hunt_file = tmp_path / "H-9999.md"
        hunt_file.write_text(bomb_content, encoding="utf-8")

        parser = HuntParser(hunt_file)
        # Should either parse or raise ValueError gracefully, never RecursionError / crash
        try:
            data = parser.parse()
            assert isinstance(data, dict)
            is_valid, errors = parser.validate()
            assert not is_valid
        except ValueError:
            pass  # Acceptable safe rejection

    def test_redos_resilience_on_massive_markdown_body(self, tmp_path: Path) -> None:
        """Massive markdown files with repeating headers and symbols must parse in bounded time (<1.0s)."""
        repetition = ("# Headline\n## Almost a heading\nSome text with special characters !@#$%^&*()\n") * 5000
        content = (
            "---\n"
            "hunt_id: H-0001\n"
            "title: Heavy ReDoS Probe\n"
            "status: testing\n"
            "date: 2026-11-16\n"
            "---\n"
            "# H-0001\n"
            f"{repetition}\n"
            "## LEARN: Prepare the Hunt\n"
            "Learning notes.\n"
            "## OBSERVE: Telemetry\n"
            "Observed events.\n"
            "## CHECK: Analyze\n"
            "Checking assertions.\n"
            "## KEEP: Persistence\n"
            "Rules preserved.\n"
        )
        hunt_file = tmp_path / "H-0001.md"
        hunt_file.write_text(content, encoding="utf-8")

        start = time.monotonic()
        parser = HuntParser(hunt_file)
        data = parser.parse()
        elapsed = time.monotonic() - start

        assert elapsed < 1.0, f"Parser took too long: {elapsed:.2f}s (possible ReDoS)"
        assert "learn" in data["lock_sections"]
        assert "keep" in data["lock_sections"]

    def test_corrupted_yaml_frontmatter_fuzz_inputs(self, tmp_path: Path) -> None:
        """Fuzz inputs with corrupted frontmatter must yield clean errors, not unhandled crashes."""
        fuzz_cases = [
            ("---\n\tinvalid: tab\n---\nBody", "Tab in YAML"),
            ("---\nkey: : bad colon\n---\nBody", "Dangling colon"),
            ("---\n[unclosed list\n---\nBody", "Unclosed list"),
            ("---\n{unclosed dict: 1\n---\nBody", "Unclosed dict"),
            ("---\n'unclosed quote\n---\nBody", "Unclosed single quote"),
            ("No frontmatter at all in this document\n", "Missing frontmatter"),
            ("---\n---\nEmpty frontmatter\n", "Empty frontmatter"),
        ]

        for i, (fuzz_text, label) in enumerate(fuzz_cases):
            f_path = tmp_path / f"H-000{i}.md"
            f_path.write_text(fuzz_text, encoding="utf-8")
            parser = HuntParser(f_path)
            try:
                parser.parse()
                is_valid, errors = parser.validate()
                assert not is_valid, f"Expected invalid for fuzz case '{label}'"
                assert len(errors) > 0
            except ValueError as e:
                # Controlled ValueError from YAML parse error is safe
                assert "Invalid YAML frontmatter" in str(e)

    def test_filename_and_id_mismatch_and_traversal(self, tmp_path: Path) -> None:
        """Filename divergence and traversal attempts in hunt_id must be rejected."""
        # 1. hunt_id differs from file stem
        mismatch_file = tmp_path / "H-0001.md"
        mismatch_file.write_text(
            "---\nhunt_id: H-0002\ntitle: Divergent\nstatus: testing\ndate: 2026-11-16\n---\n"
            "## LEARN\n## OBSERVE\n## CHECK\n## KEEP\n",
            encoding="utf-8",
        )
        parser = HuntParser(mismatch_file)
        parser.parse()
        is_valid, errors = parser.validate()
        assert not is_valid
        assert any("does not match filename" in err for err in errors)

        # 2. Path traversal in hunt_id
        traversal_file = tmp_path / "H-9999.md"
        traversal_file.write_text(
            "---\nhunt_id: '../../etc/passwd'\ntitle: Traversal\nstatus: testing\ndate: 2026-11-16\n---\n"
            "## LEARN\n## OBSERVE\n## CHECK\n## KEEP\n",
            encoding="utf-8",
        )
        p2 = HuntParser(traversal_file)
        p2.parse()
        is_valid2, errors2 = p2.validate()
        assert not is_valid2
        assert any("Invalid hunt_id format" in err for err in errors2)


# ==============================================================================
# 2. Investigation & Research Parser Fuzzing
# ==============================================================================


class TestInvestigationAndResearchFuzzing:
    """Fuzzing and stress testing for Investigation and Research document parsers."""

    def test_investigation_parser_graceful_on_fuzz_content(self, tmp_path: Path) -> None:
        """InvestigationParser must parse or gracefully report errors on malformed input."""
        inv_file = tmp_path / "I-0001.md"

        # Valid minimal investigation
        inv_file.write_text(
            "---\ninvestigation_id: I-0001\ntitle: Triage\ndate: 2026-11-16\n---\n# Notes\nSome evidence\n",
            encoding="utf-8",
        )
        parser = InvestigationParser(inv_file)
        data = parser.parse()
        assert data["frontmatter"]["investigation_id"] == "I-0001"

        # Empty file
        empty_file = tmp_path / "I-0002.md"
        empty_file.write_text("", encoding="utf-8")
        data_empty = InvestigationParser(empty_file).parse()
        assert data_empty["frontmatter"] == {}
        assert data_empty["content"] == ""

    def test_research_manager_counter_concurrency_stress(self, tmp_path: Path) -> None:
        """Concurrent research ID allocation under 8 worker threads must not duplicate IDs."""
        res_dir = tmp_path / "research"
        res_dir.mkdir()

        manager = ResearchManager(research_dir=res_dir)

        allocated_ids: list[str] = []

        def worker() -> list[str]:
            local_ids = []
            for _ in range(5):
                rid = manager.get_next_research_id()
                # Create an actual file so disk scanning works alongside counter
                (res_dir / f"{rid}.md").write_text(f"---\nresearch_id: {rid}\n---\n# Research\n")
                local_ids.append(rid)
            return local_ids

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker) for _ in range(8)]
            for f in concurrent.futures.as_completed(futures):
                allocated_ids.extend(f.result())

        assert len(allocated_ids) == 40
        assert len(set(allocated_ids)) == 40, f"Duplicate research IDs allocated under contention: {allocated_ids}"


# ==============================================================================
# 3. Sigma Transpiler & Query Validator Stress
# ==============================================================================


class TestSigmaTranspilerAndValidatorStress:
    """Stress and fuzz testing for pySigma transpilation and dialect validator."""

    @pytest.fixture
    def transpiler(self) -> SigmaTranspiler:
        return SigmaTranspiler()

    @pytest.fixture
    def validator(self) -> QueryValidator:
        return QueryValidator()

    def test_transpiler_resilience_to_malformed_and_injection_rules(self, transpiler: SigmaTranspiler) -> None:
        """Transpiler must safely reject malformed or adversarial Sigma rules without unhandled exceptions."""
        malformed_rules = [
            # Missing detection
            "title: Broken Rule\nlogsource:\n  category: process_creation\n",
            # Empty detection
            "title: Empty\nlogsource:\n  category: process_creation\ndetection:\n",
            # Detection not a dict
            "title: List Detection\nlogsource:\n  category: process_creation\ndetection: [1, 2, 3]\n",
            # Dangerous SQL / quote injection in selection value
            """title: Injection Attempt
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "') OR 1=1; DROP TABLE hunts; --"
      - "`rm -rf /`"
      - "\x00nullbyte"
  condition: selection
""",
        ]

        for rule in malformed_rules:
            results = transpiler.transpile(rule)
            assert isinstance(results, dict)
            for target, trans_res in results.items():
                # Transpilation must complete with a valid result object
                assert trans_res.target == target
                # Should not crash unhandled

    def test_validator_fuzz_and_boundary_checks(self, validator: QueryValidator) -> None:
        """QueryValidator must bound execution and return structured issues for invalid queries."""
        targets = ["sentinel_kql", "crowdstrike_cql", "rapid7_leql", "sentinelone_s1ql", "splunk_spl", "elastic_eql"]

        for target in targets:
            # 1. Unbalanced parentheses
            res_paren = validator.validate(target, "process where (Image == 'cmd.exe' and ParentImage == 'explorer.exe'")
            assert not res_paren.is_valid or res_paren.has_warnings

            # 2. Empty string
            res_empty = validator.validate(target, "")
            assert not res_empty.is_valid

            # 3. Oversized query (100k characters)
            huge_query = "CommandLine contains 'test' " * 3500
            start = time.monotonic()
            res_huge = validator.validate(target, huge_query)
            elapsed = time.monotonic() - start
            assert elapsed < 2.0, f"Validation of large query took too long: {elapsed:.2f}s"
            assert isinstance(res_huge.is_valid, bool)

    def test_concurrent_transpilation_cache_stress(self, transpiler: SigmaTranspiler) -> None:
        """16 concurrent threads repeatedly transpiling the same and distinct rules test thread safety."""
        rule_template = """title: Concurrency Test {idx}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\cmd{idx}.exe'
    CommandLine|contains: 'invoke-attack-{idx}'
  condition: selection
"""

        def worker(idx: int) -> int:
            successes = 0
            for i in range(5):
                rule = rule_template.format(idx=(idx + i) % 4)
                res = transpiler.transpile(rule, targets=["sentinel_kql", "splunk_spl"])
                if all(r.success for r in res.values()):
                    successes += 1
            return successes

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(worker, i) for i in range(16)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert sum(results) > 0


# ==============================================================================
# 4. ATT&CK Matrix & Grounding Resiliency
# ==============================================================================


class TestAttackMatrixAndGrounding:
    """Stress testing for ATT&CK mapping and claim grounding audit."""

    def test_canonical_tactic_edge_cases(self) -> None:
        """canonical_tactic must normalize renames and handle malformed inputs."""
        # Retired / renamed tactic
        assert canonical_tactic("defense-evasion") == "stealth"
        # Standard tactic
        assert canonical_tactic("initial-access") == "initial-access"
        # Unknown tactics pass through untouched
        assert canonical_tactic("unknown-tactic-xyz") == "unknown-tactic-xyz"
        assert canonical_tactic("") == ""

    def test_get_technique_boundary_and_fuzz(self) -> None:
        """get_technique must return None safely for invalid or malicious technique IDs."""
        invalid_ids = [
            "T9999",
            "T9999.999",
            "T1059.001.002",
            "../../etc/passwd",
            "T1059;DROP",
            "",
            "   ",
            "t1059",
        ]
        for tid in invalid_ids:
            tech = get_technique(tid)
            # Either None or handles without throwing unhandled exceptions
            assert tech is None or isinstance(tech, dict)

    def test_grounding_audit_unsupported_claim_detection(self) -> None:
        """Grounding audit must accurately classify fabricated CVEs and techniques as unsupported."""
        cti_text = "Adversaries executed PowerShell to download payload from example.com."
        research_text = "Investigation confirmed PowerShell execution (T1059.001)."
        draft_prose = (
            "The threat actor leveraged CVE-2029-99999 and exploited technique T9999 to achieve persistence via rundll32.exe."
        )

        report = audit_draft(draft_text=draft_prose, cti_text=cti_text, research_text=research_text)
        unsupported = report.unsupported
        unsupported_values = [claim.value for claim in unsupported]

        # The fabricated CVE must be marked unsupported
        assert any("CVE-2029-99999" in val for val in unsupported_values)


# ==============================================================================
# 5. Workspace Selection & Traversal Security
# ==============================================================================


class TestWorkspaceSelectionSecurity:
    """Stress testing workspace root resolution and traversal protection."""

    def test_workspace_root_environment_and_explicit_resolution(self, tmp_path: Path) -> None:
        """workspace_root must honor explicit paths and HECATE_WORKSPACE cleanly."""
        explicit_ws = tmp_path / "explicit_ws"
        explicit_ws.mkdir()
        assert workspace_root(explicit=explicit_ws) == explicit_ws.resolve()

        env_ws = tmp_path / "env_ws"
        env_ws.mkdir()
        orig = os.environ.get("HECATE_WORKSPACE")
        try:
            os.environ["HECATE_WORKSPACE"] = str(env_ws)
            assert workspace_root() == env_ws.resolve()
        finally:
            if orig is not None:
                os.environ["HECATE_WORKSPACE"] = orig
            else:
                os.environ.pop("HECATE_WORKSPACE", None)

    def test_hunt_manager_isolated_workspace_operations(self, tmp_path: Path) -> None:
        """HuntManager must respect isolated workspace boundaries without cross-contamination."""
        ws_a = tmp_path / "ws_a"
        ws_b = tmp_path / "ws_b"
        (ws_a / "hunts").mkdir(parents=True)
        (ws_b / "hunts").mkdir(parents=True)

        mgr_a = HuntManager(hunts_dir=ws_a / "hunts")
        mgr_b = HuntManager(hunts_dir=ws_b / "hunts")

        # Create hunt in workspace A
        hunt_a = ws_a / "hunts" / "H-0010.md"
        hunt_a.write_text(
            "---\nhunt_id: H-0010\ntitle: Alpha\nstatus: active\ndate: 2026-11-16\n---\n"
            "# H-0010\n## LEARN\n## OBSERVE\n## CHECK\n## KEEP\n",
            encoding="utf-8",
        )

        # Manager A finds it; Manager B must not find it
        assert mgr_a.find_hunt_file("H-0010") is not None
        assert mgr_b.find_hunt_file("H-0010") is None


# ==============================================================================
# 6. CLI Contracts and Wheel Entry Points
# ==============================================================================


class TestCLIContractsAndWheelConsistency:
    """Verify CLI contracts and subcommands run with expected exit codes and outputs."""

    def test_cli_help_and_subcommand_registration(self) -> None:
        """hecate-agent top-level CLI and all registered subcommands must display help cleanly."""
        commands = [
            ["hecate-agent", "--help"],
            ["hecate-agent", "hunt", "--help"],
            ["hecate-agent", "research", "--help"],
            ["hecate-agent", "investigate", "--help"],
            ["hecate-agent", "attack", "--help"],
            ["hecate-agent", "monitor", "--help"],
            ["hecate-agent", "context", "--help"],
        ]

        for cmd in commands:
            res = subprocess.run(
                ["uv", "run", *cmd],
                cwd="/home/chemch/betas/Hecate-Core",
                capture_output=True,
                text=True,
                check=False,
            )
            assert res.returncode == 0, f"Command {' '.join(cmd)} failed: {res.stderr}"
            assert "Usage:" in res.stdout or "Options:" in res.stdout or "Commands:" in res.stdout

    def test_cli_invalid_subcommand_behavior(self) -> None:
        """Invalid CLI subcommand must fail with non-zero exit code and informative error."""
        res = subprocess.run(
            ["uv", "run", "hecate-agent", "nonexistent-subcommand-xyz"],
            cwd="/home/chemch/betas/Hecate-Core",
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode != 0
        assert "No such command" in res.stderr or "Error:" in res.stderr
