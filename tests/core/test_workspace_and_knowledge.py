"""Knowledge files must reach the model regardless of working directory.

Every loader used to resolve `Path.cwd() / "knowledge" / ...`. The
orchestrator happens to set `cwd` to the workspace, so that worked for it --
but it made correctness depend on every caller doing the same, and any caller
that did not got a silent "not found" rather than an error.
"""

import pytest

from hecate_agent.agents.llm.hypothesis_generator import HypothesisGeneratorAgent
from hecate_agent.core.hunting_knowledge import (
    HYPOTHESIS_SECTIONS,
    is_enabled,
    PIVOT_SECTIONS,
    load_sections,
    load_stage_guidance,
    load_environment_context,
)
from hecate_agent.core.workspace import knowledge_file, workspace_root

KB = """# Hunting Brain

## Section 1: Hypothesis Generation Knowledge

### Patterns
Section one body.
<!-- hecate:agent-guidance:start -->
- source-scoped hypothesis rule
<!-- hecate:agent-guidance:end -->

## Section 2: Behavioral Models

### Mapping
Section two body.
<!-- hecate:agent-guidance:start -->
- verified telemetry rule
<!-- hecate:agent-guidance:end -->

## Section 3: Pivot Logic

### Chains
Section three body.
<!-- hecate:agent-guidance:start -->
- bounded pivot rule
<!-- hecate:agent-guidance:end -->

## Section 4: Analytical Rigor

<!-- hecate:agent-guidance:start -->
- preserve uncertainty rule
<!-- hecate:agent-guidance:end -->

## Section 5: Framework Mental Models

### Pyramid
Section five body.
<!-- hecate:agent-guidance:start -->
- data quality rule
<!-- hecate:agent-guidance:end -->
"""


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    (tmp_path / ".hecateconfig.yaml").write_text("workspace_name: t\n")
    (tmp_path / "knowledge").mkdir()
    (tmp_path / "knowledge" / "hunting-knowledge.md").write_text(KB)
    (tmp_path / "knowledge" / "environment.md").write_text("estate")
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    return tmp_path


class TestWorkspaceResolution:
    def test_resolves_from_the_env_var_not_the_cwd(self, workspace, tmp_path, monkeypatch):
        elsewhere = tmp_path.parent / "elsewhere"
        elsewhere.mkdir(exist_ok=True)
        monkeypatch.chdir(elsewhere)
        assert workspace_root() == workspace
        assert knowledge_file("environment.md").read_text() == "estate"

    def test_walks_up_from_cwd_when_no_env_var(self, workspace, monkeypatch):
        monkeypatch.delenv("HECATE_WORKSPACE", raising=False)
        nested = workspace / "hunts" / "2026"
        nested.mkdir(parents=True)
        monkeypatch.chdir(nested)
        assert workspace_root() == workspace

    def test_falls_back_to_cwd_rather_than_raising(self, tmp_path, monkeypatch):
        """A missing workspace should degrade the prompt, not kill a cycle."""
        monkeypatch.delenv("HECATE_WORKSPACE", raising=False)
        monkeypatch.chdir(tmp_path)
        assert workspace_root() == tmp_path

    def test_a_nonexistent_env_path_is_honored(self, workspace, monkeypatch):
        monkeypatch.setenv("HECATE_WORKSPACE", "/no/such/dir")
        from pathlib import Path

        assert workspace_root() == Path("/no/such/dir").resolve()


class TestHuntingKnowledge:
    def test_selects_only_the_requested_sections(self, workspace):
        body = load_sections(HYPOTHESIS_SECTIONS, 10_000)
        assert "Section 1" in body and "Section 2" in body and "Section 5" in body
        assert "Section 3" not in body

    def test_pivot_stage_gets_its_own_section(self, workspace):
        body = load_sections(PIVOT_SECTIONS, 10_000)
        assert "Section 3" in body
        assert "Section 1" not in body

    def test_a_missing_file_yields_nothing_rather_than_a_placeholder(self, tmp_path, monkeypatch):
        """The prompt omits the block entirely; it must not tell the model
        about knowledge it was not given."""
        monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
        assert load_sections(HYPOTHESIS_SECTIONS, 10_000) == ""

    def test_the_budget_is_respected(self, workspace):
        assert len(load_sections(HYPOTHESIS_SECTIONS, 1200)) <= 1400

    def test_truncation_is_declared(self, workspace):
        assert "excerpted" in load_sections(HYPOTHESIS_SECTIONS, 900)

    def test_a_complete_slice_is_not_labelled_partial(self, workspace):
        assert "excerpted" not in load_sections(PIVOT_SECTIONS, 50_000)

    def test_unknown_section_numbers_are_skipped(self, workspace):
        assert load_sections((99,), 10_000) == ""


class TestPromptDoesNotShipCopyableExamples:
    """H-0001 was scoped to Windows for a Linux Redis compromise because the
    model copied "Windows domain-joined endpoints" straight out of the
    prompt's Location example. ClickHouse reached 5 of 8 hunts the same way."""

    @staticmethod
    def _prompt_text() -> str:
        import inspect

        from hecate_agent.agents.llm import hypothesis_generator

        return inspect.getsource(hypothesis_generator)

    def test_the_location_example_is_gone(self):
        assert "Windows domain-joined endpoints" not in self._prompt_text()

    def test_the_data_source_example_is_gone(self):
        assert "ClickHouse nocsf_unified_events" not in self._prompt_text()

    def test_the_model_is_told_not_to_copy_placeholders(self):
        assert "copying it" in self._prompt_text()


class TestKnowledgeInjectionIsGated:
    """Compact rules ship by default; reference examples never enter prompts."""

    def test_compact_guidance_is_on_by_default(self, workspace, monkeypatch):
        monkeypatch.delenv("HECATE_HUNTING_KNOWLEDGE", raising=False)
        assert is_enabled() is True

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
    def test_it_can_be_switched_on(self, monkeypatch, value):
        monkeypatch.setenv("HECATE_HUNTING_KNOWLEDGE", value)
        assert is_enabled() is True

    @pytest.mark.parametrize("value", ["0", "false", "no", "", "  "])
    def test_other_values_leave_it_off(self, monkeypatch, value):
        monkeypatch.setenv("HECATE_HUNTING_KNOWLEDGE", value)
        assert is_enabled() is False

    def test_optional_guidance_can_be_disabled_without_removing_evidence_rules(self, workspace, monkeypatch):
        monkeypatch.setenv("HECATE_HUNTING_KNOWLEDGE", "false")
        section = HypothesisGeneratorAgent._build_hunting_knowledge_section()
        assert "source-scoped hypothesis rule" not in section
        assert "Zero matches alone" in section

    def test_the_prompt_includes_it_when_on(self, workspace, monkeypatch):
        monkeypatch.setenv("HECATE_HUNTING_KNOWLEDGE", "1")
        section = HypothesisGeneratorAgent._build_hunting_knowledge_section()
        assert "Hunting Tradecraft" in section
        assert "Section 1" in section


class TestCompactWorkspaceGuidance:
    def test_stage_rules_exclude_worked_examples(self, workspace):
        body = load_stage_guidance("triage")
        assert "verified telemetry rule" in body
        assert "preserve uncertainty rule" in body
        assert "source-scoped hypothesis rule" not in body
        assert "Section two body" not in body

    def test_legacy_reference_without_markers_is_not_injected(self, workspace):
        (workspace / "knowledge" / "hunting-knowledge.md").write_text(
            "## Section 1: Hypothesis\nCopy this unrelated platform hypothesis"
        )
        assert load_stage_guidance("hypothesis") == ""

    def test_explicit_workspace_wins_over_cwd_and_environment(self, workspace, tmp_path, monkeypatch):
        other = tmp_path / "other"
        (other / "knowledge").mkdir(parents=True)
        (other / "knowledge" / "hunting-knowledge.md").write_text(KB.replace("source-scoped", "OTHER"))
        (other / "knowledge" / "environment.md").write_text("other-estate-marker")
        monkeypatch.chdir(workspace)
        assert "OTHER hypothesis rule" in load_stage_guidance("hypothesis", workspace=other)
        assert "other-estate-marker" in load_environment_context(workspace=other)
        assert "OTHER" not in load_stage_guidance("hypothesis", workspace=workspace)

    @pytest.mark.parametrize("budget", [0, 20, 100, 250, 4000])
    def test_complete_output_stays_within_budget(self, workspace, budget):
        assert len(load_stage_guidance("hypothesis", budget)) <= budget
        assert len(load_environment_context(budget)) <= budget

    def test_missing_workspace_does_not_fall_back_to_checkout(self, tmp_path):
        assert load_stage_guidance("hypothesis", workspace=tmp_path) == ""
        assert "coverage are unknown" in load_environment_context(workspace=tmp_path)

    def test_oversized_profile_discloses_omitted_context(self, workspace):
        (workspace / "knowledge" / "environment.md").write_text("profile-line\n" * 1000)
        body = load_environment_context(500)
        assert len(body) <= 500
        assert "excerpted" in body

    def test_explicit_hypothesis_workspace_reaches_prompt(self, workspace, tmp_path):
        other = tmp_path / "explicit"
        (other / "knowledge").mkdir(parents=True)
        (other / "knowledge" / "hunting-knowledge.md").write_text(KB.replace("source-scoped", "API-owned"))
        body = HypothesisGeneratorAgent._build_hunting_knowledge_section(other)
        assert "API-owned hypothesis rule" in body
        assert "source-scoped" not in body
