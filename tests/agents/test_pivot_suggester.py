"""Tests for hecate_agent.agents.llm.pivot_suggester — pivot suggestion agent."""

import json
from unittest.mock import MagicMock, patch

import pytest

from hecate_agent.agents.llm.pivot_suggester import PivotInput, PivotSuggesterAgent
from hecate_agent.core.llm_provider import LLMProvider, LLMResponse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_PIVOT_JSON = json.dumps(
    {
        "finding_summary": "PowerShell spawned by Word — classic phishing execution chain.",
        "technique_matches": ["T1566.001", "T1059.001"],
        "pivots": [
            {
                "priority": 1,
                "query": "Find all network connections from powershell.exe within 10 minutes of the Word spawn event",
                "rationale": "C2 beaconing typically follows phishing execution",
                "data_source": "EDR network telemetry",
                "technique_hint": "T1071.001",
            },
            {
                "priority": 2,
                "query": "Search for all hosts where winword.exe spawned any child process in the last 7 days",
                "rationale": "Scope the phishing campaign — this may not be an isolated incident",
                "data_source": "EDR process creation logs",
                "technique_hint": "T1566.001",
            },
            {
                "priority": 3,
                "query": "Check file writes by powershell.exe within the same session — look for staged payloads",
                "rationale": "Download-and-execute patterns leave artifacts on disk",
                "data_source": "EDR file event logs",
                "technique_hint": "T1105",
            },
        ],
        "past_hunt_references": [],
    }
)


def _mock_provider(response_text: str) -> LLMProvider:
    provider = MagicMock(spec=LLMProvider)
    provider.complete.return_value = LLMResponse(
        text=response_text,
        model="claude-test",
        input_tokens=100,
        output_tokens=200,
        cost_usd=0.001,
        duration_ms=500,
    )
    return provider


# ---------------------------------------------------------------------------
# Heuristic (no-LLM) mode
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPivotSuggesterHeuristic:
    """Tests for the deterministic heuristic fallback mode."""

    def test_process_parent_fields_generate_process_pivots(self):
        agent = PivotSuggesterAgent(llm_enabled=False)
        result = agent.execute(
            PivotInput(
                finding='{"process": "powershell.exe", "parent": "winword.exe"}',
            )
        )
        assert result.is_success
        assert result.data is not None
        queries = [p.query for p in result.data.pivots]
        assert any("powershell.exe" in q for q in queries)
        assert any("winword.exe" in q for q in queries)

    def test_user_field_generates_auth_pivot(self):
        agent = PivotSuggesterAgent(llm_enabled=False)
        result = agent.execute(
            PivotInput(
                finding='{"user": "svc_backup", "host": "dc01"}',
            )
        )
        assert result.is_success
        queries = [p.query for p in result.data.pivots]  # type: ignore
        assert any("svc_backup" in q for q in queries)

    def test_ip_field_generates_network_pivot(self):
        agent = PivotSuggesterAgent(llm_enabled=False)
        result = agent.execute(
            PivotInput(
                finding='{"process": "chrome.exe", "dst_ip": "198.51.100.42"}',
            )
        )
        assert result.is_success
        queries = [p.query for p in result.data.pivots]  # type: ignore
        assert any("198.51.100.42" in q for q in queries)

    def test_plain_text_finding_generates_default_pivots(self):
        agent = PivotSuggesterAgent(llm_enabled=False)
        result = agent.execute(PivotInput(finding="suspicious outbound DNS to rare domain"))
        assert result.is_success
        assert len(result.data.pivots) >= 2  # type: ignore

    def test_technique_propagated_to_output(self):
        agent = PivotSuggesterAgent(llm_enabled=False)
        result = agent.execute(
            PivotInput(
                finding='{"process": "mimikatz.exe"}',
                technique="T1003.001",
            )
        )
        assert result.is_success
        assert "T1003.001" in result.data.technique_matches  # type: ignore

    def test_pivots_are_ordered_by_priority(self):
        agent = PivotSuggesterAgent(llm_enabled=False)
        result = agent.execute(
            PivotInput(
                finding='{"process": "cmd.exe", "parent": "excel.exe", "user": "alice"}',
            )
        )
        assert result.is_success
        priorities = [p.priority for p in result.data.pivots]  # type: ignore
        assert priorities == sorted(priorities)

    def test_metadata_includes_mode(self):
        agent = PivotSuggesterAgent(llm_enabled=False)
        result = agent.execute(PivotInput(finding='{"process": "wscript.exe"}'))
        assert result.metadata.get("mode") == "heuristic"

    def test_duration_ms_in_metadata(self):
        agent = PivotSuggesterAgent(llm_enabled=False)
        result = agent.execute(PivotInput(finding="test finding"))
        assert "duration_ms" in result.metadata
        assert result.metadata["duration_ms"] >= 0


# ---------------------------------------------------------------------------
# LLM mode
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPivotSuggesterLLM:
    """Tests for LLM-powered pivot suggestion."""

    def test_llm_response_parsed_into_output(self):
        provider = _mock_provider(VALID_PIVOT_JSON)
        agent = PivotSuggesterAgent(llm_enabled=True, provider=provider)
        result = agent.execute(
            PivotInput(
                finding='{"process": "powershell.exe", "parent": "winword.exe"}',
            )
        )
        assert result.is_success
        assert result.data.finding_summary == "PowerShell spawned by Word — classic phishing execution chain."  # type: ignore
        assert "T1566.001" in result.data.technique_matches  # type: ignore
        assert len(result.data.pivots) == 3  # type: ignore

    def test_pivots_have_correct_fields(self):
        provider = _mock_provider(VALID_PIVOT_JSON)
        agent = PivotSuggesterAgent(llm_enabled=True, provider=provider)
        result = agent.execute(PivotInput(finding='{"process": "powershell.exe", "parent": "winword.exe"}'))
        assert result.is_success
        first = result.data.pivots[0]  # type: ignore
        assert first.query
        assert first.rationale
        assert first.data_source
        assert first.priority == 1
        assert first.technique_hint == "T1071.001"

    def test_llm_error_returns_failure(self):
        provider = MagicMock(spec=LLMProvider)
        provider.complete.side_effect = RuntimeError("API timeout")
        agent = PivotSuggesterAgent(llm_enabled=True, provider=provider)
        result = agent.execute(PivotInput(finding="test finding"))
        assert not result.is_success
        assert result.error is not None

    def test_malformed_json_falls_through_retries(self):
        provider = _mock_provider("not valid json at all {{{")
        agent = PivotSuggesterAgent(llm_enabled=True, provider=provider)
        result = agent.execute(PivotInput(finding="test finding"))
        assert not result.is_success

    def test_llm_called_with_finding_in_prompt(self):
        provider = _mock_provider(VALID_PIVOT_JSON)
        agent = PivotSuggesterAgent(llm_enabled=True, provider=provider)
        agent.execute(PivotInput(finding='{"process": "notepad.exe", "parent": "explorer.exe"}'))
        call_args = provider.complete.call_args  # type: ignore
        prompt = call_args[1]["messages"][0]["content"]
        assert "notepad.exe" in prompt

    def test_hunt_context_included_in_prompt(self):
        provider = _mock_provider(VALID_PIVOT_JSON)
        agent = PivotSuggesterAgent(llm_enabled=True, provider=provider)

        with patch.object(agent, "_load_hunt_context") as mock_ctx:
            mock_ctx.return_value = {
                "frontmatter": {
                    "hunt_id": "H-0042",
                    "title": "LSASS Dump Hunt",
                    "techniques": ["T1003.001"],
                    "tactics": ["credential-access"],
                    "platform": ["Windows"],
                }
            }
            agent.execute(PivotInput(finding="suspicious process", hunt_id="H-0042"))

        prompt = provider.complete.call_args[1]["messages"][0]["content"]  # type: ignore
        assert "H-0042" in prompt
        assert "LSASS Dump Hunt" in prompt

    def test_technique_hint_in_prompt(self):
        provider = _mock_provider(VALID_PIVOT_JSON)
        agent = PivotSuggesterAgent(llm_enabled=True, provider=provider)
        agent.execute(PivotInput(finding="test", technique="T1059.001"))
        prompt = provider.complete.call_args[1]["messages"][0]["content"]  # type: ignore
        assert "T1059.001" in prompt


# ---------------------------------------------------------------------------
# Context loaders
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPivotContextLoading:
    """Tests for the context-loading helpers."""

    def test_load_environment_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        agent = PivotSuggesterAgent(llm_enabled=False)
        env = agent._load_environment()
        assert "coverage are unknown" in env

    def test_load_environment_reads_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        knowledge = tmp_path / "knowledge"
        knowledge.mkdir()
        (knowledge / "environment.md").write_text("# Test Env\nUsing Splunk and CrowdStrike.", encoding="utf-8")
        agent = PivotSuggesterAgent(llm_enabled=False)
        env = agent._load_environment()
        assert "Splunk" in env

    def test_load_hunt_context_returns_none_when_no_id(self):
        agent = PivotSuggesterAgent(llm_enabled=False)
        assert agent._load_hunt_context(None) is None

    def test_load_past_hunts_empty_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        agent = PivotSuggesterAgent(llm_enabled=False)
        result = agent._load_past_hunts("powershell")
        assert isinstance(result, list)
