"""Tests for BaseAgent JSON parsing and resilience."""

import pytest
from hecate_agent.agents.base import LLMAgent


class DummyLLMAgent(LLMAgent[str, str]):
    def execute(self, input_data: str) -> str:
        return input_data


def test_parse_json_valid_and_markdown():
    agent = DummyLLMAgent()
    # Standard JSON
    assert agent._parse_json_response('{"key": "value"}') == {"key": "value"}

    # Markdown block
    assert agent._parse_json_response('```json\n{"key": "value"}\n```') == {"key": "value"}

    # Chatty preamble
    chatty = 'Sure! Here is the JSON you requested:\n{"key": "value"}\nHope this helps!'
    assert agent._parse_json_response(chatty) == {"key": "value"}


def test_parse_json_repairs_windows_paths_and_unc_shares():
    agent = DummyLLMAgent()
    # Raw Windows path with invalid escape \P and \U
    payload = r'{"path": "C:\Program Files\evil.exe", "description": "drops to C:\Users\Admin"}'
    parsed = agent._parse_json_response(payload)
    assert parsed["path"] == r"C:\Program Files\evil.exe"
    assert parsed["description"] == r"drops to C:\Users\Admin"

    # UNC share from Hunt 2
    unc_payload = r'{"unc": "\\145.249.109.147@80\webdav", "action": "connect"}'
    parsed_unc = agent._parse_json_response(unc_payload)
    assert parsed_unc["unc"] == r"\145.249.109.147@80\webdav"
    assert parsed_unc["action"] == "connect"


def test_parse_json_preserves_valid_escapes():
    agent = DummyLLMAgent()
    payload = r'{"newline": "line1\nline2", "tab": "col1\tcol2", "quote": "hello \"world\""}'
    parsed = agent._parse_json_response(payload)
    assert parsed["newline"] == "line1\nline2"
    assert parsed["tab"] == "col1\tcol2"
    assert parsed["quote"] == 'hello "world"'


def test_parse_json_raises_on_invalid():
    agent = DummyLLMAgent()
    with pytest.raises(ValueError, match="Failed to parse JSON"):
        agent._parse_json_response("This has no json at all.")


def test_call_llm_with_retry_truncates_huge_responses(monkeypatch):
    agent = DummyLLMAgent()
    prompts_received = []

    huge_hallucination = "A" * 5000

    def mock_call_llm(prompt, **kwargs):
        prompts_received.append(prompt)
        if len(prompts_received) == 1:
            return huge_hallucination
        return '{"valid": true}'

    monkeypatch.setattr(agent, "_call_llm", mock_call_llm)

    def validate(resp):
        if resp == huge_hallucination:
            return "Too long and invalid JSON"
        return None

    result = agent._call_llm_with_retry("initial prompt", validate, max_retries=1, backoff_base_sec=0)
    assert result == '{"valid": true}'
    assert len(prompts_received) == 2

    retry_prompt = prompts_received[1]
    # Check that the 5000 character output was truncated in the prompt
    assert "... [truncated] ..." in retry_prompt
    assert huge_hallucination not in retry_prompt
    assert "Too long and invalid JSON" in retry_prompt


def test_call_llm_with_retry_jittered_backoff(monkeypatch):
    agent = DummyLLMAgent()
    sleep_calls = []

    monkeypatch.setattr("time.sleep", lambda s: sleep_calls.append(s))
    monkeypatch.setattr(agent, "_call_llm", lambda *a, **kw: "invalid")

    def validate(resp):
        return "always invalid"

    res = agent._call_llm_with_retry("test prompt", validate, max_retries=2, backoff_base_sec=0.5)
    assert res == "invalid"
    # Should have retried 2 times, so 2 sleep calls
    assert len(sleep_calls) == 2
    # First sleep: base=0.5 * 2^0 = 0.5 (+ jitter 0.05-0.2) -> between 0.55 and 0.70
    assert 0.5 <= sleep_calls[0] <= 0.75
    # Second sleep: base=0.5 * 2^1 = 1.0 (+ jitter 0.05-0.2) -> between 1.05 and 1.25
    assert 1.0 <= sleep_calls[1] <= 1.25

