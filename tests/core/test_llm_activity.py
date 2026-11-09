"""The live call log: what a provider call leaves behind while a run is in progress."""

from pathlib import Path
from typing import Any, Dict, List

import pytest

from hecate_agent.core import llm_activity
from hecate_agent.core.llm_provider import LLMProvider, LLMResponse


class _Provider(LLMProvider):
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def complete(self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
        if self.fail:
            raise RuntimeError("timed out")
        return LLMResponse(text="ok", input_tokens=1200, output_tokens=80, model="local/model", duration_ms=1500, cost_usd=0.0)

    @property
    def provider_name(self) -> str:
        return "fake"


def _summary(path: Path) -> Dict[str, Any]:
    return llm_activity.summarize_calls(path.read_text().splitlines())


def test_each_call_is_logged_as_it_starts_and_as_it_ends(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_activity.CALL_LOG_ENV, str(log))
    _Provider().complete([])
    _Provider().complete([])
    summary = _summary(log)
    assert summary["llm_calls"] == 2 and summary["in_flight"] == 0 and summary["failed"] == 0
    assert summary["input_tokens"] == 2400 and summary["output_tokens"] == 160
    assert summary["models"] == ["local/model"]


def test_a_call_that_has_not_returned_is_in_flight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_activity.CALL_LOG_ENV, str(log))
    _Provider().complete([])
    seen: List[Dict[str, Any]] = []

    class Slow(_Provider):
        def complete(self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
            seen.append(_summary(log))
            return super().complete(messages, max_tokens, temperature)

    Slow().complete([])
    assert seen[0]["llm_calls"] == 1 and seen[0]["in_flight"] == 1
    # The inherited call is one call, however many classes it passes through.
    assert _summary(log)["llm_calls"] == 2


def test_a_failed_call_is_not_left_in_flight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_activity.CALL_LOG_ENV, str(log))
    with pytest.raises(RuntimeError):
        _Provider(fail=True).complete([])
    summary = _summary(log)
    assert summary["failed"] == 1 and summary["in_flight"] == 0 and summary["llm_calls"] == 0


def test_nothing_is_written_unless_a_call_log_is_named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(llm_activity.CALL_LOG_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    _Provider().complete([])
    assert list(tmp_path.iterdir()) == []
    assert llm_activity.summarize_calls([]) == {}


def test_full_message_sizes_and_reported_peak_are_recorded_without_content(tmp_path, monkeypatch):
    import json

    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv(llm_activity.CALL_LOG_ENV, str(log))
    messages = [{"role": "system", "content": "PRIVATE_SYSTEM_INSTRUCTIONS"},
                {"role": "user", "content": "PRIVATE_LOADED_RESEARCH"}]
    _Provider().complete(messages)
    start = json.loads(log.read_text().splitlines()[0])
    assert start["prompt_chars"] == sum(len(m["content"]) for m in messages)
    assert start["message_count"] == 2
    assert "PRIVATE" not in log.read_text()
    summary = _summary(log)
    assert summary["max_input_tokens"] == 1200
    assert summary["input_token_samples"] == 1


def test_call_meta_is_copied_onto_log_lines(tmp_path, monkeypatch):
    import json

    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv(llm_activity.CALL_LOG_ENV, str(log))
    with llm_activity.call_meta(tier="complex", capability="hypothesis"):
        _Provider().complete([{"role": "user", "content": "x"}])
    start, end = [json.loads(line) for line in log.read_text().splitlines()]
    assert start["tier"] == "complex" and start["capability"] == "hypothesis"
    assert end["tier"] == "complex" and end["capability"] == "hypothesis"
    assert end["provider"] == "fake"
    summary = _summary(log)
    assert summary["tiers"] == ["complex"]
    assert summary["capabilities"] == ["hypothesis"]
    assert summary["by_tier"]["complex"]["llm_calls"] == 1
    assert summary["by_tier"]["simple"]["llm_calls"] == 0
    assert summary["escalated_calls"] == 0


def test_summarize_calls_splits_simple_and_complex_tiers() -> None:
    lines = [
        '{"event":"start","tier":"simple","ts":1}',
        '{"event":"end","tier":"simple","input_tokens":10,"output_tokens":2,"duration_ms":1000,"cost_usd":0,"model":"local"}',
        '{"event":"start","tier":"complex","capability":"hypothesis","ts":2,"escalated":true}',
        '{"event":"end","tier":"complex","input_tokens":20,"output_tokens":5,"duration_ms":2000,"cost_usd":0.4,"model":"cloud","escalated":true}',
        '{"event":"start","tier":"simple","ts":3}',
        '{"event":"error","tier":"simple","ts":3.5}',
    ]
    summary = llm_activity.summarize_calls(lines)
    assert summary["llm_calls"] == 2
    assert summary["failed"] == 1
    assert summary["by_tier"]["simple"]["llm_calls"] == 1
    assert summary["by_tier"]["simple"]["failed"] == 1
    assert summary["by_tier"]["complex"]["llm_calls"] == 1
    assert summary["by_tier"]["complex"]["cost_usd"] == 0.4
    assert summary["escalated_calls"] == 2
    assert "local" in summary["by_tier"]["simple"]["models"]
