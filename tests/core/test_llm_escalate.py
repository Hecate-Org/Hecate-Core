"""Simple→complex escalation on validation failure."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


from hecate_agent.agents.base import LLMAgent
from hecate_agent.core.llm_escalate import can_escalate, complete_with_escalation
from hecate_agent.core.llm_provider import LLMProvider, LLMResponse
from hecate_agent.core.llm_router import LLMRouter


class _Backend(LLMProvider):
    def __init__(self, name: str, texts: List[str]) -> None:
        self._name = name
        self.model = name
        self.texts = list(texts)
        self.calls = 0

    @property
    def provider_name(self) -> str:
        return self._name

    def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        text = self.texts[min(self.calls, len(self.texts) - 1)]
        self.calls += 1
        return LLMResponse(text=text, input_tokens=1, output_tokens=1, model=self.model, duration_ms=1, cost_usd=0.0)


def test_can_escalate_requires_distinct_simple_backend() -> None:
    shared = _Backend("same", ["ok"])
    shared_router = LLMRouter({"simple": shared, "complex": shared})
    assert not can_escalate(shared_router, capability="pivot_suggest")

    simple = _Backend("ollama", ["bad"])
    complex_ = _Backend("cloud", ["good"])
    router = LLMRouter(
        {"simple": simple, "complex": complex_},
        capability_tiers={"pivot_suggest": "simple"},
    )
    assert can_escalate(router, capability="pivot_suggest")
    assert not can_escalate(router, capability="hypothesis")


def test_complete_with_escalation_retries_on_complex() -> None:
    simple = _Backend("ollama", ["not-json"])
    complex_ = _Backend("cloud", ['{"observables": []}'])
    router = LLMRouter(
        {"simple": simple, "complex": complex_},
        capability_tiers={"artifact_extract": "simple"},
    )

    response, escalated = complete_with_escalation(
        router,
        [{"role": "user", "content": "x"}],
        validate=lambda text: text.startswith("{"),
        capability="artifact_extract",
    )
    assert escalated
    assert response.text.startswith("{")
    assert simple.calls == 1
    assert complex_.calls == 1


def test_call_llm_with_retry_escalates_after_simple_failures() -> None:
    simple = _Backend("ollama", ["bad", "still-bad"])
    complex_ = _Backend("cloud", ['{"ok": true}'])
    router = LLMRouter(
        {"simple": simple, "complex": complex_},
        capability_tiers={"pivot_suggest": "simple"},
    )

    class Stub(LLMAgent[dict, dict]):
        def execute(self, input_data: dict) -> Any:
            return self._success({})

    agent = Stub(provider=router)

    def validate(text: str) -> Optional[str]:
        return None if text.startswith("{") else "expected json object"

    result = agent._call_llm_with_retry(
        "prompt",
        validate,
        max_retries=1,
        backoff_base_sec=0,
        capability="pivot_suggest",
    )
    assert result.startswith("{")
    assert simple.calls == 2  # initial + one retry
    assert complex_.calls == 1  # escalate
