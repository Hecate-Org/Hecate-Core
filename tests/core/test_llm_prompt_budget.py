"""Simple-tier prompt clipping stays under the local context budget."""

from hecate_agent.core.llm_prompt_budget import (
    TRUNCATION_MARKER,
    clip_messages_for_tier,
    clip_text_for_simple,
    simple_max_prompt_chars,
)
from hecate_agent.core.llm_provider import LLMProvider, LLMResponse
from hecate_agent.core.llm_router import LLMRouter


class _Capture(LLMProvider):
    def __init__(self) -> None:
        self.seen: list[list[dict[str, str]]] = []

    def complete(self, messages, max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
        self.seen.append(list(messages))
        return LLMResponse(
            text="ok", model="x", input_tokens=1, output_tokens=1, duration_ms=1, cost_usd=0.0
        )

    @property
    def provider_name(self) -> str:
        return "capture"


def test_complex_tier_is_not_clipped():
    huge = "x" * (simple_max_prompt_chars() + 5000)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": huge}]
    out = clip_messages_for_tier(messages, "complex")
    assert out[1]["content"] == huge
    assert TRUNCATION_MARKER not in out[1]["content"]


def test_simple_tier_clips_user_message_and_keeps_system():
    budget = 200
    messages = [
        {"role": "system", "content": "keep-me"},
        {"role": "user", "content": "u" * 500},
    ]
    out = clip_messages_for_tier(messages, "simple", max_chars=budget)
    assert out[0]["content"] == "keep-me"
    assert TRUNCATION_MARKER in out[1]["content"]
    assert sum(len(m["content"]) for m in out) <= budget


def test_router_clips_only_simple_complete():
    simple = _Capture()
    complex_ = _Capture()
    router = LLMRouter({"simple": simple, "complex": complex_})
    huge = [{"role": "user", "content": "y" * (simple_max_prompt_chars() + 1000)}]
    router.complete(huge, tier="simple")
    router.complete(huge, tier="complex")
    assert TRUNCATION_MARKER in simple.seen[0][0]["content"]
    assert TRUNCATION_MARKER not in complex_.seen[0][0]["content"]


def test_clip_text_for_simple_respects_budget(monkeypatch):
    monkeypatch.setenv("HECATE_LLM_SIMPLE_MAX_PROMPT_CHARS", "80")
    text = clip_text_for_simple("z" * 200)
    assert TRUNCATION_MARKER in text
    assert len(text) <= 80
