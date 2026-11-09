"""Dual-backend LLM router: config resolution and tier selection."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from hecate_agent.core.llm_provider import LLMProvider, LLMResponse
from hecate_agent.core.llm_router import (
    DEFAULT_CAPABILITY_TIERS,
    LLMRouter,
    RECOMMENDED_CAPABILITY_TIERS,
    apply_recommended_capability_tiers,
    create_router,
    resolve_capability_tiers,
    resolve_tier_config,
)


class _FakeProvider(LLMProvider):
    def __init__(self, name: str, model: str = "fake") -> None:
        self._name = name
        self.model = model
        self.calls: List[Dict[str, Any]] = []

    @property
    def provider_name(self) -> str:
        return self._name

    def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        self.calls.append({"messages": messages, "max_tokens": max_tokens, "temperature": temperature})
        return LLMResponse(
            text=f"from-{self._name}",
            input_tokens=1,
            output_tokens=1,
            model=self.model,
            duration_ms=1,
            cost_usd=0.0,
        )


def test_default_capability_map_routes_volume_to_simple() -> None:
    assert DEFAULT_CAPABILITY_TIERS["source_extraction"] == "simple"
    assert DEFAULT_CAPABILITY_TIERS["feed_classification"] == "simple"
    assert DEFAULT_CAPABILITY_TIERS["research_summarize"] == "simple"
    assert DEFAULT_CAPABILITY_TIERS["artifact_extract"] == "simple"
    assert DEFAULT_CAPABILITY_TIERS["pivot_suggest"] == "simple"
    assert DEFAULT_CAPABILITY_TIERS["hypothesis"] == "complex"
    assert DEFAULT_CAPABILITY_TIERS["sigma_draft"] == "complex"
    assert DEFAULT_CAPABILITY_TIERS["research_synthesize"] == "complex"
    assert RECOMMENDED_CAPABILITY_TIERS == DEFAULT_CAPABILITY_TIERS


def test_resolve_tier_config_overlays_nested_and_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HECATE_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("HECATE_LLM_MODEL", "base-model")
    monkeypatch.setenv("HECATE_LLM_SIMPLE_MODEL", "local-model")
    monkeypatch.delenv("HECATE_LLM_SIMPLE_PROVIDER", raising=False)

    cfg = resolve_tier_config(
        "simple",
        {
            "provider": "ollama",
            "model": "base-model",
            "simple": {"provider": "ollama", "model": "ignored-by-env"},
        },
    )
    assert cfg["provider"] == "ollama"
    assert cfg["model"] == "local-model"


def test_resolve_capability_tiers_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_LLM_ALLOW_DEMOTION", "1")
    mapping = resolve_capability_tiers({"defaults": {"hypothesis": "simple", "sigma_draft": "complex"}})
    assert mapping["hypothesis"] == "simple"
    assert mapping["sigma_draft"] == "complex"
    assert mapping["source_extraction"] == "simple"  # untouched default


def test_resolve_capability_tiers_blocks_locked_demotion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("HECATE_LLM_ALLOW_DEMOTION", raising=False)
    monkeypatch.setenv("HECATE_LLM_DEMOTION_GATES", str(tmp_path / "missing.json"))
    mapping = resolve_capability_tiers({"defaults": {"hypothesis": "simple"}})
    assert mapping["hypothesis"] == "complex"


def test_router_routes_by_capability_and_explicit_tier() -> None:
    simple = _FakeProvider("ollama", "local")
    complex_ = _FakeProvider("litellm", "cloud")
    router = LLMRouter(
        {"simple": simple, "complex": complex_},
        capability_tiers={"sigma_draft": "complex", "artifact_extract": "simple"},
    )

    assert router.resolve_tier(capability="artifact_extract") == "simple"
    assert router.resolve_tier(capability="sigma_draft") == "complex"
    assert router.resolve_tier() == "complex"
    assert router.resolve_tier(tier="simple") == "simple"

    text = router.complete(
        [{"role": "user", "content": "hi"}],
        capability="artifact_extract",
    ).text
    assert text == "from-ollama"
    assert len(simple.calls) == 1
    assert complex_.calls == []

    router.complete([{"role": "user", "content": "hi"}], tier="complex")
    assert len(complex_.calls) == 1


def test_create_router_shares_backend_when_tiers_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("HECATE_LLM_MODEL", "qwen2.5:7b")
    monkeypatch.delenv("HECATE_LLM_SIMPLE_PROVIDER", raising=False)
    monkeypatch.delenv("HECATE_LLM_SIMPLE_MODEL", raising=False)
    monkeypatch.delenv("HECATE_LLM_COMPLEX_PROVIDER", raising=False)
    monkeypatch.delenv("HECATE_LLM_COMPLEX_MODEL", raising=False)

    fake = _FakeProvider("ollama", "qwen2.5:7b")
    monkeypatch.setattr(
        "hecate_agent.core.llm_router.create_provider",
        lambda config=None: fake,
    )
    router = create_router()
    assert router.simple is router.complex


def test_create_router_builds_distinct_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_LLM_SIMPLE_PROVIDER", "ollama")
    monkeypatch.setenv("HECATE_LLM_SIMPLE_MODEL", "local")
    monkeypatch.setenv("HECATE_LLM_COMPLEX_PROVIDER", "openai")
    monkeypatch.setenv("HECATE_LLM_COMPLEX_MODEL", "gpt-4o")

    built: List[Dict[str, Any]] = []

    def _fake_create(config=None):
        cfg = dict(config or {})
        built.append(cfg)
        return _FakeProvider(str(cfg.get("provider")), str(cfg.get("model")))

    monkeypatch.setattr("hecate_agent.core.llm_router.create_provider", _fake_create)
    # Avoid workspace/env base provider colliding with fingerprints
    monkeypatch.delenv("HECATE_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("HECATE_LLM_MODEL", raising=False)

    router = create_router()
    assert router.simple is not router.complex
    assert router.simple.provider_name == "ollama"
    assert router.complex.provider_name == "openai"
    assert len(built) == 2


def test_apply_recommended_capability_tiers() -> None:
    router = LLMRouter({"simple": _FakeProvider("a"), "complex": _FakeProvider("b")})
    apply_recommended_capability_tiers(router)
    assert router.resolve_tier(capability="source_extraction") == "simple"
    assert router.resolve_tier(capability="hypothesis") == "complex"


def test_router_complete_tags_call_log(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    from hecate_agent.core import llm_activity

    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv(llm_activity.CALL_LOG_ENV, str(log))
    router = LLMRouter(
        {"simple": _FakeProvider("ollama"), "complex": _FakeProvider("cloud")},
        capability_tiers={"pivot_suggest": "simple"},
    )
    router.complete([{"role": "user", "content": "x"}], capability="pivot_suggest")
    lines = [json.loads(line) for line in log.read_text().splitlines()]
    assert lines[0]["event"] == "start"
    assert lines[0]["tier"] == "simple"
    assert lines[0]["capability"] == "pivot_suggest"
    assert lines[1]["event"] == "end"
    assert lines[1]["tier"] == "simple"
    summary = llm_activity.summarize_calls(log.read_text().splitlines())
    assert summary["tiers"] == ["simple"]
    assert summary["capabilities"] == ["pivot_suggest"]


def test_llm_agent_uses_router_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from hecate_agent.agents.base import LLMAgent

    class Stub(LLMAgent[dict, dict]):
        def execute(self, input_data):
            return self._success({})

    simple = _FakeProvider("ollama", "local")
    complex_ = _FakeProvider("litellm", "cloud")
    router = LLMRouter(
        {"simple": simple, "complex": complex_},
        capability_tiers={"hypothesis": "complex"},
    )
    agent = Stub(provider=router)
    text = agent._call_llm("prompt", capability="hypothesis")
    assert text == "from-litellm"
    assert complex_.calls and not simple.calls
