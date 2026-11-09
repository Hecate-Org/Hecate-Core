"""Demotion eval gates for locked complex capabilities."""

from __future__ import annotations

from pathlib import Path

import pytest

from hecate_agent.core.llm_demotion import (
    ALLOW_DEMOTION_ENV,
    COMPLEX_LOCKED_CAPABILITIES,
    apply_demotion_locks,
    demotion_unlocked,
    evaluate_demotion_gate,
    write_demotion_gate,
)
from hecate_agent.core.llm_router import resolve_capability_tiers
from tests.core.test_eval_harness import FakeProvider, LSASS_FIXTURE


def test_locked_capabilities_ignore_config_demotion_without_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(ALLOW_DEMOTION_ENV, raising=False)
    monkeypatch.setenv("HECATE_LLM_DEMOTION_GATES", str(tmp_path / "gates.json"))
    mapping = apply_demotion_locks({"hypothesis": "simple", "source_extraction": "simple"})
    assert mapping["hypothesis"] == "complex"
    assert mapping["source_extraction"] == "simple"


def test_allow_env_unlocks_demotion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ALLOW_DEMOTION_ENV, "1")
    assert demotion_unlocked("hypothesis")
    mapping = apply_demotion_locks({"hypothesis": "simple"})
    assert mapping["hypothesis"] == "simple"


def test_gate_stamp_unlocks_demotion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ALLOW_DEMOTION_ENV, raising=False)
    gate_path = tmp_path / "gates.json"
    monkeypatch.setenv("HECATE_LLM_DEMOTION_GATES", str(gate_path))

    provider = FakeProvider(responses={LSASS_FIXTURE.prompt: "LSASS memory dump"})
    result = evaluate_demotion_gate(
        provider, "research_synthesize", fail_under=0.5, fixtures=[LSASS_FIXTURE]
    )
    assert result.allowed
    write_demotion_gate(result, path=gate_path)
    assert demotion_unlocked("research_synthesize", path=gate_path)

    mapping = resolve_capability_tiers(
        {"defaults": {"research_synthesize": "simple"}},
    )
    # resolve_capability_tiers uses default gate path from env
    assert mapping["research_synthesize"] == "simple"


def test_failing_gate_does_not_unlock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ALLOW_DEMOTION_ENV, raising=False)
    gate_path = tmp_path / "gates.json"
    monkeypatch.setenv("HECATE_LLM_DEMOTION_GATES", str(gate_path))
    provider = FakeProvider(default="nope")
    result = evaluate_demotion_gate(
        provider, "hypothesis", fail_under=1.0, fixtures=[LSASS_FIXTURE]
    )
    assert not result.allowed
    write_demotion_gate(result, path=gate_path)  # stamp records allowed=false
    assert not demotion_unlocked("hypothesis", path=gate_path)


def test_complex_locked_set_covers_judgement_stages() -> None:
    assert "hypothesis" in COMPLEX_LOCKED_CAPABILITIES
    assert "sigma_draft" in COMPLEX_LOCKED_CAPABILITIES
    assert "source_extraction" not in COMPLEX_LOCKED_CAPABILITIES
