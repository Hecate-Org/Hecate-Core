"""Source reuse must preserve grounding, budgets and honest usage metrics."""

import json
import sqlite3
from unittest.mock import Mock

import pytest

from hecate_agent.core import llm_provider, source_evidence as se, source_extraction as sx
from hecate_agent.core.provenance import IndicatorRecord

URL = "https://report.example/article"
PAGE = "The malware launches cmd.exe. Its C2 domain is evil.example."
REPLY = json.dumps({"artifacts": [{"value": "cmd.exe", "kind": "process", "evidence": "The malware launches cmd.exe."}]})


@pytest.fixture
def provider(monkeypatch):
    class Provider:
        provider_name = "fake"
        model = "model-v1"
        base_url = "http://model.example"

        def respond(self, messages, *, max_tokens, temperature):
            return llm_provider.LLMResponse(
                text=REPLY,
                input_tokens=100,
                output_tokens=30,
                model=self.model,
                duration_ms=250,
                cost_usd=0.01,
            )

    instance = Provider()
    instance.complete = Mock(side_effect=instance.respond)
    # Session now builds a router; inject the fake backend for both tiers.
    monkeypatch.setattr(
        "hecate_agent.core.llm_router.create_router",
        Mock(return_value=instance),
    )
    return instance


def session(tmp_path, **kwargs):
    return sx.SourceExtractionSession(cache_path=tmp_path / "cache.db", **kwargs)


def extract(tmp_path, *, text=PAGE, url=URL, **kwargs):
    return se.extract_source_evidence(url, page_text=text, session=session(tmp_path, **kwargs))


def test_persistent_cache_reports_zero_new_model_usage(tmp_path, provider):
    first = extract(tmp_path)
    second = extract(tmp_path)
    assert second.artifacts == first.artifacts
    assert provider.complete.call_count == 1
    assert second.extraction_metrics["cache_hits"] == 1
    assert second.extraction_metrics["model_calls"] == 0
    assert second.usage_metadata()["input_tokens"] == 0
    assert second.usage_metadata()["estimated_cost_usd"] == 0


@pytest.mark.parametrize("change", ["content", "url", "prompt", "model", "endpoint", "version"])
def test_cache_invalidation(tmp_path, provider, monkeypatch, change):
    extract(tmp_path)
    text, url = PAGE, URL
    if change == "content":
        text += " New report revision."
    elif change == "url":
        url += "?revision=2"
    elif change == "prompt":
        monkeypatch.setattr(se, "SYSTEM_PROMPT", se.SYSTEM_PROMPT + " New extraction instruction.")
    elif change == "model":
        provider.model = "model-v2"
    elif change == "endpoint":
        provider.base_url = "http://other.example"
    else:
        monkeypatch.setattr(sx, "EXTRACTOR_VERSION", "next")
    evidence = extract(tmp_path, text=text, url=url)
    assert provider.complete.call_count == 2
    assert evidence.extraction_metrics["cache_hits"] == 0


def test_source_is_refetched_before_cache_lookup(tmp_path, provider, monkeypatch):
    fetch = Mock(side_effect=[PAGE, PAGE, PAGE + " Updated."])
    monkeypatch.setattr(se, "fetch_page_text", fetch)
    for _ in range(3):
        se.extract_source_evidence(URL, session=session(tmp_path))
    assert fetch.call_count == 3
    assert provider.complete.call_count == 2


def test_expiration_and_disabled_cache(tmp_path, provider, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(sx.time, "time", lambda: clock[0])
    extract(tmp_path, cache_ttl_sec=10)
    clock[0] += 11
    extract(tmp_path, cache_ttl_sec=10)
    extract(tmp_path, cache_ttl_sec=0)
    assert provider.complete.call_count == 3


def test_corrupt_or_ungrounded_cache_entry_is_recomputed(tmp_path, provider):
    extract(tmp_path)
    for reply in ["broken JSON", json.dumps({"artifacts": [{"value": "invented.exe", "kind": "process"}]})]:
        with sqlite3.connect(tmp_path / "cache.db") as conn:
            conn.execute("UPDATE responses SET reply = ?", (reply,))
        result = extract(tmp_path)
        assert [a.value for a in result.artifacts] == ["cmd.exe"]
        assert result.extraction_metrics["cache_hits"] == 0
    assert provider.complete.call_count == 3


def test_failed_or_malformed_response_is_not_cached(tmp_path, provider):
    provider.complete.side_effect = [
        RuntimeError("provider failed"),
        llm_provider.LLMResponse("truncated", 100, 30, "fake", 1, 0.0),
        provider.respond([], max_tokens=3000, temperature=0),
    ]
    for _ in range(3):
        extract(tmp_path)
    assert provider.complete.call_count == 3
    assert extract(tmp_path).extraction_metrics["cache_hits"] == 1


def test_cache_failure_is_nonfatal(tmp_path, provider):
    (tmp_path / "cache.db").write_text("not a SQLite database")
    assert extract(tmp_path).artifacts
    assert provider.complete.call_count == 1


def test_call_budget_is_shared_with_classification(tmp_path, provider):
    budget = session(tmp_path, max_calls=1)
    evidence = se.extract_source_evidence(URL, page_text=PAGE, session=budget)
    records = se.build_indicator_records({"domain": ["evil.example"]}, evidence, session=budget)
    assert provider.complete.call_count == 1
    assert evidence.artifacts  # Verified extraction survives exhausted classification.
    assert records[0].role == "unknown"
    assert evidence.extraction_metrics["budget_exhausted"]
    assert any("budget exhausted" in note for note in evidence.dropped)


def test_cache_hit_does_not_spend_classification_budget(tmp_path, provider):
    extract(tmp_path)
    budget = session(tmp_path, max_calls=1)
    evidence = se.extract_source_evidence(URL, page_text=PAGE, session=budget)
    se.build_indicator_records({"domain": ["evil.example"]}, evidence, session=budget)
    assert budget.calls == 1
    assert evidence.extraction_metrics["cache_hits"] == 1
    assert provider.complete.call_count == 2


def test_failed_calls_consume_budget_and_usage_stays_unknown(tmp_path, provider):
    provider.complete.side_effect = RuntimeError("offline")
    result = extract(tmp_path, text=PAGE * 600, max_calls=2)
    assert provider.complete.call_count == 2
    assert result.extraction_metrics["budget_exhausted"]
    assert result.usage_metadata()["input_tokens"] is None
    assert result.usage_metadata()["estimated_cost_usd"] is None


def test_token_budget_rejects_oversized_prompt_without_calling_model(tmp_path, provider):
    evidence = extract(tmp_path, max_tokens=1)
    provider.complete.assert_not_called()
    assert evidence.extraction_metrics["budget_exhausted"]
    assert "incomplete" in evidence.error


def test_remaining_tokens_cap_output_even_when_usage_is_missing(tmp_path, provider):
    prompt_bytes = len(se.SYSTEM_PROMPT.encode()) + len(PAGE.encode()) + 512
    evidence = extract(tmp_path, max_tokens=prompt_bytes + 50)
    assert provider.complete.call_args.kwargs["max_tokens"] == 50
    assert evidence.extraction_metrics["token_budget_used"] <= prompt_bytes + 50
    assert evidence.extraction_metrics["attempts"][0]["input_tokens"] == 100


def test_missing_provider_token_counts_cannot_bypass_the_budget(tmp_path, provider, monkeypatch):
    chunks = ["cmd.exe", "another cmd.exe"]
    monkeypatch.setattr(se, "chunk_text", lambda text: chunks)
    provider.complete.side_effect = lambda *args, **kwargs: llm_provider.LLMResponse(REPLY, 0, 0, "fake", 1, 0.0)
    prompt_bytes = len(se.SYSTEM_PROMPT.encode()) + len(chunks[0].encode()) + 512
    evidence = extract(tmp_path, max_tokens=prompt_bytes + len(REPLY.encode()))
    assert provider.complete.call_count == 1
    assert evidence.extraction_metrics["budget_exhausted"]
    assert evidence.usage_metadata()["input_tokens"] is None
    assert evidence.extraction_metrics["attempts"][0]["input_tokens"] is None


def test_retry_budget_prioritizes_unread_original_chunks(tmp_path, provider, monkeypatch):
    chunks = ["first " * 400, "second " * 400]
    monkeypatch.setattr(se, "chunk_text", lambda text: chunks)
    provider.complete.side_effect = lambda *args, **kwargs: llm_provider.LLMResponse("bad", 100, 30, "fake", 1, 0.0)
    evidence = extract(tmp_path, max_calls=3)
    assert [call.args[0][1]["content"] for call in provider.complete.call_args_list[:2]] == chunks
    assert provider.complete.call_count == 3
    rows = evidence.extraction_metrics["attempts"]
    assert [row["retry_depth"] for row in rows[:3]] == [0, 0, 1]
    assert all(row["duration_ms"] >= 0 for row in rows)
    assert rows[-1]["status"] == "budget_exhausted"


def test_cache_entry_count_is_bounded(tmp_path, provider, monkeypatch):
    monkeypatch.setattr(sx, "MAX_CACHE_ENTRIES", 2)
    for revision in range(4):
        extract(tmp_path, url=f"{URL}?rev={revision}")
    with sqlite3.connect(tmp_path / "cache.db") as conn:
        assert conn.execute("SELECT count(*) FROM responses").fetchone()[0] == 2


def test_one_provider_instance_is_reused_across_chunks_and_classification(
    tmp_path, provider, monkeypatch
):
    from hecate_agent.core import llm_router

    budget = session(tmp_path)
    evidence = se.extract_source_evidence(URL, page_text=PAGE * 200, session=budget)
    se.classify_feed_indicators([IndicatorRecord("evil.example", "domain")], evidence, session=budget)
    llm_router.create_router.assert_called_once()
    assert provider.complete.call_count > 1


def test_extraction_session_routes_phases_through_router(tmp_path, monkeypatch):
    from hecate_agent.core.llm_router import LLMRouter

    class Backend:
        def __init__(self, name: str, model: str, text: str = REPLY) -> None:
            self.provider_name = name
            self.model = model
            self.model_id = None
            self.base_url = None
            self.region = None
            self.num_ctx = None
            self.think = None
            self.complete = Mock(
                return_value=llm_provider.LLMResponse(text, 10, 5, model, 1, 0.0)
            )

    simple = Backend("ollama", "local")
    complex_ = Backend("cloud", "cloud")
    router = LLMRouter({"simple": simple, "complex": complex_})
    monkeypatch.setattr("hecate_agent.core.llm_router.create_router", lambda: router)

    budget = session(tmp_path)
    se.extract_source_evidence(URL, page_text=PAGE, session=budget)
    assert simple.complete.call_count == 1
    assert complex_.complete.call_count == 0


def test_extraction_escalates_invalid_simple_reply(tmp_path, monkeypatch):
    from hecate_agent.core.llm_router import LLMRouter

    class Backend:
        def __init__(self, name: str, model: str, text: str) -> None:
            self.provider_name = name
            self.model = model
            self.model_id = None
            self.base_url = None
            self.region = None
            self.num_ctx = None
            self.think = None
            self.complete = Mock(
                return_value=llm_provider.LLMResponse(text, 10, 5, model, 1, 0.0)
            )

    simple = Backend("ollama", "local", "not valid json")
    complex_ = Backend("cloud", "cloud", REPLY)
    router = LLMRouter({"simple": simple, "complex": complex_})
    monkeypatch.setattr("hecate_agent.core.llm_router.create_router", lambda: router)

    budget = session(tmp_path, max_calls=4)
    evidence = se.extract_source_evidence(URL, page_text=PAGE, session=budget)
    assert simple.complete.call_count == 1
    assert complex_.complete.call_count == 1
    assert [a.value for a in evidence.artifacts] == ["cmd.exe"]
    assert any(row.get("escalated") for row in evidence.extraction_metrics["attempts"])
