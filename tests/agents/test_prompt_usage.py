import logging
from concurrent.futures import ThreadPoolExecutor

from hecate_agent.agents.base import LLMAgent
from hecate_agent.core.llm_provider import LLMProvider, LLMResponse


class Agent(LLMAgent[str, str]):
    def execute(self, input_data):
        return self._call_llm(input_data)


class Provider(LLMProvider):
    def __init__(self, counts, texts=None):
        self.counts = iter(counts)
        self.texts = iter(texts or ["ok"] * len(counts))
        self.prompts = []

    @property
    def provider_name(self):
        return "fake"

    def complete(self, messages, max_tokens=4096, temperature=0.7):
        self.prompts.append(messages[0]["content"])
        return LLMResponse(
            text=next(self.texts),
            input_tokens=next(self.counts),
            output_tokens=7,
            model="qwen/local",
            cost_usd=0,
            duration_ms=1,
        )


def test_full_prompt_usage_is_reported_without_logging_source_content(caplog):
    provider = Provider([100, 250])
    agent = Agent(provider=provider)
    secret = "PRIVATE_HUNT_CONTEXT"
    with caplog.at_level(logging.INFO):
        agent._call_llm("Instructions\n" + secret)
        agent._call_llm("More instructions\n" + secret)
    usage = agent._llm_usage_metadata()
    assert usage["input_tokens"] == 350
    assert usage["max_input_tokens"] == 250
    assert usage["input_token_samples"] == usage["llm_calls"] == 2
    assert "provider_input_tokens=250" in caplog.text
    assert "prompt_chars=" in caplog.text
    assert secret not in caplog.text
    agent._reset_llm_usage()
    assert agent._llm_usage_metadata()["max_input_tokens"] is None
    assert agent._llm_usage_metadata()["input_token_samples"] == 0


def test_retry_feedback_counts_toward_full_prompt_usage():
    provider = Provider([100, 300], ["invalid", "valid"])
    agent = Agent(provider=provider)
    assert (
        agent._call_llm_with_retry(
            "Instructions", lambda text: None if text == "valid" else "try again", max_retries=1, backoff_base_sec=0
        )
        == "valid"
    )
    assert "Failed validation" in provider.prompts[1]
    usage = agent._llm_usage_metadata()
    assert usage["input_tokens"] == 400
    assert usage["max_input_tokens"] == 300
    assert usage["input_token_samples"] == 2


def test_missing_input_usage_is_explicit(caplog):
    agent = Agent(provider=Provider([0]))
    with caplog.at_level(logging.INFO):
        agent._call_llm("actual nonempty prompt")
    assert agent._llm_usage_metadata()["max_input_tokens"] is None
    assert agent._llm_usage_metadata()["input_token_samples"] == 0
    assert "provider_input_tokens=unavailable" in caplog.text


def test_parallel_calls_keep_peak_and_totals_separate():
    agent = Agent()
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(agent._log_llm_metrics, "test", "qwen/local", n, 5, 0, 1) for n in (100, 400, 200, 300)]
        for future in futures:
            future.result()
    usage = agent._llm_usage_metadata()
    assert usage["input_tokens"] == 1000
    assert usage["max_input_tokens"] == 400
    assert usage["input_token_samples"] == usage["llm_calls"] == 4
