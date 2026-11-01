"""Tests for hecate_agent.core.llm_provider - model-agnostic LLM provider layer."""

import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from hecate_agent.core.llm_provider import (
    BedrockProvider,
    LiteLLMProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    create_provider,
)

# ---------------------------------------------------------------------------
# LiteLLM provider
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLiteLLMProvider:
    """Test LiteLLMProvider with mocked litellm."""

    def test_litellm_provider_complete(self):
        """Mocked litellm.completion returns a properly parsed LLMResponse."""
        mock_usage = MagicMock()
        mock_usage.prompt_tokens = 80
        mock_usage.completion_tokens = 40

        mock_message = MagicMock()
        mock_message.content = "LiteLLM response"

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage = mock_usage

        mock_litellm = MagicMock()
        mock_litellm.completion.return_value = mock_response

        with patch.dict(sys.modules, {"litellm": mock_litellm}):
            provider = LiteLLMProvider(model="anthropic/claude-sonnet-4-5-20250514")
            result = provider.complete(messages=[{"role": "user", "content": "Hi"}])

        assert result.text == "LiteLLM response"
        assert result.input_tokens == 80
        assert result.output_tokens == 40
        assert result.model == "anthropic/claude-sonnet-4-5-20250514"
        assert provider.provider_name == "litellm"

        # Verify the request was built correctly
        mock_litellm.completion.assert_called_once_with(
            model="anthropic/claude-sonnet-4-5-20250514",
            messages=[{"role": "user", "content": "Hi"}],
            max_tokens=4096,
            temperature=0.7,
        )

    def test_litellm_provider_import_error(self):
        """ImportError is raised when litellm is not installed."""
        # Remove litellm from sys.modules so the lazy import fails
        with patch.dict(sys.modules, {"litellm": None}):
            provider = LiteLLMProvider()
            with pytest.raises(ImportError, match="litellm"):
                provider.complete(messages=[{"role": "user", "content": "Hi"}])


# ---------------------------------------------------------------------------
# Bedrock provider
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBedrockProvider:
    """Test BedrockProvider with mocked boto3."""

    def _make_mock_client(self, text="Hello from Bedrock", input_tok=100, output_tok=50):
        """Build a mock boto3 bedrock-runtime client."""
        mock_body = MagicMock()
        mock_body.read.return_value = json.dumps(
            {
                "content": [{"text": text}],
                "usage": {
                    "input_tokens": input_tok,
                    "output_tokens": output_tok,
                },
            }
        ).encode()
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = {"body": mock_body}
        return mock_client

    def test_bedrock_provider_complete(self):
        """Mocked Bedrock invoke_model returns a properly parsed LLMResponse."""
        mock_client = self._make_mock_client()

        provider = BedrockProvider(model_id="us.anthropic.claude-sonnet-4-5-20250929-v1:0")
        provider._client = mock_client  # inject mock, bypass boto3 import

        result = provider.complete(messages=[{"role": "user", "content": "Hi"}])

        assert result.text == "Hello from Bedrock"
        assert result.input_tokens == 100
        assert result.output_tokens == 50
        assert provider.provider_name == "bedrock"

        # Verify the Bedrock request body format is preserved
        call_kwargs = mock_client.invoke_model.call_args
        sent_body = json.loads(call_kwargs.kwargs.get("body", call_kwargs[1].get("body", "")))
        assert sent_body["anthropic_version"] == "bedrock-2023-05-31"
        assert sent_body["messages"] == [{"role": "user", "content": "Hi"}]

    def test_bedrock_provider_import_error(self):
        """ImportError is raised when boto3 is not installed."""
        with patch.dict(sys.modules, {"boto3": None}):
            provider = BedrockProvider()
            provider._client = None  # ensure lazy init triggers
            with pytest.raises(ImportError, match="boto3"):
                provider.complete(messages=[{"role": "user", "content": "Hi"}])


# ---------------------------------------------------------------------------
# Ollama provider
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOllamaProvider:
    """Test OllamaProvider with mocked urllib."""

    def test_ollama_provider_complete(self):
        """Mocked urlopen returns a properly parsed LLMResponse."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "message": {"content": "Hello from Ollama"},
                "prompt_eval_count": 10,
                "eval_count": 5,
            }
        ).encode("utf-8")
        mock_resp.status = 200
        # complete() uses `with urlopen(...) as resp:` -- a real HTTPResponse's
        # __enter__ returns itself, so the mock must too (MagicMock's default
        # __enter__ return value is a *different* auto-generated mock).
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            provider = OllamaProvider(model="llama3")
            result = provider.complete(messages=[{"role": "user", "content": "Hi"}])

        assert result.text == "Hello from Ollama"
        assert result.input_tokens == 10
        assert result.output_tokens == 5
        assert result.cost_usd == 0.0
        assert provider.provider_name == "ollama"

    def test_ollama_provider_sends_correct_payload(self):
        """Verify the JSON payload sent to Ollama's /api/chat endpoint."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "message": {"content": "ok"},
                "prompt_eval_count": 1,
                "eval_count": 1,
            }
        ).encode("utf-8")
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp  # see comment in test_ollama_provider_complete

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            provider = OllamaProvider(model="llama3")
            provider.complete(
                messages=[{"role": "user", "content": "test"}],
                max_tokens=512,
                temperature=0.3,
            )

        sent_request = mock_urlopen.call_args[0][0]
        sent_body = json.loads(sent_request.data.decode("utf-8"))
        assert sent_body["model"] == "llama3"
        assert sent_body["messages"] == [{"role": "user", "content": "test"}]
        assert sent_body["stream"] is False
        assert sent_body["options"]["num_predict"] == 512
        assert sent_body["options"]["temperature"] == 0.3
        assert "api/chat" in sent_request.full_url

    def _sent_options(self, provider):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"message": {"content": "ok"}}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            provider.complete(messages=[{"role": "user", "content": "test"}])
        return json.loads(mock_urlopen.call_args[0][0].data.decode("utf-8"))["options"]

    def test_ollama_provider_sends_num_ctx_when_set(self):
        """Ollama's 4096 default silently truncated long research and extraction prompts."""
        assert self._sent_options(OllamaProvider(model="llama3", num_ctx=16384))["num_ctx"] == 16384

    def test_ollama_provider_omits_num_ctx_when_unset(self):
        assert "num_ctx" not in self._sent_options(OllamaProvider(model="llama3"))

    def test_ollama_num_ctx_resolution(self, monkeypatch):
        from hecate_agent.core.llm_provider import _DEFAULT_OLLAMA_NUM_CTX, _ollama_num_ctx

        monkeypatch.delenv("HECATE_OLLAMA_NUM_CTX", raising=False)
        assert _ollama_num_ctx({}) == _DEFAULT_OLLAMA_NUM_CTX
        monkeypatch.setenv("HECATE_OLLAMA_NUM_CTX", "32768")
        assert _ollama_num_ctx({}) == 32768
        assert _ollama_num_ctx({"num_ctx": 8192}) == 8192

    def _sent_body(self, provider):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"message": {"content": "ok"}}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            provider.complete(messages=[{"role": "user", "content": "test"}])
        return json.loads(mock_urlopen.call_args[0][0].data.decode("utf-8"))

    def test_ollama_provider_sends_think_only_when_set(self):
        """qwen3.6 and gemma4 think by default and returned an empty answer; a model without thinking rejects the option."""
        assert "think" not in self._sent_body(OllamaProvider(model="llama3"))
        assert self._sent_body(OllamaProvider(model="qwen3.6", think=False))["think"] is False
        assert self._sent_body(OllamaProvider(model="qwen3.6", think=True))["think"] is True

    def test_ollama_think_resolution(self, monkeypatch):
        from hecate_agent.core.llm_provider import _ollama_think

        monkeypatch.delenv("HECATE_OLLAMA_THINK", raising=False)
        assert _ollama_think({}) is None
        monkeypatch.setenv("HECATE_OLLAMA_THINK", "false")
        assert _ollama_think({}) is False
        assert _ollama_think({"think": True}) is True
        monkeypatch.setenv("HECATE_OLLAMA_THINK", "")
        assert _ollama_think({}) is None

    def test_ollama_provider_connection_error(self):
        """ConnectionError is raised when Ollama is unreachable."""
        from urllib.error import URLError

        with patch(
            "urllib.request.urlopen",
            side_effect=URLError("Connection refused"),
        ):
            provider = OllamaProvider()
            with pytest.raises(ConnectionError, match="Cannot reach Ollama"):
                provider.complete(messages=[{"role": "user", "content": "Hi"}])


# ---------------------------------------------------------------------------
# OpenAI-compatible provider
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenAICompatibleProvider:
    """Test OpenAICompatibleProvider with mocked openai."""

    def test_openai_provider_complete(self):
        """Mocked openai client returns a properly parsed LLMResponse."""
        mock_usage = MagicMock()
        mock_usage.prompt_tokens = 60
        mock_usage.completion_tokens = 30

        mock_message = MagicMock()
        mock_message.content = "Hello from OpenAI"

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage = mock_usage

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        provider = OpenAICompatibleProvider(model="gpt-4o", api_key="test-key")
        provider._client = mock_client  # inject mock, bypass openai import

        result = provider.complete(messages=[{"role": "user", "content": "Hi"}])

        assert result.text == "Hello from OpenAI"
        assert result.input_tokens == 60
        assert result.output_tokens == 30
        assert provider.provider_name == "openai"

        # Verify the request was built correctly
        mock_client.chat.completions.create.assert_called_once_with(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hi"}],
            max_tokens=4096,
            temperature=0.7,
        )


# ---------------------------------------------------------------------------
# create_provider factory
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCreateProvider:
    """Test the create_provider factory with various configurations."""

    def _clean_env(self):
        """Return a dict for patch.dict that clears all auto-detect keys."""
        return {
            "HECATE_LLM_PROVIDER": "",
            "HECATE_LLM_MODEL": "",
            "ANTHROPIC_API_KEY": "",
            "OPENAI_API_KEY": "",
            "AWS_PROFILE": "",
            "AWS_ACCESS_KEY_ID": "",
        }

    def test_create_provider_explicit_config(self):
        """Explicit config dict selects the correct provider class."""
        with (
            patch.object(BedrockProvider, "_get_client", return_value=MagicMock()),
            patch("hecate_agent.core.llm_provider._load_config_file", return_value={}),
            patch.dict("os.environ", self._clean_env(), clear=False),
        ):
            provider = create_provider({"provider": "bedrock", "model": "us.anthropic.claude-sonnet-4-5-v1:0"})
            assert isinstance(provider, BedrockProvider)

    def test_create_provider_env_vars(self):
        """HECATE_LLM_PROVIDER env var selects the correct provider."""
        env = self._clean_env()
        env["HECATE_LLM_PROVIDER"] = "ollama"

        with (
            patch("hecate_agent.core.llm_provider._load_config_file", return_value={}),
            patch.dict("os.environ", env, clear=False),
        ):
            provider = create_provider()
            assert isinstance(provider, OllamaProvider)

    def test_create_provider_auto_detect_anthropic(self):
        """ANTHROPIC_API_KEY triggers LiteLLM provider."""
        env = self._clean_env()
        env["ANTHROPIC_API_KEY"] = "sk-ant-test"

        with (
            patch("hecate_agent.core.llm_provider._load_config_file", return_value={}),
            patch.dict("os.environ", env, clear=False),
        ):
            provider = create_provider()
            assert isinstance(provider, LiteLLMProvider)

    def test_create_provider_auto_detect_openai(self):
        """OPENAI_API_KEY triggers OpenAICompatibleProvider."""
        env = self._clean_env()
        env["OPENAI_API_KEY"] = "sk-test"

        with (
            patch("hecate_agent.core.llm_provider._load_config_file", return_value={}),
            patch.dict("os.environ", env, clear=False),
        ):
            provider = create_provider()
            assert isinstance(provider, OpenAICompatibleProvider)

    def test_create_provider_auto_detect_aws(self):
        """AWS_PROFILE triggers BedrockProvider."""
        env = self._clean_env()
        env["AWS_PROFILE"] = "default"

        with (
            patch("hecate_agent.core.llm_provider._load_config_file", return_value={}),
            patch.dict("os.environ", env, clear=False),
        ):
            provider = create_provider()
            assert isinstance(provider, BedrockProvider)

    def test_create_provider_auto_detect_ollama(self):
        """Running Ollama triggers OllamaProvider when no API keys set."""
        env = self._clean_env()

        with (
            patch("hecate_agent.core.llm_provider._load_config_file", return_value={}),
            patch.dict("os.environ", env, clear=False),
            patch("hecate_agent.core.llm_provider._ollama_is_running", return_value=True),
        ):
            provider = create_provider()
            assert isinstance(provider, OllamaProvider)

    def test_create_provider_no_provider_error(self):
        """RuntimeError when no provider can be determined."""
        env = self._clean_env()

        with (
            patch("hecate_agent.core.llm_provider._load_config_file", return_value={}),
            patch.dict("os.environ", env, clear=False),
            patch("hecate_agent.core.llm_provider._ollama_is_running", return_value=False),
        ):
            with pytest.raises(RuntimeError, match="No LLM provider"):
                create_provider()

    def test_create_provider_unknown_provider(self):
        """ValueError for an unrecognized provider name."""
        with (
            patch("hecate_agent.core.llm_provider._load_config_file", return_value={}),
            patch.dict("os.environ", self._clean_env(), clear=False),
        ):
            with pytest.raises(ValueError, match="Unknown LLM provider"):
                create_provider({"provider": "unknown"})


# ---------------------------------------------------------------------------
# Rate-limit exponential backoff
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRateLimitRetry:
    """Test retry_on_rate_limit backoff behavior."""

    def test_retry_on_rate_limit_succeeds_after_transient_429(self, monkeypatch):
        from hecate_agent.core.llm_provider import retry_on_rate_limit

        calls = [0]
        slept = []
        monkeypatch.setattr("time.sleep", lambda s: slept.append(s))

        class Mock429(Exception):
            status_code = 429

        @retry_on_rate_limit
        def flaky():
            calls[0] += 1
            if calls[0] < 3:
                raise Mock429("Rate limit exceeded")
            return "success"

        result = flaky()
        assert result == "success"
        assert calls[0] == 3
        assert len(slept) == 2

    def test_retry_on_rate_limit_respects_retry_after(self, monkeypatch):
        from hecate_agent.core.llm_provider import retry_on_rate_limit

        slept = []
        monkeypatch.setattr("time.sleep", lambda s: slept.append(s))

        class MockRateLimit(Exception):
            status_code = 429
            retry_after = 2.5

        calls = [0]

        @retry_on_rate_limit
        def with_header():
            calls[0] += 1
            if calls[0] == 1:
                raise MockRateLimit("Rate limit")
            return "ok"

        res = with_header()
        assert res == "ok"
        assert len(slept) == 1
        assert slept[0] == 2.5

    def test_retry_on_rate_limit_exhausted(self, monkeypatch):
        from hecate_agent.core.llm_provider import retry_on_rate_limit

        slept = []
        monkeypatch.setattr("time.sleep", lambda s: slept.append(s))

        class Mock429(Exception):
            status_code = 429

        @retry_on_rate_limit
        def always_fails():
            raise Mock429("429 Too Many Requests")

        with pytest.raises(Mock429):
            always_fails()
        assert len(slept) == 5

    def test_non_rate_limit_error_not_retried(self, monkeypatch):
        from hecate_agent.core.llm_provider import retry_on_rate_limit

        slept = []
        monkeypatch.setattr("time.sleep", lambda s: slept.append(s))

        @retry_on_rate_limit
        def bad_value():
            raise ValueError("bad input")

        with pytest.raises(ValueError, match="bad input"):
            bad_value()
        assert len(slept) == 0

    def test_retry_on_503_service_unavailable(self, monkeypatch):
        from hecate_agent.core.llm_provider import retry_on_rate_limit

        calls = [0]
        slept = []
        monkeypatch.setattr("time.sleep", lambda s: slept.append(s))

        class Mock503(Exception):
            status_code = 503

        @retry_on_rate_limit
        def transient_503():
            calls[0] += 1
            if calls[0] < 2:
                raise Mock503("503 Service Unavailable")
            return "recovered"

        assert transient_503() == "recovered"
        assert calls[0] == 2
        assert len(slept) == 1


# ---------------------------------------------------------------------------
# Circuit Breaker tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCircuitBreaker:
    """Test LLM upstream circuit breaker protection."""

    def test_circuit_breaker_transitions(self, monkeypatch):
        from hecate_agent.core.llm_provider import (
            CircuitBreaker,
            CircuitBreakerOpenError,
            CircuitState,
        )

        current_time = [1000.0]
        monkeypatch.setattr("time.monotonic", lambda: current_time[0])

        cb = CircuitBreaker("test-provider", failure_threshold=3, cooldown_seconds=20.0)
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

        class Mock503(Exception):
            status_code = 503

        # First 2 failures: still CLOSED
        cb.record_failure(Mock503("Service unavailable"))
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 1

        cb.record_failure(Mock503("Service unavailable"))
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 2

        # 3rd failure: trips to OPEN
        cb.record_failure(Mock503("Service unavailable"))
        assert cb.state == CircuitState.OPEN
        assert cb.failure_count == 3
        assert cb.cooldown_remaining == 20.0

        # While OPEN, before_call() raises CircuitBreakerOpenError
        with pytest.raises(CircuitBreakerOpenError) as exc_info:
            cb.before_call()
        assert "Circuit breaker is OPEN for LLM provider 'test-provider'" in str(exc_info.value)
        assert exc_info.value.failure_count == 3

        # Advance time by 10s: still OPEN (cooldown 10s remaining)
        current_time[0] += 10.0
        assert cb.state == CircuitState.OPEN
        assert cb.cooldown_remaining == 10.0

        # Advance time past 20s: transitions to HALF_OPEN
        current_time[0] += 15.0
        assert cb.state == CircuitState.HALF_OPEN

        # Probe call succeeds: resets to CLOSED
        cb.before_call()  # allowed
        cb.record_success()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0
        assert cb.last_error is None

    def test_circuit_breaker_half_open_failure_trips_to_open(self, monkeypatch):
        from hecate_agent.core.llm_provider import CircuitBreaker, CircuitState

        current_time = [1000.0]
        monkeypatch.setattr("time.monotonic", lambda: current_time[0])

        cb = CircuitBreaker("test-probe", failure_threshold=1, cooldown_seconds=30.0)

        class Mock429(Exception):
            status_code = 429

        cb.record_failure(Mock429("Rate limit"))
        assert cb.state == CircuitState.OPEN

        # Advance past cooldown
        current_time[0] += 35.0
        assert cb.state == CircuitState.HALF_OPEN

        # Probe fails: immediately trips back to OPEN
        cb.record_failure(Mock429("Still throttled"))
        assert cb.state == CircuitState.OPEN

    def test_circuit_breaker_auth_failure_threshold(self):
        from hecate_agent.core.llm_provider import CircuitBreaker, CircuitState

        cb = CircuitBreaker("test-auth", failure_threshold=5, auth_failure_threshold=2)

        class Mock401(Exception):
            status_code = 401

        cb.record_failure(Mock401("Unauthorized / Invalid API Key"))
        assert cb.state == CircuitState.CLOSED

        cb.record_failure(Mock401("Unauthorized / Invalid API Key"))
        assert cb.state == CircuitState.OPEN

    def test_circuit_breaker_non_breaker_errors(self):
        from hecate_agent.core.llm_provider import CircuitBreaker, CircuitState

        cb = CircuitBreaker("test-non-breaker", failure_threshold=2)
        cb.record_failure(ValueError("Bad prompt syntax"))
        cb.record_failure(KeyError("missing key"))
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

    def test_circuit_breaker_manual_trip_and_reset(self):
        from hecate_agent.core.llm_provider import CircuitBreaker, CircuitState

        cb = CircuitBreaker("test-manual")
        assert cb.state == CircuitState.CLOSED

        cb.trip("Administrative emergency stop")
        assert cb.state == CircuitState.OPEN
        assert "Administrative emergency stop" in cb.last_error

        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0
        assert cb.last_error is None
