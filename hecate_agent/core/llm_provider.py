"""Model-agnostic LLM provider abstraction for Hecate.

Supports multiple LLM backends (LiteLLM, AWS Bedrock, Ollama, OpenAI-compatible)
with lazy imports so no single provider's dependencies are required at install time.

Usage:
    from hecate_agent.core.llm_provider import create_provider

    provider = create_provider()  # auto-detect from env/config
    response = provider.complete(
        messages=[{"role": "user", "content": "Hello"}],
        max_tokens=1024,
    )
    print(response.text, response.cost_usd)
"""

import json
import logging
import os
import random
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate LLM call cost in USD based on token counts.

    Delegates to the canonical cost_tracker, which maintains the authoritative
    pricing table with fuzzy model-name matching.

    Args:
        model: Model identifier string.
        input_tokens: Number of input/prompt tokens.
        output_tokens: Number of output/completion tokens.

    Returns:
        Estimated cost in USD, rounded to 6 decimal places.
    """
    from hecate_agent.core.cost_tracker import estimate_cost

    return estimate_cost(model, input_tokens, output_tokens)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class LLMResponse:
    """Response from an LLM provider call.

    Attributes:
        text: The generated text content.
        input_tokens: Number of prompt/input tokens consumed.
        output_tokens: Number of completion/output tokens generated.
        model: Model identifier used for the request.
        duration_ms: Wall-clock time of the LLM call in milliseconds.
        cost_usd: Estimated cost of the call in USD.
    """

    text: str
    input_tokens: int
    output_tokens: int
    model: str
    duration_ms: int
    cost_usd: float


# ---------------------------------------------------------------------------
# Rate-limit exponential backoff
# ---------------------------------------------------------------------------


def _is_rate_limit_error(exc: BaseException) -> bool:
    """Check if an exception represents an HTTP 429 rate limit, 503, or transient throttling error."""
    for attr in ("status_code", "http_status", "code"):
        val = getattr(exc, attr, None)
        if val in (429, 503, 502, 504):
            return True

    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        err = resp.get("Error", {})
        code = str(err.get("Code", ""))
        if code in (
            "ThrottlingException",
            "ProvisionedThroughputExceededException",
            "RequestLimitExceeded",
            "TooManyRequestsException",
            "Throttling",
            "ServiceUnavailable",
            "ModelNotReadyException",
            "InternalServerException",
        ):
            return True
        if resp.get("ResponseMetadata", {}).get("HTTPStatusCode") in (429, 503, 502, 504):
            return True

    cls_name = exc.__class__.__name__.lower()
    if any(k in cls_name for k in ("ratelimit", "throttl", "serviceunavailable")):
        return True

    msg = str(exc).lower()
    if any(
        phrase in msg
        for phrase in (
            "429",
            "503",
            "rate limit",
            "too many requests",
            "throttling",
            "throttled",
            "quota exceeded",
            "service unavailable",
            "temporarily unavailable",
        )
    ):
        return True

    return False


def _extract_retry_after(exc: BaseException) -> Optional[float]:
    """Extract Retry-After header or delay hint if present on the exception."""
    retry_after = getattr(exc, "retry_after", None)
    if retry_after is not None:
        try:
            return float(retry_after)
        except (ValueError, TypeError):
            pass

    headers = getattr(exc, "headers", None)
    if isinstance(headers, dict):
        ra = headers.get("retry-after") or headers.get("Retry-After")
        if ra is not None:
            try:
                return float(ra)
            except (ValueError, TypeError):
                pass
    return None


def retry_on_rate_limit(
    fn: Callable[..., Any],
    max_retries: Optional[int] = None,
    initial_backoff: Optional[float] = None,
    backoff_factor: Optional[float] = None,
    max_backoff: Optional[float] = None,
) -> Callable[..., Any]:
    """Decorator / wrapper that retries a function with exponential backoff on HTTP 429 rate limits."""

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        retries = 0
        limit_retries = max_retries if max_retries is not None else int(os.getenv("HECATE_LLM_MAX_RETRIES", "5"))
        cur_backoff = initial_backoff if initial_backoff is not None else float(os.getenv("HECATE_LLM_INITIAL_BACKOFF", "1.0"))
        factor = backoff_factor if backoff_factor is not None else float(os.getenv("HECATE_LLM_BACKOFF_FACTOR", "2.0"))
        cap = max_backoff if max_backoff is not None else float(os.getenv("HECATE_LLM_MAX_BACKOFF", "60.0"))

        while True:
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                if not _is_rate_limit_error(exc) or retries >= limit_retries:
                    raise
                retries += 1
                hint = _extract_retry_after(exc)
                if hint is not None and hint > 0:
                    wait_time = min(hint, cap)
                else:
                    jitter = random.uniform(0.0, 0.25 * cur_backoff)
                    wait_time = min(cur_backoff + jitter, cap)
                    cur_backoff = min(cur_backoff * factor, cap)

                logger.warning(
                    "LLM rate limit encountered (HTTP 429 / %s). Retrying in %.2fs (attempt %d/%d). Error: %s",
                    exc.__class__.__name__,
                    wait_time,
                    retries,
                    limit_retries,
                    exc,
                )
                time.sleep(wait_time)

    return wrapper


# ---------------------------------------------------------------------------
# Circuit Breaker Protection
# ---------------------------------------------------------------------------


class CircuitState(str, Enum):
    """Operational states of an LLM upstream circuit breaker."""

    CLOSED = "CLOSED"  # Normal operations: requests flow through to upstream
    OPEN = "OPEN"  # Tripped: requests fail-fast to prevent cascading outages
    HALF_OPEN = "HALF_OPEN"  # Cooldown period elapsed: single probe allowed to test recovery


class CircuitBreakerOpenError(RuntimeError):
    """Raised when an LLM provider call is blocked by an open circuit breaker."""

    def __init__(
        self,
        provider: str,
        cooldown_remaining: float,
        failure_count: int,
        last_error: Optional[str] = None,
    ):
        self.provider = provider
        self.cooldown_remaining = max(0.0, cooldown_remaining)
        self.failure_count = failure_count
        self.last_error = last_error
        msg = (
            f"Circuit breaker is OPEN for LLM provider '{provider}' after "
            f"{failure_count} consecutive upstream failures. "
            f"Failing fast for another {self.cooldown_remaining:.1f}s to allow upstream recovery. "
            f"Last error: {last_error or 'Unknown failure'}"
        )
        super().__init__(msg)


def _is_breaker_failure(exc: BaseException) -> Tuple[bool, bool]:
    """Classify an exception for circuit breaker tracking.

    Returns:
        (is_breaker_failure, is_auth_failure)
    """
    if isinstance(exc, CircuitBreakerOpenError):
        return False, False

    # Check HTTP status codes on the exception
    for attr in ("status_code", "http_status", "code"):
        val = getattr(exc, attr, None)
        if val in (401, 403):
            return True, True
        if val in (429, 500, 502, 503, 504):
            return True, False

    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
        err = resp.get("Error", {})
        code = str(err.get("Code", ""))
        if status in (401, 403) or code in (
            "UnrecognizedClientException",
            "AccessDeniedException",
            "ExpiredTokenException",
            "AuthFailure",
            "InvalidSignatureException",
        ):
            return True, True
        if status in (429, 500, 502, 503, 504) or code in (
            "ThrottlingException",
            "ProvisionedThroughputExceededException",
            "RequestLimitExceeded",
            "TooManyRequestsException",
            "Throttling",
            "ServiceUnavailable",
            "ModelNotReadyException",
            "InternalServerException",
        ):
            return True, False

    cls_name = exc.__class__.__name__.lower()
    if any(k in cls_name for k in ("authentication", "permissiondenied", "unauthorized", "forbidden")):
        return True, True
    if any(k in cls_name for k in ("ratelimit", "throttl", "serviceunavailable", "timeout", "connect", "network")):
        return True, False

    msg = str(exc).lower()
    if any(
        phrase in msg
        for phrase in (
            "unauthorized",
            "invalid api key",
            "invalid_api_key",
            "forbidden",
            "access denied",
            "authentication failed",
            "expired token",
        )
    ):
        return True, True

    if any(
        phrase in msg
        for phrase in (
            "429",
            "500",
            "502",
            "503",
            "504",
            "rate limit",
            "too many requests",
            "throttling",
            "throttled",
            "service unavailable",
            "temporarily unavailable",
            "connection refused",
            "connection reset",
            "connection error",
            "network error",
            "timeout",
            "timed out",
        )
    ):
        return True, False

    import socket

    if isinstance(exc, (TimeoutError, ConnectionError, socket.timeout)):
        return True, False

    return False, False


class CircuitBreaker:
    """Thread-safe circuit breaker protecting against cascading upstream LLM failures."""

    def __init__(
        self,
        provider_name: str,
        failure_threshold: Optional[int] = None,
        cooldown_seconds: Optional[float] = None,
        auth_failure_threshold: Optional[int] = None,
        half_open_successes: int = 1,
    ):
        self.provider_name = provider_name
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._auth_failure_threshold = auth_failure_threshold
        self.half_open_successes = half_open_successes

        self._lock = threading.RLock()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._auth_failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._last_error: Optional[str] = None

    @property
    def failure_threshold(self) -> int:
        if self._failure_threshold is not None:
            return self._failure_threshold
        return int(os.getenv("HECATE_LLM_CIRCUIT_FAILURE_THRESHOLD", "5"))

    @property
    def cooldown_seconds(self) -> float:
        if self._cooldown_seconds is not None:
            return self._cooldown_seconds
        return float(os.getenv("HECATE_LLM_CIRCUIT_COOLDOWN_SECONDS", "30.0"))

    @property
    def auth_failure_threshold(self) -> int:
        if self._auth_failure_threshold is not None:
            return self._auth_failure_threshold
        return int(os.getenv("HECATE_LLM_CIRCUIT_AUTH_THRESHOLD", "2"))

    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._check_cooldown_transition(time.monotonic())
            return self._state

    @property
    def failure_count(self) -> int:
        with self._lock:
            return self._failure_count

    @property
    def last_error(self) -> Optional[str]:
        with self._lock:
            return self._last_error

    @property
    def cooldown_remaining(self) -> float:
        with self._lock:
            if self._state != CircuitState.OPEN or self._last_failure_time is None:
                return 0.0
            elapsed = time.monotonic() - self._last_failure_time
            return max(0.0, self.cooldown_seconds - elapsed)

    def _check_cooldown_transition(self, now: float) -> None:
        """Transition from OPEN to HALF_OPEN once cooldown has expired. Must hold self._lock."""
        if self._state == CircuitState.OPEN and self._last_failure_time is not None:
            elapsed = now - self._last_failure_time
            if elapsed >= self.cooldown_seconds:
                logger.info(
                    "Circuit breaker for '%s' cooldown expired (%.1fs elapsed). Transitioning to HALF_OPEN probe.",
                    self.provider_name,
                    elapsed,
                )
                self._state = CircuitState.HALF_OPEN
                self._success_count = 0

    def before_call(self) -> None:
        """Check circuit breaker state before executing a call. Raises CircuitBreakerOpenError if OPEN."""
        with self._lock:
            now = time.monotonic()
            self._check_cooldown_transition(now)
            if self._state == CircuitState.OPEN:
                elapsed = now - (self._last_failure_time or now)
                remaining = max(0.0, self.cooldown_seconds - elapsed)
                raise CircuitBreakerOpenError(
                    provider=self.provider_name,
                    cooldown_remaining=remaining,
                    failure_count=self._failure_count,
                    last_error=self._last_error,
                )

    def record_success(self) -> None:
        """Record a successful call, resetting state to CLOSED."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.half_open_successes:
                    logger.info(
                        "Circuit breaker probe call for '%s' succeeded. Resetting to CLOSED.",
                        self.provider_name,
                    )
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._auth_failure_count = 0
                    self._last_error = None
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0
                self._auth_failure_count = 0

    def record_failure(self, exc: BaseException) -> None:
        """Record a failed call and trip breaker to OPEN if threshold exceeded."""
        is_fail, is_auth = _is_breaker_failure(exc)
        if not is_fail:
            return

        with self._lock:
            now = time.monotonic()
            self._last_failure_time = now
            self._last_error = f"{exc.__class__.__name__}: {exc}"

            if is_auth:
                self._auth_failure_count += 1
            self._failure_count += 1

            if self._state == CircuitState.HALF_OPEN:
                logger.warning(
                    "Circuit breaker probe call for '%s' failed. Tripping back to OPEN.",
                    self.provider_name,
                )
                self._state = CircuitState.OPEN
            elif self._state == CircuitState.CLOSED:
                threshold = self.auth_failure_threshold if is_auth else self.failure_threshold
                count = self._auth_failure_count if is_auth else self._failure_count
                if count >= threshold:
                    self._state = CircuitState.OPEN
                    logger.error(
                        "Circuit breaker tripped to OPEN for '%s' after %d consecutive failures (threshold: %d). "
                        "Failing fast for %.1fs. Error: %s",
                        self.provider_name,
                        count,
                        threshold,
                        self.cooldown_seconds,
                        self._last_error,
                    )

    def reset(self) -> None:
        """Manually reset the breaker to CLOSED state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._auth_failure_count = 0
            self._success_count = 0
            self._last_failure_time = None
            self._last_error = None

    def trip(self, reason: str = "manual") -> None:
        """Manually trip the breaker to OPEN state."""
        with self._lock:
            self._state = CircuitState.OPEN
            self._last_failure_time = time.monotonic()
            self._last_error = f"ManualTrip: {reason}"

    def status_dict(self) -> Dict[str, Any]:
        """Return diagnostic dictionary of current circuit breaker metrics."""
        with self._lock:
            self._check_cooldown_transition(time.monotonic())
            return {
                "provider": self.provider_name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "auth_failure_count": self._auth_failure_count,
                "failure_threshold": self.failure_threshold,
                "cooldown_seconds": self.cooldown_seconds,
                "cooldown_remaining": self.cooldown_remaining,
                "last_error": self._last_error,
            }


_CIRCUIT_BREAKERS: Dict[str, CircuitBreaker] = {}
_CB_LOCK = threading.Lock()


def get_circuit_breaker(provider_name: str) -> CircuitBreaker:
    """Retrieve or create the circuit breaker instance for a given provider."""
    with _CB_LOCK:
        if provider_name not in _CIRCUIT_BREAKERS:
            _CIRCUIT_BREAKERS[provider_name] = CircuitBreaker(provider_name)
        return _CIRCUIT_BREAKERS[provider_name]


def reset_all_circuit_breakers() -> None:
    """Reset all registered circuit breakers to CLOSED state."""
    with _CB_LOCK:
        for cb in _CIRCUIT_BREAKERS.values():
            cb.reset()


def get_all_circuit_breakers() -> Dict[str, CircuitBreaker]:
    """Retrieve all registered circuit breakers."""
    with _CB_LOCK:
        return dict(_CIRCUIT_BREAKERS)


def with_circuit_breaker(
    fn: Callable[..., Any],
    provider_name: Optional[str] = None,
) -> Callable[..., Any]:
    """Decorator enforcing circuit breaker protection on an LLM complete() method."""

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        enabled = os.getenv("HECATE_LLM_CIRCUIT_BREAKER_ENABLED", "true").lower() in ("1", "true", "yes")
        if not enabled:
            return fn(*args, **kwargs)

        self_obj = args[0] if args else None
        p_name = str(provider_name or getattr(self_obj, "provider_name", None) or "default")
        cb = get_circuit_breaker(p_name)
        cb.before_call()
        try:
            result = fn(*args, **kwargs)
            cb.record_success()
            return result
        except BaseException as exc:
            cb.record_failure(exc)
            raise

    return wrapper


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class LLMProvider(ABC):
    """Abstract base class for LLM providers.

    Subclasses must implement ``complete`` and ``provider_name``.
    """

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Every provider's calls are visible to the live call log, whoever makes them,
        # with automatic exponential backoff on HTTP 429 rate limits and circuit breaker
        # fast-failing during sustained upstream outages.
        if "complete" in cls.__dict__:
            from hecate_agent.core.llm_activity import recorded

            cls.complete = recorded(with_circuit_breaker(retry_on_rate_limit(cls.__dict__["complete"])))  # type: ignore[method-assign]

    @abstractmethod
    def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """Send a chat-completion request to the LLM.

        Args:
            messages: List of message dicts with ``role`` and ``content`` keys.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature (0.0 - 1.0).

        Returns:
            An LLMResponse with the generated text and metadata.
        """
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return a human-readable name for this provider (e.g. ``'bedrock'``)."""
        ...


# ---------------------------------------------------------------------------
# LiteLLM provider (100+ models)
# ---------------------------------------------------------------------------


class LiteLLMProvider(LLMProvider):
    """Provider backed by the ``litellm`` library.

    Supports 100+ models via a unified interface. The ``litellm`` package is
    imported lazily so it is only required when this provider is actually used.

    Args:
        model: A litellm-compatible model string (e.g. ``"anthropic/claude-sonnet-4-5-20250514"``).
    """

    def __init__(self, model: str = "anthropic/claude-sonnet-4-5-20250514"):
        self.model = model

    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "litellm"

    def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """Complete a chat request via litellm.

        Args:
            messages: Chat messages.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature.

        Returns:
            LLMResponse with results and metrics.

        Raises:
            ImportError: If litellm is not installed.
        """
        try:
            import litellm
        except ImportError:
            raise ImportError("litellm package is not installed. Install it with: pip install litellm")

        start = time.monotonic()
        response = litellm.completion(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        text = response.choices[0].message.content or ""
        usage = response.usage
        input_tokens = getattr(usage, "prompt_tokens", 0) or 0
        output_tokens = getattr(usage, "completion_tokens", 0) or 0

        return LLMResponse(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self.model,
            duration_ms=duration_ms,
            cost_usd=_estimate_cost(self.model, input_tokens, output_tokens),
        )


# ---------------------------------------------------------------------------
# AWS Bedrock provider (backward-compatible)
# ---------------------------------------------------------------------------


class BedrockProvider(LLMProvider):
    """Provider for AWS Bedrock with the Anthropic Messages API.

    Preserves the exact request/response pattern used by the existing Hecate
    codebase for backward compatibility.

    Args:
        model_id: Bedrock model identifier.
        region: AWS region. Defaults to ``AWS_REGION`` / ``AWS_DEFAULT_REGION``
            env vars, then ``us-east-1``.
    """

    def __init__(
        self,
        model_id: str = "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        region: Optional[str] = None,
    ):
        self.model_id = model_id
        self.region = region or os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
        self._client = None  # type: Any

    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "bedrock"

    def _get_client(self) -> Any:
        """Lazily create and cache the Bedrock runtime client.

        Returns:
            A boto3 Bedrock runtime client.

        Raises:
            ImportError: If boto3 is not installed.
            ValueError: If client creation fails (e.g. bad credentials).
        """
        if self._client is not None:
            return self._client

        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 package is not installed. Install it with: pip install boto3")

        try:
            self._client = boto3.client(service_name="bedrock-runtime", region_name=self.region)
        except Exception as exc:
            raise ValueError("Failed to create Bedrock client: {}".format(exc))

        return self._client

    def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """Send a chat-completion request to AWS Bedrock.

        Args:
            messages: Chat messages.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature.

        Returns:
            LLMResponse with results and metrics.

        Raises:
            ImportError: If boto3 is not installed.
            ValueError: If Bedrock client creation or invocation fails.
        """
        client = self._get_client()

        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": messages,
        }

        start = time.monotonic()
        response = client.invoke_model(modelId=self.model_id, body=json.dumps(request_body))
        duration_ms = int((time.monotonic() - start) * 1000)

        response_body = json.loads(response["body"].read())
        text = response_body["content"][0]["text"]

        usage = response_body.get("usage", {})
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)

        return LLMResponse(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self.model_id,
            duration_ms=duration_ms,
            cost_usd=_estimate_cost(self.model_id, input_tokens, output_tokens),
        )


# ---------------------------------------------------------------------------
# Ollama provider (local models, stdlib only)
# ---------------------------------------------------------------------------


class OllamaProvider(LLMProvider):
    """Provider for locally-running Ollama models.

    Uses only ``urllib.request`` from the standard library so there are zero
    external dependencies.

    Args:
        model: Ollama model name (e.g. ``"llama3"``).
        base_url: Ollama HTTP API base URL.
        timeout_sec: Per-request HTTP timeout. Larger local models (e.g.
            14B+ quantized models that spill past GPU VRAM) can take well
            over a minute to complete a single 2048-token generation, so
            this defaults higher than a typical API timeout. Override via
            the ``HECATE_OLLAMA_TIMEOUT_SEC`` env var or the ``timeout_sec``
            config key.
        num_ctx: Context window, in tokens, requested per call. Ollama's own
            default is 4096, and it silently drops the start of any longer
            prompt: 36 "truncating input prompt" events in this workspace's
            Ollama log before this was set, on research and artifact-extraction
            prompts. Override via ``HECATE_OLLAMA_NUM_CTX`` or the ``num_ctx``
            config key.
        think: Whether a reasoning model thinks before it answers. ``None``
            leaves the model's own default and sends nothing, which is what a
            model without the feature needs: Ollama rejects the option for one.
            Newer models think by default (``qwen3.6``, ``gemma4``) and spend
            the generation budget on it: a 400-token extraction call returned
            400 tokens of reasoning and an empty answer. Set
            ``HECATE_OLLAMA_THINK=false`` or the ``think`` config key.
    """

    def __init__(
        self,
        model: str = "llama3",
        base_url: str = "http://localhost:11434",
        timeout_sec: int = 180,
        num_ctx: Optional[int] = None,
        think: Optional[bool] = None,
    ):
        self.model = model
        self.timeout_sec = timeout_sec
        self.num_ctx = num_ctx
        self.think = think
        self.base_url = base_url.rstrip("/")

    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "ollama"

    def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """Send a chat request to the local Ollama API.

        Args:
            messages: Chat messages.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature.

        Returns:
            LLMResponse with results and metrics.

        Raises:
            ConnectionError: If Ollama is not reachable.
        """
        import urllib.error
        import urllib.request

        url = "{}/api/chat".format(self.base_url)
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
                **({"num_ctx": self.num_ctx} if self.num_ctx else {}),
            },
            **({"think": self.think} if self.think is not None else {}),
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                duration_ms = int((time.monotonic() - start) * 1000)
                body = json.loads(resp.read().decode("utf-8"))
        except TimeoutError:
            raise ConnectionError(
                "Ollama request timed out after {}s (model={}). Larger local models "
                "may need a higher HECATE_OLLAMA_TIMEOUT_SEC.".format(self.timeout_sec, self.model)
            )
        except urllib.error.URLError as exc:
            raise ConnectionError("Cannot reach Ollama at {}. Is it running? Error: {}".format(self.base_url, exc))

        text = body.get("message", {}).get("content", "")

        # Ollama may report token counts in eval_count / prompt_eval_count
        input_tokens = body.get("prompt_eval_count", 0) or 0
        output_tokens = body.get("eval_count", 0) or 0

        return LLMResponse(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self.model,
            duration_ms=duration_ms,
            cost_usd=0.0,  # Local models are free
        )


# ---------------------------------------------------------------------------
# OpenAI-compatible provider
# ---------------------------------------------------------------------------


class OpenAICompatibleProvider(LLMProvider):
    """Provider for any OpenAI-compatible API endpoint.

    Works with OpenAI, Azure OpenAI, vLLM, text-generation-inference, and
    other servers that expose the ``/v1/chat/completions`` interface.

    The ``openai`` package is imported lazily.

    Args:
        model: Model name to request (e.g. ``"gpt-4o"``).
        api_key: API key. Falls back to ``OPENAI_API_KEY`` env var.
        base_url: Optional base URL override for non-OpenAI endpoints.
    """

    def __init__(
        self,
        model: str = "gpt-4o",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self.model = model
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = base_url
        self._client = None  # type: Any

    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "openai"

    def _get_client(self) -> Any:
        """Lazily create and cache the OpenAI client.

        Returns:
            An ``openai.OpenAI`` client instance.

        Raises:
            ImportError: If the openai package is not installed.
        """
        if self._client is not None:
            return self._client

        try:
            import openai
        except ImportError:
            raise ImportError("openai package is not installed. Install it with: pip install openai")

        kwargs = {}  # type: Dict[str, Any]
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.base_url:
            kwargs["base_url"] = self.base_url

        self._client = openai.OpenAI(**kwargs)
        return self._client

    def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """Send a chat-completion request to an OpenAI-compatible API.

        Args:
            messages: Chat messages.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature.

        Returns:
            LLMResponse with results and metrics.

        Raises:
            ImportError: If the openai package is not installed.
        """
        client = self._get_client()

        start = time.monotonic()
        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        text = response.choices[0].message.content or ""
        usage = response.usage
        input_tokens = getattr(usage, "prompt_tokens", 0) or 0
        output_tokens = getattr(usage, "completion_tokens", 0) or 0

        return LLMResponse(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self.model,
            duration_ms=duration_ms,
            cost_usd=_estimate_cost(self.model, input_tokens, output_tokens),
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

# Canonical mapping from config/env strings to provider classes.
_PROVIDER_MAP = {
    "litellm": "LiteLLMProvider",
    "bedrock": "BedrockProvider",
    "ollama": "OllamaProvider",
    "openai": "OpenAICompatibleProvider",
}


def _load_config_file() -> Dict[str, Any]:
    """Load LLM settings from .hecateconfig.yaml if present.

    Searches two conventional locations relative to the current working directory:
    ``./config/.hecateconfig.yaml`` and ``./.hecateconfig.yaml``.

    Returns:
        The ``llm`` section of the config as a dict, or an empty dict.
    """
    from pathlib import Path

    candidates = [
        Path.cwd() / "config" / ".hecateconfig.yaml",
        Path.cwd() / ".hecateconfig.yaml",
    ]

    for path in candidates:
        if path.is_file():
            try:
                import yaml

                with open(str(path), "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
                result: Dict[str, Any] = data.get("llm", {})
                return result
            except ImportError:
                # PyYAML not installed; try stdlib JSON fallback (unlikely to work, but safe)
                logger.debug("PyYAML not installed; skipping config file %s", path)
            except Exception as exc:
                logger.debug("Failed to read config %s: %s", path, exc)

    return {}


def _ollama_is_running(base_url: str = "http://localhost:11434") -> bool:
    """Check whether an Ollama instance is reachable.

    Args:
        base_url: Ollama HTTP API base URL.

    Returns:
        True if Ollama responds to a version request.
    """
    import urllib.error
    import urllib.request

    try:
        req = urllib.request.Request("{}/api/version".format(base_url))
        with urllib.request.urlopen(req, timeout=2) as resp:
            return bool(resp.status == 200)
    except Exception:
        return False


def _get_default_ollama_model(base_url: str = "http://localhost:11434") -> str:
    """Return the first installed Ollama model if reachable, else 'llama3'."""
    import json
    import urllib.request

    try:
        req = urllib.request.Request(f"{base_url}/api/tags")
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = data.get("models", [])
            for m in models:
                name = m.get("name")
                if name:
                    return str(name)
    except Exception:
        pass
    return "llama3"


def create_provider(config: Optional[Dict[str, Any]] = None) -> LLMProvider:
    """Create an LLM provider using a layered configuration strategy.

    Resolution order:

    1. Explicit ``config`` dict (``provider``, ``model``, plus provider-specific keys).
    2. Environment variables: ``HECATE_LLM_PROVIDER``, ``HECATE_LLM_MODEL``.
    3. ``.hecateconfig.yaml`` ``llm`` section.
    4. Auto-detection based on available API keys / running services.

    Auto-detection order:
        ``ANTHROPIC_API_KEY`` -> LiteLLM (Anthropic)
        ``OPENAI_API_KEY`` -> OpenAI-compatible
        ``AWS_PROFILE`` or ``AWS_ACCESS_KEY_ID`` -> Bedrock
        Ollama running locally -> Ollama
        Otherwise -> raises RuntimeError

    Args:
        config: Optional configuration dictionary with keys such as
            ``provider``, ``model``, ``api_key``, ``base_url``, ``region``.

    Returns:
        A configured LLMProvider instance.

    Raises:
        RuntimeError: If no provider can be determined.
        ValueError: If an unknown provider name is given.
    """
    effective = _resolve_llm_config(config)
    provider_name = effective.get("provider", "").lower()
    model = effective.get("model")

    if provider_name in ("none", "disabled", "offline"):
        raise RuntimeError("No LLM provider configured (offline mode enabled).")

    # --- Explicit provider requested ---
    if provider_name:
        return _build_provider(provider_name, model, effective)

    logger.debug("No explicit LLM provider configured; auto-detecting...")
    return _autodetect_provider(model, effective)


def _resolve_llm_config(config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge the configuration layers, lowest precedence first."""
    try:
        from hecate_agent.core.workspace import load_workspace_env

        load_workspace_env()
    except Exception:
        pass
    effective: Dict[str, Any] = {}

    # Layer 1: config file
    file_config = _load_config_file()
    if file_config:
        effective.update(file_config)

    # Layer 2: environment variables
    for key, env_var in (
        ("provider", "HECATE_LLM_PROVIDER"),
        ("model", "HECATE_LLM_MODEL"),
        ("base_url", "HECATE_LLM_BASE_URL"),
    ):
        value = os.getenv(env_var)
        if value:
            effective[key] = value

    # Layer 3: explicit config dict (highest priority)
    if config:
        effective.update(config)
    return effective


def _autodetect_provider(model: Optional[str], effective: Dict[str, Any]) -> LLMProvider:
    """Pick a provider from whichever credentials or services are present."""
    # Anthropic API key -> LiteLLM with anthropic prefix
    if os.getenv("ANTHROPIC_API_KEY"):
        detected_model = model or "anthropic/claude-sonnet-4-5-20250514"
        logger.info("Auto-detected ANTHROPIC_API_KEY -> using LiteLLM provider with model %s", detected_model)
        return LiteLLMProvider(model=detected_model)

    # OpenAI API key -> OpenAI-compatible provider
    if os.getenv("OPENAI_API_KEY"):
        detected_model = model or "gpt-4o"
        logger.info("Auto-detected OPENAI_API_KEY -> using OpenAI provider with model %s", detected_model)
        return OpenAICompatibleProvider(
            model=detected_model,
            api_key=os.getenv("OPENAI_API_KEY", ""),
            base_url=effective.get("base_url"),
        )

    # AWS credentials -> Bedrock
    if os.getenv("AWS_PROFILE") or os.getenv("AWS_ACCESS_KEY_ID"):
        detected_model = model or "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
        logger.info("Auto-detected AWS credentials -> using Bedrock provider with model %s", detected_model)
        return BedrockProvider(
            model_id=detected_model,
            region=effective.get("region"),
        )

    # Ollama running locally or at OLLAMA_HOST (e.g. a Docker service)
    ollama_url: str = str(effective.get("base_url") or os.getenv("OLLAMA_HOST") or "http://localhost:11434")
    if _ollama_is_running(ollama_url):
        detected_model = model or _get_default_ollama_model(ollama_url)
        logger.info("Auto-detected local Ollama -> using Ollama provider with model %s", detected_model)
        return OllamaProvider(
            model=detected_model,
            base_url=ollama_url,
            timeout_sec=_ollama_timeout_sec(effective),
            num_ctx=_ollama_num_ctx(effective),
            think=_ollama_think(effective),
        )

    raise RuntimeError(
        "No LLM provider could be determined. Set one of: "
        "HECATE_LLM_PROVIDER env var, ANTHROPIC_API_KEY, OPENAI_API_KEY, "
        "AWS_PROFILE/AWS_ACCESS_KEY_ID, or start a local Ollama instance. "
        "Alternatively, add an 'llm' section to .hecateconfig.yaml."
    )


def _ollama_think(config: Dict[str, Any]) -> Optional[bool]:
    """Resolve whether an Ollama reasoning model thinks: config key, then env var, else the model's default."""
    value = config.get("think", os.getenv("HECATE_OLLAMA_THINK"))
    if value is None or str(value).strip() == "":
        return None
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _ollama_timeout_sec(config: Dict[str, Any]) -> int:
    """Resolve the Ollama per-request timeout: config key, then env var, then default."""
    if "timeout_sec" in config:
        return int(config["timeout_sec"])
    env_value = os.getenv("HECATE_OLLAMA_TIMEOUT_SEC")
    if env_value:
        return int(env_value)
    return 180


#: Room for a long research or extraction prompt plus the 4096-token default
#: generation budget, where Ollama's 4096 default cut prompts short.
_DEFAULT_OLLAMA_NUM_CTX = 16384


def _ollama_num_ctx(config: Dict[str, Any]) -> int:
    """Resolve the Ollama context window: config key, then env var, then default."""
    if "num_ctx" in config:
        return int(config["num_ctx"])
    env_value = os.getenv("HECATE_OLLAMA_NUM_CTX")
    if env_value:
        return int(env_value)
    return _DEFAULT_OLLAMA_NUM_CTX


def _build_provider(name: str, model: Optional[str], config: Dict[str, Any]) -> LLMProvider:
    """Instantiate a specific provider by name.

    Args:
        name: Provider name (e.g. ``"bedrock"``, ``"litellm"``).
        model: Optional model override.
        config: Full effective config dict for provider-specific keys.

    Returns:
        A configured LLMProvider instance.

    Raises:
        ValueError: If the provider name is not recognized.
    """
    if name not in _PROVIDER_MAP:
        raise ValueError(
            "Unknown LLM provider '{}'. Supported providers: {}".format(name, ", ".join(sorted(_PROVIDER_MAP.keys())))
        )

    if name == "litellm":
        return LiteLLMProvider(model=model or "anthropic/claude-sonnet-4-5-20250514")

    if name == "bedrock":
        return BedrockProvider(
            model_id=model or "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            region=config.get("region"),
        )

    if name == "ollama":
        base_url: str = str(config.get("base_url") or os.getenv("OLLAMA_HOST") or "http://localhost:11434")
        return OllamaProvider(
            model=model or _get_default_ollama_model(base_url),
            base_url=base_url,
            timeout_sec=_ollama_timeout_sec(config),
            num_ctx=_ollama_num_ctx(config),
            think=_ollama_think(config),
        )

    if name == "openai":
        return OpenAICompatibleProvider(
            model=model or "gpt-4o",
            api_key=config.get("api_key") or os.getenv("OPENAI_API_KEY", ""),
            base_url=config.get("base_url"),
        )

    # Unreachable given the _PROVIDER_MAP check, but satisfies type checkers.
    raise ValueError("Unknown provider: {}".format(name))
