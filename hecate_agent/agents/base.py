"""Base classes for Hecate agents."""

import json
import logging
import random
import re
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar, cast

from hecate_agent.core.cost_tracker import summarize_cost

# Type variables for input/output
InputT = TypeVar("InputT")
OutputT = TypeVar("OutputT")

logger = logging.getLogger(__name__)


@dataclass
class AgentResult(Generic[OutputT]):
    """Standard result format for all agents."""

    success: bool
    data: Optional[OutputT]
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        """Check if the agent execution was successful."""
        return self.success and self.error is None


class Agent(ABC, Generic[InputT, OutputT]):
    """Base class for all agents."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize agent with optional configuration.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self._setup()

    def _setup(self) -> None:
        """Optional setup method for subclasses."""
        pass

    @abstractmethod
    def execute(self, input_data: InputT) -> AgentResult[OutputT]:
        """Execute agent logic.

        Args:
            input_data: Input for the agent

        Returns:
            AgentResult with output data or error
        """
        pass

    def __call__(self, input_data: InputT) -> AgentResult[OutputT]:
        """Allow calling agent as a function."""
        return self.execute(input_data)


class DeterministicAgent(Agent[InputT, OutputT]):
    """Base class for deterministic Python agents (no LLM)."""

    pass


class LLMAgent(Agent[InputT, OutputT]):
    """Base class for LLM-powered agents.

    Uses the model-agnostic provider abstraction from hecate_agent.core.llm_provider.
    Supports Claude, GPT, Gemini, Ollama, and any OpenAI-compatible endpoint.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        llm_enabled: bool = True,
        provider: Optional[Any] = None,
    ):
        """Initialize LLM agent.

        Args:
            config: Optional configuration dictionary
            llm_enabled: Whether to enable LLM functionality
            provider: Optional pre-configured LLMProvider instance. If None,
                auto-detects from environment/config when first needed.
        """
        self.llm_enabled = llm_enabled
        self._provider = provider
        self._usage_lock = threading.Lock()
        self._usage: Dict[str, Any] = {
            "llm_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "llm_duration_ms": 0,
            "estimated_cost_usd": 0.0,
            "models": set(),
        }
        super().__init__(config)

    def _reset_llm_usage(self) -> None:
        """Clear usage totals before an agent execution."""
        with self._usage_lock:
            self._usage = {
                "llm_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "llm_duration_ms": 0,
                "estimated_cost_usd": 0.0,
                "models": set(),
            }

    def _llm_usage_metadata(self) -> Dict[str, Any]:
        """Return a thread-safe snapshot of provider usage for this execution."""
        with self._usage_lock:
            snapshot = dict(self._usage)
            snapshot["models"] = sorted(snapshot["models"])
        # Zero from a local model or from missing usage is unknown, not free.
        cost, basis = summarize_cost(
            snapshot["models"],
            snapshot["llm_calls"],
            snapshot["input_tokens"],
            snapshot["output_tokens"],
            float(snapshot["estimated_cost_usd"]),
        )
        snapshot["estimated_cost_usd"] = cost
        snapshot["cost_basis"] = basis
        return snapshot

    def _get_provider(self) -> Any:
        """Get or create an LLM provider.

        Uses the provider abstraction layer which auto-detects the available
        LLM backend from environment variables and configuration.

        Returns:
            LLMProvider instance

        Raises:
            RuntimeError: If no provider can be determined
        """
        if self._provider is not None:
            return self._provider

        from hecate_agent.core.llm_provider import create_provider

        llm_config = self.config.get("llm", {})
        self._provider = create_provider(llm_config if llm_config else None)
        return self._provider

    def _call_llm(self, prompt: str, max_tokens: int = 4096, temperature: Optional[float] = None) -> str:
        """Call the LLM and return response text.

        Provider-agnostic: works with any configured LLM backend.

        Args:
            prompt: The prompt to send to the LLM.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature. Left as the provider default
                when None. Worth lowering for calls whose output is a
                judgement rather than prose -- a yes/no classification
                sampled at the creative default varies run to run on
                identical input, which reads as the model being unreliable
                when it is really just being asked to be creative about a
                question that has one right answer.

        Returns:
            The generated text content.
        """
        provider = self._get_provider()
        complete_kwargs: Dict[str, Any] = {
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
        }
        if temperature is not None:
            complete_kwargs["temperature"] = temperature
        response = provider.complete(**complete_kwargs)

        self._log_llm_metrics(
            agent_name=self.__class__.__name__,
            model_id=response.model,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost_usd=response.cost_usd,
            duration_ms=response.duration_ms,
        )

        result: str = response.text
        return result

    def _call_llm_with_retry(
        self,
        prompt: str,
        validate_fn: Callable[[str], Optional[str]],
        max_retries: int = 2,
        max_tokens: int = 4096,
        temperature: Optional[float] = None,
        max_feedback_chars: int = 1500,
        backoff_base_sec: float = 0.5,
    ) -> str:
        """Call LLM with a validation-retry loop.

        If the response fails validation, appends bounded error feedback to the
        prompt and retries up to ``max_retries`` times with jittered backoff.

        Args:
            prompt: The prompt to send to the LLM.
            validate_fn: A function that takes the response text and returns
                None if valid, or an error string if invalid.
            max_retries: Maximum number of retry attempts.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature.
            max_feedback_chars: Maximum characters of invalid response to embed
                in the retry prompt to prevent unbounded context inflation.
            backoff_base_sec: Base delay in seconds for exponential backoff.
                Set to 0 to disable backoff.

        Returns:
            The generated text (last attempt, even if imperfect).
        """
        current_prompt = prompt
        result = ""

        for attempt in range(1 + max_retries):
            result = self._call_llm(current_prompt, max_tokens=max_tokens, temperature=temperature)
            error = validate_fn(result)
            if error is None:
                return result
            if attempt < max_retries:
                logger.debug("LLM response validation failed (attempt %d): %s", attempt + 1, error)

                if len(result) > max_feedback_chars:
                    feedback_payload = result[:max_feedback_chars] + "\n... [truncated] ..."
                else:
                    feedback_payload = result

                clipped_error = error[:500] + (" ... [truncated]" if len(error) > 500 else "")

                current_prompt = (
                    f"{prompt}\n\nYour previous response:\n```json\n{feedback_payload}\n```\n\n"
                    f"Failed validation with error: {clipped_error}\n"
                    "Please fix the issue in the JSON and try again. Return valid JSON only."
                )

                if backoff_base_sec > 0:
                    delay = (backoff_base_sec * (2**attempt)) + random.uniform(0.05, 0.2)
                    time.sleep(delay)

        return result

    def _parse_json_response(self, text: str) -> Dict[str, Any]:
        """Extract and parse JSON from an LLM response.

        Handles responses wrapped in markdown code blocks.

        Args:
            text: Raw LLM response text.

        Returns:
            Parsed JSON as a dictionary.

        Raises:
            ValueError: If JSON cannot be extracted or parsed.
        """
        cleaned = text.strip()

        # Try to extract JSON from markdown code blocks
        if "```json" in cleaned:
            json_start = cleaned.find("```json") + 7
            json_end = cleaned.find("```", json_start)
            if json_end > json_start:
                cleaned = cleaned[json_start:json_end].strip()
        elif "```" in cleaned:
            json_start = cleaned.find("```") + 3
            json_end = cleaned.find("```", json_start)
            if json_end > json_start:
                cleaned = cleaned[json_start:json_end].strip()

        def _repair_json_string(s: str) -> str:
            # Strip trailing commas: ", ]" -> "]" or ", }" -> "}"
            s = re.sub(r",\s*([\]}])", r"\1", s)
            # Remove single-line comments outside strings
            s = re.sub(r"(?m)^\s*//.*?$", "", s)
            # Repair unescaped backslashes
            s = re.sub(r"(?<!\\)\\(?![\"\\/bfnrt]|u[0-9a-fA-F]{4})", r"\\\\", s)
            return s

        def _close_unclosed_json(s: str) -> str:
            trimmed = s.strip()
            in_string = False
            escape = False
            stack = []
            for ch in trimmed:
                if escape:
                    escape = False
                    continue
                if ch == "\\":
                    escape = True
                    continue
                if ch == '"':
                    in_string = not in_string
                    continue
                if not in_string:
                    if ch in "{[":
                        stack.append(ch)
                    elif ch == "}" and stack and stack[-1] == "{":
                        stack.pop()
                    elif ch == "]" and stack and stack[-1] == "[":
                        stack.pop()

            if in_string:
                trimmed += '"'
            trimmed = re.sub(r",\s*$", "", trimmed)
            trimmed = re.sub(r":\s*$", "", trimmed)
            close_map = {"{": "}", "[": "]"}
            for open_ch in reversed(stack):
                trimmed += close_map[open_ch]
            return trimmed

        def _try_decode(candidate: str) -> Optional[Dict[str, Any]]:
            def _load_dict(s: str) -> Optional[Dict[str, Any]]:
                try:
                    res = json.loads(s)
                    if isinstance(res, dict):
                        return cast(Dict[str, Any], res)
                except json.JSONDecodeError:
                    pass
                return None

            res = _load_dict(candidate)
            if res is not None:
                return res
            res = _load_dict(_repair_json_string(candidate))
            if res is not None:
                return res
            return _load_dict(_repair_json_string(_close_unclosed_json(candidate)))

        parsed = _try_decode(cleaned)
        if parsed is not None:
            return parsed

        # Smaller local models (e.g. via Ollama) often prepend chatty
        # preamble ("Sure, here's the JSON:") or trailing commentary
        # instead of returning bare JSON despite the prompt. Fall back
        # to slicing out the outermost {...} span and retrying once
        # before giving up.
        brace_start = cleaned.find("{")
        brace_end = cleaned.rfind("}")
        if brace_start != -1 and brace_end > brace_start:
            parsed = _try_decode(cleaned[brace_start : brace_end + 1])
            if parsed is not None:
                return parsed

        raise ValueError(
            "Failed to parse JSON from LLM response. "
            "Response text (first 500 chars): {}".format(cleaned[:500])
        )

    def _log_llm_metrics(
        self,
        agent_name: str,
        model_id: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        duration_ms: int,
    ) -> None:
        """Log LLM call metrics to centralized tracker.

        Override this method in subclasses or plugins to implement custom metrics tracking.

        Args:
            agent_name: Name of the agent (e.g., "hypothesis-generator")
            model_id: Model identifier
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            cost_usd: Estimated cost in USD
            duration_ms: Call duration in milliseconds
        """
        # Keep usage on the agent so public APIs can return it with the result.
        # Research fans out across worker threads, so updates and snapshots are
        # protected even when several provider responses arrive together.
        with self._usage_lock:
            self._usage["llm_calls"] += 1
            self._usage["input_tokens"] += input_tokens
            self._usage["output_tokens"] += output_tokens
            self._usage["llm_duration_ms"] += duration_ms
            self._usage["estimated_cost_usd"] += cost_usd
            self._usage["models"].add(model_id)
