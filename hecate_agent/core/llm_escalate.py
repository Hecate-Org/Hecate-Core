"""Simple→complex escalation when a local-tier response fails validation."""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional, Sequence

from hecate_agent.core.llm_activity import call_meta
from hecate_agent.core.llm_provider import LLMResponse
from hecate_agent.core.llm_router import LLMRouter

logger = logging.getLogger(__name__)

ValidateFn = Callable[[str], Optional[str]]
BoolValidateFn = Callable[[str], bool]


def backends_differ(router: LLMRouter) -> bool:
    """True when simple and complex are distinct provider instances."""
    return router.simple is not router.complex


def can_escalate(
    router: Any,
    *,
    tier: Optional[str] = None,
    capability: Optional[str] = None,
) -> bool:
    """Escalate only from a real simple backend to a different complex one."""
    if not isinstance(router, LLMRouter):
        return False
    if not backends_differ(router):
        return False
    resolved = router.resolve_tier(tier, capability)
    return resolved == "simple"


def complete_with_escalation(
    router: LLMRouter,
    messages: Sequence[Dict[str, str]],
    *,
    validate: BoolValidateFn,
    max_tokens: int = 4096,
    temperature: float = 0.0,
    capability: Optional[str] = None,
    tier: Optional[str] = None,
) -> tuple[LLMResponse, bool]:
    """Run once on the resolved tier; if invalid and escalatable, retry on complex.

    Returns ``(response, escalated)``. The returned response is the last attempt
    (complex when escalated), even when still invalid — callers decide next steps.
    """
    from hecate_agent.core.llm_prompt_budget import would_clip_messages_for_simple

    resolved = router.resolve_tier(tier, capability)
    # Oversized prompts are clipped on simple and often fail validation; skip
    # the doomed local call when a distinct complex backend is available.
    if (
        resolved == "simple"
        and backends_differ(router)
        and would_clip_messages_for_simple(messages)
    ):
        logger.info(
            "Skipping simple for oversized %s prompt; using complex directly",
            capability or tier or "llm",
        )
        with call_meta(escalated="true", escalate_from="simple_over_budget"):
            response = router.complete(
                list(messages),
                max_tokens=max_tokens,
                temperature=temperature,
                tier="complex",
                capability=capability,
            )
        return response, True

    response = router.complete(
        list(messages),
        max_tokens=max_tokens,
        temperature=temperature,
        tier=tier,
        capability=capability,
    )
    if validate(response.text):
        return response, False
    if resolved != "simple" or not backends_differ(router):
        return response, False

    logger.info(
        "Escalating invalid %s response from simple→complex",
        capability or tier or "llm",
    )
    with call_meta(escalated="true", escalate_from="simple"):
        escalated = router.complete(
            list(messages),
            max_tokens=max_tokens,
            temperature=temperature,
            tier="complex",
            capability=capability,
        )
    return escalated, True
