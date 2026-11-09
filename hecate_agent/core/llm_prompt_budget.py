"""Clip oversized prompts before they hit the local simple-tier model.

Local MoE / small-context backends (Ollama) silently truncate when the prompt
exceeds ``num_ctx``. Prefer an explicit clip with a marker so extraction and
escalation still see a coherent prefix rather than a mid-token cut.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Mapping, Optional, Sequence

# Conservative default: ~12k chars ≈ 3–4k tokens, well under a 16k Ollama ctx
# once system instructions and generation room are reserved.
DEFAULT_SIMPLE_MAX_PROMPT_CHARS = 12_000
SIMPLE_MAX_PROMPT_CHARS_ENV = "HECATE_LLM_SIMPLE_MAX_PROMPT_CHARS"
TRUNCATION_MARKER = "\n\n[truncated for simple-tier context budget]\n"


def simple_max_prompt_chars(config: Optional[Mapping[str, Any]] = None) -> int:
    """Resolved char budget for simple-tier prompts."""
    env = os.getenv(SIMPLE_MAX_PROMPT_CHARS_ENV, "").strip()
    if env:
        try:
            value = int(env)
            if value > 0:
                return value
        except ValueError:
            pass
    if config:
        for key in ("simple_max_prompt_chars", "max_prompt_chars"):
            raw = config.get(key)
            if raw is None and isinstance(config.get("simple"), dict):
                raw = config["simple"].get("max_prompt_chars")
            if raw is not None:
                try:
                    value = int(raw)
                    if value > 0:
                        return value
                except (TypeError, ValueError):
                    pass
    return DEFAULT_SIMPLE_MAX_PROMPT_CHARS


def _message_chars(messages: Sequence[Mapping[str, Any]]) -> int:
    total = 0
    for message in messages:
        content = message.get("content", "")
        if isinstance(content, str):
            total += len(content)
    return total


def clip_messages_for_tier(
    messages: Sequence[Mapping[str, str]],
    tier: str,
    *,
    max_chars: Optional[int] = None,
    config: Optional[Mapping[str, Any]] = None,
) -> List[Dict[str, str]]:
    """Return messages unchanged for complex; clip user content for simple when over budget.

    Prefers trimming the last user message so system instructions stay intact.
    When a single message still exceeds the budget, keeps the head and appends
    ``TRUNCATION_MARKER``.
    """
    cleaned = [{**dict(message)} for message in messages]
    if str(tier).strip().lower() != "simple":
        return cleaned

    budget = max_chars if max_chars is not None else simple_max_prompt_chars(config)
    if budget <= 0 or _message_chars(cleaned) <= budget:
        return cleaned

    # Walk user messages from the end, shrinking until under budget.
    for index in range(len(cleaned) - 1, -1, -1):
        if _message_chars(cleaned) <= budget:
            break
        if cleaned[index].get("role") != "user":
            continue
        content = cleaned[index].get("content", "")
        if not isinstance(content, str) or not content:
            continue
        overhead = _message_chars(cleaned) - len(content)
        room = max(0, budget - overhead - len(TRUNCATION_MARKER))
        if room <= 0:
            cleaned[index]["content"] = TRUNCATION_MARKER.strip()
            continue
        if len(content) > room:
            cleaned[index]["content"] = content[:room].rstrip() + TRUNCATION_MARKER

    # Last resort: shrink any remaining oversized non-user content.
    if _message_chars(cleaned) > budget:
        for index in range(len(cleaned) - 1, -1, -1):
            if _message_chars(cleaned) <= budget:
                break
            content = cleaned[index].get("content", "")
            if not isinstance(content, str) or not content:
                continue
            overhead = _message_chars(cleaned) - len(content)
            room = max(0, budget - overhead - len(TRUNCATION_MARKER))
            cleaned[index]["content"] = (
                content[:room].rstrip() + TRUNCATION_MARKER if room else TRUNCATION_MARKER.strip()
            )
    return cleaned


def clip_text_for_simple(text: str, *, max_chars: Optional[int] = None, config: Optional[Mapping[str, Any]] = None) -> str:
    """Clip a single scraped/user blob for simple-tier extraction prompts."""
    budget = max_chars if max_chars is not None else simple_max_prompt_chars(config)
    if budget <= 0 or len(text) <= budget:
        return text
    room = max(0, budget - len(TRUNCATION_MARKER))
    return text[:room].rstrip() + TRUNCATION_MARKER
