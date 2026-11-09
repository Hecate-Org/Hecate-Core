"""Dual-backend LLM router: simple (local) vs complex (cloud) tiers.

Item 1 of dual-LLM work: config + router + call-log tags. Call sites that do
not pass ``capability`` / ``tier`` keep today's behavior (``complex`` /
legacy single provider). When ``simple`` is unset, both tiers share the same
backend from ``create_provider()``.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Mapping, MutableMapping, Optional

from hecate_agent.core.llm_activity import call_meta
from hecate_agent.core.llm_provider import LLMProvider, LLMResponse, create_provider

logger = logging.getLogger(__name__)

LLM_TIERS = ("simple", "complex")
_ROUTER_SECTION_KEYS = frozenset({"simple", "complex", "defaults", "tiers"})

# Active routing map. Extraction / summarize / pivots → simple; judgement
# stages (hypothesis, Sigma, triage, research synthesis) stay on complex.
# Override per install via ``llm.defaults`` in ``.hecateconfig.yaml``.
DEFAULT_CAPABILITY_TIERS: Dict[str, str] = {
    "source_extraction": "simple",
    "feed_classification": "simple",
    "artifact_extract": "simple",
    "research_summarize": "simple",
    "research_synthesize": "complex",
    "hypothesis": "complex",
    "sigma_draft": "complex",
    "sigma_review": "complex",
    "finding_triage": "complex",
    "pivot_suggest": "simple",
}

# Alias kept for callers/tests that opted into the recommended map early.
RECOMMENDED_CAPABILITY_TIERS: Dict[str, str] = dict(DEFAULT_CAPABILITY_TIERS)


def _flat_backend_config(config: Mapping[str, Any]) -> Dict[str, Any]:
    """Drop router sections so create_provider sees only backend keys."""
    return {
        key: value
        for key, value in config.items()
        if key not in _ROUTER_SECTION_KEYS and not isinstance(value, dict)
    }


def _tier_env_overrides(tier: str) -> Dict[str, str]:
    prefix = f"HECATE_LLM_{tier.upper()}_"
    out: Dict[str, str] = {}
    for key, suffix in (
        ("provider", "PROVIDER"),
        ("model", "MODEL"),
        ("base_url", "BASE_URL"),
    ):
        value = os.getenv(prefix + suffix)
        if value:
            out[key] = value
    return out


def _resolve_llm_layers(config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    from hecate_agent.core.llm_provider import _resolve_llm_config

    return _resolve_llm_config(config)


def resolve_tier_config(tier: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Backend settings for ``simple`` or ``complex``, falling back to the legacy single LLM config."""
    tier_name = tier.strip().lower()
    if tier_name not in LLM_TIERS:
        raise ValueError(f"Unknown LLM tier {tier!r}; expected one of {LLM_TIERS}")

    effective = _resolve_llm_layers(config)
    merged: Dict[str, Any] = _flat_backend_config(effective)

    nested = effective.get(tier_name)
    if isinstance(nested, dict):
        merged.update(
            {
                key: value
                for key, value in nested.items()
                if key not in _ROUTER_SECTION_KEYS and not isinstance(value, dict)
            }
        )

    merged.update(_tier_env_overrides(tier_name))
    return merged


def resolve_capability_tiers(config: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Capability → tier map: defaults, then ``llm.defaults`` / ``llm.tiers`` from config/env file.

    High-stakes capabilities stay on complex unless a demotion eval gate (or
    ``HECATE_LLM_ALLOW_DEMOTION``) unlocks them — see ``llm_demotion``.
    """
    from hecate_agent.core.llm_demotion import apply_demotion_locks

    mapping = dict(DEFAULT_CAPABILITY_TIERS)
    effective = _resolve_llm_layers(config)
    for section_key in ("defaults", "tiers"):
        section = effective.get(section_key)
        if not isinstance(section, dict):
            continue
        for capability, tier in section.items():
            name = str(capability).strip()
            target = str(tier).strip().lower()
            if name and target in LLM_TIERS:
                mapping[name] = target
    return apply_demotion_locks(mapping)


def _provider_fingerprint(cfg: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(cfg.get("provider") or "").strip().lower(),
        str(cfg.get("model") or "").strip(),
        str(cfg.get("base_url") or "").strip(),
    )


def _build_tier_provider(tier: str, config: Optional[Dict[str, Any]]) -> LLMProvider:
    tier_cfg = resolve_tier_config(tier, config)
    backend = _flat_backend_config(tier_cfg)
    if not backend.get("provider") and not backend.get("model"):
        # Empty tier section → identical to legacy create_provider().
        return create_provider(config=_flat_backend_config(_resolve_llm_layers(config)) or None)
    return create_provider(config=backend or None)


class LLMRouter:
    """Routes ``complete`` to a simple or complex backend.

    Not an ``LLMProvider`` subclass: circuit breakers stay on the real backends,
    and the call log records the backend that actually ran.
    """

    provider_name = "router"

    def __init__(
        self,
        providers: Mapping[str, LLMProvider],
        *,
        capability_tiers: Optional[Mapping[str, str]] = None,
        default_tier: str = "complex",
    ) -> None:
        missing = [tier for tier in LLM_TIERS if tier not in providers]
        if missing:
            raise ValueError(f"LLMRouter missing backends: {missing}")
        if default_tier not in LLM_TIERS:
            raise ValueError(f"default_tier must be one of {LLM_TIERS}")
        self._providers: Dict[str, LLMProvider] = {tier: providers[tier] for tier in LLM_TIERS}
        self._capability_tiers = {
            str(key): str(value).lower()
            for key, value in (capability_tiers or DEFAULT_CAPABILITY_TIERS).items()
            if str(value).lower() in LLM_TIERS
        }
        self._default_tier = default_tier

    @property
    def simple(self) -> LLMProvider:
        return self._providers["simple"]

    @property
    def complex(self) -> LLMProvider:
        return self._providers["complex"]

    def resolve_tier(
        self,
        tier: Optional[str] = None,
        capability: Optional[str] = None,
    ) -> str:
        """Pick ``simple`` or ``complex`` from an explicit tier or capability name."""
        if tier is not None:
            cleaned = str(tier).strip().lower()
            if cleaned in LLM_TIERS:
                return cleaned
            raise ValueError(f"Unknown LLM tier {tier!r}; expected one of {LLM_TIERS}")
        if capability:
            mapped = self._capability_tiers.get(str(capability).strip())
            if mapped in LLM_TIERS:
                return mapped
        return self._default_tier

    def provider_for(
        self,
        *,
        tier: Optional[str] = None,
        capability: Optional[str] = None,
    ) -> LLMProvider:
        return self._providers[self.resolve_tier(tier, capability)]

    def complete(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        *,
        tier: Optional[str] = None,
        capability: Optional[str] = None,
    ) -> LLMResponse:
        """Delegate to the resolved backend; tag the call log with tier/capability."""
        from hecate_agent.core.llm_prompt_budget import clip_messages_for_tier

        resolved = self.resolve_tier(tier, capability)
        provider = self._providers[resolved]
        clipped = clip_messages_for_tier(messages, resolved)
        with call_meta(tier=resolved, capability=capability or ""):
            return provider.complete(
                messages=clipped,
                max_tokens=max_tokens,
                temperature=temperature,
            )


def create_router(config: Optional[Dict[str, Any]] = None) -> LLMRouter:
    """Build a router from dual config, sharing one backend when tiers match.

    Resolution per tier: legacy ``llm`` / ``HECATE_LLM_*`` base, then
    ``llm.simple`` / ``llm.complex`` (or ``HECATE_LLM_SIMPLE_*`` /
    ``HECATE_LLM_COMPLEX_*``). Capability map from ``llm.defaults``.
    """
    simple_cfg = resolve_tier_config("simple", config)
    complex_cfg = resolve_tier_config("complex", config)

    if _provider_fingerprint(simple_cfg) == _provider_fingerprint(complex_cfg):
        shared = _build_tier_provider("complex", config)
        providers: Dict[str, LLMProvider] = {"simple": shared, "complex": shared}
        logger.debug(
            "LLM router: simple and complex share provider=%s model=%s",
            getattr(shared, "provider_name", "?"),
            getattr(shared, "model", getattr(shared, "model_id", "")),
        )
    else:
        providers = {
            "simple": _build_tier_provider("simple", config),
            "complex": _build_tier_provider("complex", config),
        }
        logger.info(
            "LLM router: simple=%s/%s complex=%s/%s",
            providers["simple"].provider_name,
            getattr(providers["simple"], "model", getattr(providers["simple"], "model_id", "")),
            providers["complex"].provider_name,
            getattr(providers["complex"], "model", getattr(providers["complex"], "model_id", "")),
        )

    return LLMRouter(
        providers,
        capability_tiers=resolve_capability_tiers(config),
        default_tier="complex",
    )


def apply_recommended_capability_tiers(
    router: LLMRouter,
    *,
    overrides: Optional[Mapping[str, str]] = None,
) -> None:
    """Swap in the recommended simple/complex map (for tests / opt-in)."""
    mapping: MutableMapping[str, str] = dict(RECOMMENDED_CAPABILITY_TIERS)
    if overrides:
        for key, value in overrides.items():
            if str(value).lower() in LLM_TIERS:
                mapping[str(key)] = str(value).lower()
    router._capability_tiers = dict(mapping)
