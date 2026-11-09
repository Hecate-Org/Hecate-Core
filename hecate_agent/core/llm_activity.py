"""A live record of provider calls, so a long run can be watched while it happens.

Usage totals reach the caller only when a whole stage returns, which for a
local model can be many minutes after the first call was sent. When
``HECATE_LLM_CALL_LOG`` names a file, every provider call appends a line as
it starts and another as it ends; without it nothing is written.

Optional ``call_meta(tier=..., capability=...)`` context is copied onto each
start/end/error line so dual-backend routing is visible in the log.
"""

from __future__ import annotations

import functools
import json
import os
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Callable, Dict, Iterator, List

CALL_LOG_ENV = "HECATE_LLM_CALL_LOG"

_write_lock = threading.Lock()
_in_call = threading.local()
_call_meta: ContextVar[Dict[str, Any]] = ContextVar("hecate_llm_call_meta", default={})


@contextmanager
def call_meta(**meta: Any) -> Iterator[None]:
    """Attach routing metadata (tier, capability, …) to call-log lines in this scope."""
    cleaned = {key: value for key, value in meta.items() if value not in (None, "")}
    if not cleaned:
        yield
        return
    merged = {**_call_meta.get(), **cleaned}
    token = _call_meta.set(merged)
    try:
        yield
    finally:
        _call_meta.reset(token)


def current_call_meta() -> Dict[str, Any]:
    """Snapshot of active call metadata (empty when unset)."""
    return dict(_call_meta.get())


def _append(record: Dict[str, Any]) -> None:
    path = os.environ.get(CALL_LOG_ENV)
    if not path:
        return
    try:
        meta = current_call_meta()
        line = json.dumps({"ts": round(time.time(), 3), **meta, **record})
        with _write_lock, open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except (OSError, TypeError, ValueError):
        pass  # watching a run must never be what breaks it


def recorded(complete: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a provider's ``complete`` so each call is logged when the call log is on."""

    @functools.wraps(complete)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        # A provider that extends another's ``complete`` is still making one call.
        if not os.environ.get(CALL_LOG_ENV) or getattr(_in_call, "active", False):
            return complete(self, *args, **kwargs)
        messages = kwargs.get("messages", args[0] if args else [])
        _append({
            "event": "start",
            "message_count": len(messages),
            "prompt_chars": sum(len(m.get("content", "")) for m in messages if isinstance(m.get("content"), str)),
        })
        _in_call.active = True
        try:
            response = complete(self, *args, **kwargs)
        except BaseException:
            _append({"event": "error"})
            raise
        finally:
            _in_call.active = False
        _append(
            {
                "event": "end",
                "model": getattr(response, "model", ""),
                "input_tokens": getattr(response, "input_tokens", 0),
                "output_tokens": getattr(response, "output_tokens", 0),
                "duration_ms": getattr(response, "duration_ms", 0),
                "cost_usd": getattr(response, "cost_usd", 0.0),
                "provider": getattr(self, "provider_name", ""),
            }
        )
        return response

    return wrapper


def _empty_tier_bucket() -> Dict[str, Any]:
    return {
        "llm_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "duration_ms": 0,
        "cost_usd": 0.0,
        "failed": 0,
        "models": [],
    }


def _tier_key(record: Dict[str, Any]) -> str:
    tier = str(record.get("tier") or "").strip().lower()
    return tier if tier in ("simple", "complex") else "unknown"


def summarize_calls(lines: List[str]) -> Dict[str, Any]:
    """Totals for a call log's lines; empty when they hold no call at all."""
    started = failed = 0
    ended: List[Dict[str, Any]] = []
    start_tiers: List[str] = []
    error_tiers: List[str] = []
    last_start = last_end = 0.0
    escalated_calls = 0
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        event, ts = record.get("event"), float(record.get("ts") or 0.0)
        if event == "start":
            started += 1
            last_start = max(last_start, ts)
            start_tiers.append(_tier_key(record))
            if record.get("escalated") or record.get("escalate_from"):
                escalated_calls += 1
        elif event == "error":
            failed += 1
            error_tiers.append(_tier_key(record))
        elif event == "end":
            ended.append(record)
            last_end = max(last_end, ts)
            if record.get("escalated") or record.get("escalate_from"):
                escalated_calls += 1
    if not started:
        return {}

    by_tier: Dict[str, Dict[str, Any]] = {
        "simple": _empty_tier_bucket(),
        "complex": _empty_tier_bucket(),
        "unknown": _empty_tier_bucket(),
    }
    for record in ended:
        bucket = by_tier[_tier_key(record)]
        bucket["llm_calls"] += 1
        bucket["input_tokens"] += int(record.get("input_tokens") or 0)
        bucket["output_tokens"] += int(record.get("output_tokens") or 0)
        bucket["duration_ms"] += int(record.get("duration_ms") or 0)
        bucket["cost_usd"] += float(record.get("cost_usd") or 0.0)
        model = record.get("model")
        if model:
            models = bucket["models"]
            name = str(model)
            if name not in models:
                models.append(name)
    for tier_name in error_tiers:
        by_tier[tier_name]["failed"] += 1
    for bucket in by_tier.values():
        bucket["cost_usd"] = round(float(bucket["cost_usd"]), 6)
        bucket["models"] = sorted(bucket["models"])

    return {
        "llm_calls": len(ended),
        "in_flight": max(0, started - len(ended) - failed),
        "failed": failed,
        "input_tokens": sum(int(r.get("input_tokens") or 0) for r in ended),
        "max_input_tokens": max((int(r.get("input_tokens") or 0) for r in ended), default=0) or None,
        "input_token_samples": sum(int(r.get("input_tokens") or 0) > 0 for r in ended),
        "output_tokens": sum(int(r.get("output_tokens") or 0) for r in ended),
        "duration_ms": sum(int(r.get("duration_ms") or 0) for r in ended),
        "cost_usd": sum(float(r.get("cost_usd") or 0.0) for r in ended),
        "models": sorted({str(r["model"]) for r in ended if r.get("model")}),
        "tiers": sorted({str(r["tier"]) for r in ended if r.get("tier")}),
        "capabilities": sorted({str(r["capability"]) for r in ended if r.get("capability")}),
        "by_tier": by_tier,
        "escalated_calls": escalated_calls,
        "last_start": last_start,
        "last_end": last_end,
        "ended_calls": ended,
        # Retained for diagnostics; start-line tiers when end lines omit them.
        "start_tiers": sorted({tier for tier in start_tiers if tier != "unknown"}),
    }

