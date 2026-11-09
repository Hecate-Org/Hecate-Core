"""Model budget, verified-response cache and telemetry for one source stage."""

import hashlib
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urldefrag

EXTRACTOR_VERSION = "1"
MAX_CACHE_ENTRIES = 512
MAX_CACHE_REPLY_BYTES = 128000


class SourceBudgetExceeded(RuntimeError):
    """No further source model calls fit in the stage's budget."""


class SourceExtractionSession:
    """Shared by extraction and classification; providers are created lazily once.

    Token limits use conservative UTF-8 prompt-byte reservations plus the
    provider's capped output allowance. These reservations are separate from
    reported/billable token usage, which is never estimated in telemetry.
    """

    def __init__(
        self,
        *,
        max_calls: int = 16,
        max_tokens: int = 256000,
        cache_path: Optional[Path] = None,
        cache_ttl_sec: int = 86400,
    ) -> None:
        if max_calls < 1 or max_tokens < 1 or cache_ttl_sec < 0:
            raise ValueError("Source budgets must be positive and cache TTL nonnegative")
        self.max_calls = max_calls
        self.max_tokens = max_tokens
        self.cache_path = cache_path
        self.cache_ttl_sec = cache_ttl_sec
        self.calls = 0
        self.tokens_used = 0
        self.exhausted = False
        self.attempts: List[Dict[str, Any]] = []
        self._provider: Any = None
        self._source = ""

    def bind_source(self, url: str, text: str) -> None:
        self._source = self._hash([urldefrag(url.strip())[0], text])

    @staticmethod
    def _hash(value: Any) -> str:
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()

    def snapshot(self) -> Dict[str, Any]:
        return {
            "max_calls": self.max_calls,
            "max_tokens": self.max_tokens,
            "model_calls": self.calls,
            "token_budget_used": self.tokens_used,
            "budget_exhausted": self.exhausted,
            "cache_hits": sum(row["cache_hit"] for row in self.attempts),
            "attempts": list(self.attempts),
        }

    def _cache_read(self, key: str) -> Optional[str]:
        if not self.cache_path or not self.cache_ttl_sec or not self.cache_path.exists():
            return None
        try:
            with closing(sqlite3.connect(self.cache_path, timeout=0.2)) as conn:
                row = conn.execute(
                    "SELECT reply FROM responses WHERE key = ? AND created_at > ?",
                    (key, time.time() - self.cache_ttl_sec),
                ).fetchone()
            return row[0] if row and isinstance(row[0], str) else None
        except (OSError, sqlite3.Error):
            return None  # A cache failure never changes grounding or stops a hunt.

    def _cache_write(self, key: str, reply: str) -> None:
        if not self.cache_path or not self.cache_ttl_sec or len(reply.encode("utf-8")) > MAX_CACHE_REPLY_BYTES:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(self.cache_path, timeout=0.2)) as conn, conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS responses (key TEXT PRIMARY KEY, reply TEXT NOT NULL, created_at REAL NOT NULL)"
                )
                conn.execute("CREATE INDEX IF NOT EXISTS response_age ON responses(created_at)")
                conn.execute("INSERT OR REPLACE INTO responses VALUES (?, ?, ?)", (key, reply, time.time()))
                conn.execute("DELETE FROM responses WHERE created_at <= ?", (time.time() - self.cache_ttl_sec,))
                conn.execute(
                    "DELETE FROM responses WHERE key IN (SELECT key FROM responses ORDER BY created_at DESC LIMIT -1 OFFSET ?)",
                    (MAX_CACHE_ENTRIES,),
                )
        except (OSError, sqlite3.Error):
            pass

    def complete(
        self,
        messages: List[Dict[str, str]],
        usage: Dict[str, Any],
        *,
        phase: str,
        chunk: int = 0,
        depth: int = 0,
        validate: Callable[[str], bool],
    ) -> str:
        from hecate_agent.core.llm_router import LLMRouter, create_router

        started = time.monotonic()
        capability = "feed_classification" if phase == "classification" else "source_extraction"
        row: Dict[str, Any] = {
            "phase": phase,
            "chunk": chunk,
            "retry_depth": depth,
            "cache_hit": False,
            "status": "error",
            "input_tokens": None,
            "output_tokens": None,
            "capability": capability,
        }
        try:
            if self._provider is None:
                self._provider = create_router()
            provider = self._provider
            backend = (
                provider.provider_for(capability=capability)
                if isinstance(provider, LLMRouter)
                else provider
            )
            identity = {
                attr: getattr(backend, attr, None)
                for attr in ("provider_name", "model", "model_id", "base_url", "region", "num_ctx", "think")
            }
            key = self._hash([EXTRACTOR_VERSION, self._source, identity, messages, 3000, 0.0])
            cached = self._cache_read(key)
            if cached is not None and validate(cached):
                row.update(cache_hit=True, status="cached")
                return cached

            # UTF-8 bytes bound ordinary text tokens conservatively; allow for
            # chat framing as well. Reserve output before dispatch, so even
            # failed calls or providers omitting usage cannot bypass the cap.
            prompt_bound = sum(len(message["content"].encode("utf-8")) + 256 for message in messages)
            allowance = min(3000, self.max_tokens - self.tokens_used - prompt_bound)
            if self.calls >= self.max_calls or allowance <= 0:
                self.exhausted = True
                row["status"] = "budget_exhausted"
                raise SourceBudgetExceeded("source extraction call/token budget exhausted")
            reservation = prompt_bound + allowance
            self.calls += 1
            self.tokens_used += reservation
            row["reserved_tokens"] = reservation
            usage["llm_calls"] = usage.get("llm_calls", 0) + 1
            usage.setdefault("input_token_samples", 0)
            if isinstance(provider, LLMRouter):
                response = provider.complete(
                    messages,
                    max_tokens=allowance,
                    temperature=0.0,
                    capability=capability,
                )
            else:
                response = provider.complete(messages, max_tokens=allowance, temperature=0.0)

            def _record_usage(resp: Any) -> None:
                usage["input_tokens"] = usage.get("input_tokens", 0) + resp.input_tokens
                usage["output_tokens"] = usage.get("output_tokens", 0) + resp.output_tokens
                usage["input_token_samples"] = usage.get("input_token_samples", 0) + int(
                    resp.input_tokens > 0
                )
                usage["max_input_tokens"] = max(usage.get("max_input_tokens", 0), resp.input_tokens)
                usage["llm_duration_ms"] = usage.get("llm_duration_ms", 0) + resp.duration_ms
                usage["cost_usd"] = usage.get("cost_usd", 0.0) + resp.cost_usd
                usage["models"] = sorted({*usage.get("models", []), resp.model})

            output_bound = response.output_tokens or allowance
            self.tokens_used += max(prompt_bound, response.input_tokens) + output_bound - reservation
            _record_usage(response)

            from hecate_agent.core.llm_escalate import can_escalate

            if (
                not validate(response.text)
                and isinstance(provider, LLMRouter)
                and can_escalate(provider, capability=capability)
            ):
                escalate_allowance = min(3000, self.max_tokens - self.tokens_used - prompt_bound)
                if self.calls < self.max_calls and escalate_allowance > 0:
                    escalate_reservation = prompt_bound + escalate_allowance
                    self.calls += 1
                    self.tokens_used += escalate_reservation
                    usage["llm_calls"] = usage.get("llm_calls", 0) + 1
                    row["escalated"] = True
                    from hecate_agent.core.llm_activity import call_meta

                    with call_meta(escalated="true", escalate_from="simple"):
                        response = provider.complete(
                            messages,
                            max_tokens=escalate_allowance,
                            temperature=0.0,
                            tier="complex",
                            capability=capability,
                        )
                    escalate_output = response.output_tokens or escalate_allowance
                    self.tokens_used += (
                        max(prompt_bound, response.input_tokens) + escalate_output - escalate_reservation
                    )
                    _record_usage(response)

            row.update(
                status="ok" if validate(response.text) else "invalid_response",
                input_tokens=response.input_tokens or None,
                output_tokens=response.output_tokens or None,
            )
            if row["status"] == "ok":
                self._cache_write(key, response.text)
            return response.text
        finally:
            row["duration_ms"] = max(0, round((time.monotonic() - started) * 1000))
            self.attempts.append(row)
