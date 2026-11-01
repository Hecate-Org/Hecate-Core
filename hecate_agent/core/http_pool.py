"""Shared HTTP keep-alive connection pool for OSINT, CTI, and external requests."""

from __future__ import annotations

import atexit
import threading
from typing import Any
from unittest.mock import Mock, NonCallableMock

import httpx

_CLIENT_LOCK = threading.Lock()
_CLIENTS: dict[str, httpx.Client] = {}
_ORIGINAL_HTTPX_GET = httpx.get
_ORIGINAL_HTTPX_POST = httpx.post


def get_shared_client(
    pool_name: str = "default",
    timeout: float = 15.0,
    verify: bool = True,
    follow_redirects: bool = True,
    headers: dict[str, str] | None = None,
    max_keepalive_connections: int = 25,
    max_connections: int = 100,
    keepalive_expiry: float = 60.0,
) -> httpx.Client:
    """Return a thread-safe shared httpx.Client with connection pooling."""
    header_key = tuple(sorted(headers.items())) if headers else ()
    key = f"{pool_name}:{verify}:{follow_redirects}:{timeout}:{header_key}"
    with _CLIENT_LOCK:
        client = _CLIENTS.get(key)
        if client is None or client.is_closed:
            limits = httpx.Limits(
                max_keepalive_connections=max_keepalive_connections,
                max_connections=max_connections,
                keepalive_expiry=keepalive_expiry,
            )
            client = httpx.Client(
                timeout=timeout,
                verify=verify,
                follow_redirects=follow_redirects,
                limits=limits,
                headers=headers,
            )
            _CLIENTS[key] = client
        return client


def close_shared_clients() -> None:
    """Close and clear all pooled HTTP clients."""
    with _CLIENT_LOCK:
        for client in _CLIENTS.values():
            try:
                if not client.is_closed:
                    client.close()
            except Exception:
                pass
        _CLIENTS.clear()


atexit.register(close_shared_clients)


def is_mocked(func: Any, original: Any | None = None) -> bool:
    """Check if an httpx function has been patched or mocked."""
    if isinstance(func, (Mock, NonCallableMock)):
        return True
    if getattr(func, "_mock_name", None) is not None or getattr(func, "mock", None) is not None:
        return True
    if original is not None:
        return func is not original
    return False
