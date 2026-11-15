"""Shared HTTP keep-alive connection pool for OSINT, CTI, and external requests."""

from __future__ import annotations

import atexit
import threading
from contextlib import contextmanager
from typing import Any, Iterator
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


def pooled_request(
    method: str,
    url: str,
    *,
    pool_name: str = "default",
    timeout: float | httpx.Timeout | None = 15.0,
    verify: bool = True,
    follow_redirects: bool = True,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """Issue an HTTP request via the shared keep-alive pool.

    Falls back to bare ``httpx.request`` when tests have patched ``httpx.get`` /
    ``httpx.post`` so existing mocks keep working.
    """
    method_u = method.upper()
    if method_u == "GET" and is_mocked(httpx.get, _ORIGINAL_HTTPX_GET):
        return httpx.get(
            url,
            timeout=timeout,
            verify=verify,
            follow_redirects=follow_redirects,
            headers=headers,
            **kwargs,
        )
    if method_u == "POST" and is_mocked(httpx.post, _ORIGINAL_HTTPX_POST):
        return httpx.post(
            url,
            timeout=timeout,
            verify=verify,
            follow_redirects=follow_redirects,
            headers=headers,
            **kwargs,
        )
    timeout_s = 15.0
    if isinstance(timeout, (int, float)):
        timeout_s = float(timeout)
    elif isinstance(timeout, httpx.Timeout):
        # Prefer read timeout when present; fall back to pool default.
        read = getattr(timeout, "read", None)
        timeout_s = float(read) if isinstance(read, (int, float)) else 15.0
    client = get_shared_client(
        pool_name=pool_name,
        timeout=timeout_s,
        verify=verify,
        follow_redirects=follow_redirects,
        headers=headers,
    )
    return client.request(method_u, url, timeout=timeout, **kwargs)


def pooled_get(url: str, **kwargs: Any) -> httpx.Response:
    return pooled_request("GET", url, **kwargs)


def pooled_post(url: str, **kwargs: Any) -> httpx.Response:
    return pooled_request("POST", url, **kwargs)


@contextmanager
def use_shared_httpx(pool_name: str = "default") -> Iterator[None]:
    """Temporarily route module-level ``httpx.get``/``post`` through the pool.

    No-ops when tests have already patched those entry points.
    """
    if is_mocked(httpx.get, _ORIGINAL_HTTPX_GET) or is_mocked(httpx.post, _ORIGINAL_HTTPX_POST):
        yield
        return

    def _get(url: str, **kwargs: Any) -> httpx.Response:
        # Call the client directly — do not re-enter via patched ``httpx.get``.
        timeout = kwargs.pop("timeout", 15.0)
        verify = kwargs.pop("verify", True)
        follow_redirects = kwargs.pop("follow_redirects", True)
        headers = kwargs.pop("headers", None)
        timeout_s = float(timeout) if isinstance(timeout, (int, float)) else 15.0
        client = get_shared_client(
            pool_name=pool_name,
            timeout=timeout_s,
            verify=verify,
            follow_redirects=follow_redirects,
            headers=headers,
        )
        return client.get(url, timeout=timeout, **kwargs)

    def _post(url: str, **kwargs: Any) -> httpx.Response:
        timeout = kwargs.pop("timeout", 15.0)
        verify = kwargs.pop("verify", True)
        follow_redirects = kwargs.pop("follow_redirects", True)
        headers = kwargs.pop("headers", None)
        timeout_s = float(timeout) if isinstance(timeout, (int, float)) else 15.0
        client = get_shared_client(
            pool_name=pool_name,
            timeout=timeout_s,
            verify=verify,
            follow_redirects=follow_redirects,
            headers=headers,
        )
        return client.post(url, timeout=timeout, **kwargs)

    original_get, original_post = httpx.get, httpx.post
    httpx.get = _get  # type: ignore[assignment]
    httpx.post = _post  # type: ignore[assignment]
    try:
        yield
    finally:
        httpx.get = original_get
        httpx.post = original_post


def is_mocked(func: Any, original: Any | None = None) -> bool:
    """Check if an httpx function has been patched or mocked."""
    if isinstance(func, (Mock, NonCallableMock)):
        return True
    if getattr(func, "_mock_name", None) is not None or getattr(func, "mock", None) is not None:
        return True
    if original is not None:
        return func is not original
    return False
