"""Tests for shared HTTP keep-alive connection pool in Hecate-Core."""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx

from hecate_agent.core.http_pool import (
    close_shared_clients,
    get_shared_client,
    is_mocked,
    pooled_get,
    use_shared_httpx,
)


def test_get_shared_client_reuses_instance() -> None:
    c1 = get_shared_client(pool_name="core_pool", timeout=12.0)
    c2 = get_shared_client(pool_name="core_pool", timeout=12.0)
    assert c1 is c2
    assert not c1.is_closed


def test_get_shared_client_differentiates_params() -> None:
    c1 = get_shared_client(pool_name="pool_1", timeout=10.0)
    c2 = get_shared_client(pool_name="pool_2", timeout=10.0)
    assert c1 is not c2


def test_close_shared_clients_closes_all() -> None:
    c1 = get_shared_client(pool_name="core_close_1", timeout=5.0)
    c2 = get_shared_client(pool_name="core_close_2", timeout=5.0)
    assert not c1.is_closed
    assert not c2.is_closed

    close_shared_clients()
    assert c1.is_closed
    assert c2.is_closed


def test_is_mocked_detects_mock() -> None:
    def real_func():
        return None

    mock_func = MagicMock()
    assert is_mocked(mock_func)
    assert not is_mocked(real_func)
    # With original check
    assert is_mocked(mock_func, original=real_func)
    assert not is_mocked(real_func, original=real_func)


def test_pooled_get_reuses_keep_alive_client(monkeypatch) -> None:
    close_shared_clients()
    seen: list[httpx.Client] = []

    class FakeResp:
        status_code = 200

    def fake_request(self, method, url, **kwargs):
        seen.append(self)
        return FakeResp()

    monkeypatch.setattr(httpx.Client, "request", fake_request)
    pooled_get("https://example.test/a", pool_name="pool_reuse", timeout=3.0)
    pooled_get("https://example.test/b", pool_name="pool_reuse", timeout=3.0)
    assert len(seen) == 2
    assert seen[0] is seen[1]
    close_shared_clients()


def test_use_shared_httpx_routes_module_get(monkeypatch) -> None:
    close_shared_clients()
    calls: list[str] = []

    class FakeResp:
        status_code = 200

    def fake_request(self, method, url, **kwargs):
        calls.append(url)
        return FakeResp()

    monkeypatch.setattr(httpx.Client, "request", fake_request)
    with use_shared_httpx(pool_name="ctx_pool"):
        httpx.get("https://example.test/via-pool", timeout=2.0)
    assert calls == ["https://example.test/via-pool"]
    close_shared_clients()
