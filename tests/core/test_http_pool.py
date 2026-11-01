"""Tests for shared HTTP keep-alive connection pool in Hecate-Core."""

from __future__ import annotations

from unittest.mock import MagicMock

from hecate_agent.core.http_pool import (
    close_shared_clients,
    get_shared_client,
    is_mocked,
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
