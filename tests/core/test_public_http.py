"""Untrusted downloads must never reconnect through an unchecked hostname."""

import socket

import httpx
import pytest

from hecate_agent.core import public_http as ph


class Body(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False

    def __iter__(self):
        yield from self.chunks

    def close(self):
        self.closed = True


@pytest.fixture
def public_dns(monkeypatch):
    calls = []

    def lookup(host, port, **kwargs):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(ph.socket, "getaddrinfo", lookup)
    return calls


def transport(monkeypatch, handler):
    monkeypatch.setattr("httpx._client.HTTPTransport", lambda **kwargs: httpx.MockTransport(handler))


def test_rebinding_cannot_change_the_connection_destination(monkeypatch):
    calls = []

    def lookup(host, port, **kwargs):
        calls.append(host)
        address = "93.184.216.34" if len(calls) == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    monkeypatch.setattr(ph.socket, "getaddrinfo", lookup)

    def handle(request):
        assert request.url.host == "93.184.216.34"
        assert request.headers["Host"] == "reports.example"
        assert request.extensions["sni_hostname"] == "reports.example"
        return httpx.Response(200, stream=Body([b"public report"]))

    transport(monkeypatch, handle)
    response = ph.public_get("https://reports.example/report")
    assert response.text == "public report"
    assert str(response.url) == "https://reports.example/report"
    assert calls == ["reports.example"]


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "::ffff:127.0.0.1",
        "ff02::1",
        "2002:7f00:1::",
        "64:ff9b::7f00:1",
        "64:ff9b:1::7f00:1",
        "100.100.100.200",
    ],
)
def test_nonpublic_or_transition_addresses_are_rejected(monkeypatch, address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    monkeypatch.setattr(ph.socket, "getaddrinfo", lambda *a, **k: [(family, 1, 6, "", (address, 443))])
    with pytest.raises(ValueError):
        ph.public_get("https://reports.example/report")


def test_mixed_dns_answers_are_rejected_before_any_connection(monkeypatch):
    monkeypatch.setattr(
        ph.socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET, 1, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, 1, 6, "", ("10.0.0.1", 443)),
        ],
    )
    with pytest.raises(ValueError):
        ph.public_get("https://reports.example/report")


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://{}@reports.example/".format(":".join(("user", "password"))),
        "http://@reports.example/",
        "https://reports.example:8000/",
        "https://reports.example:bad/",
        "https://[fe80::1%25eth0]/",
    ],
)
def test_unsafe_url_syntax_never_reaches_dns(monkeypatch, url):
    monkeypatch.setattr(ph.socket, "getaddrinfo", lambda *a, **k: pytest.fail("DNS must not run"))
    with pytest.raises((ValueError, httpx.InvalidURL)):
        ph.public_get(url)


def test_redirect_to_private_address_is_not_connected(monkeypatch, public_dns):
    calls = []

    def lookup(host, port, **kwargs):
        address = "93.184.216.34" if host == "reports.example" else "169.254.169.254"
        return [(socket.AF_INET, 1, 6, "", (address, port))]

    monkeypatch.setattr(ph.socket, "getaddrinfo", lookup)

    def handle(request):
        calls.append(request.url.host)
        return httpx.Response(302, headers={"location": "https://metadata.example/latest/"})

    transport(monkeypatch, handle)
    with pytest.raises(ValueError):
        ph.public_get("https://reports.example/report")
    assert calls == ["93.184.216.34"]


def test_redirect_removes_credentials_and_preserves_relative_urls(monkeypatch, public_dns):
    calls = []

    def handle(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(302, headers={"location": "https://other.example/readme"})
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        assert request.headers["Host"] == "other.example"
        return httpx.Response(200, stream=Body([b"done"]))

    transport(monkeypatch, handle)
    response = ph.public_get("https://reports.example/report", headers={"Authorization": "fixture", "Cookie": "fixture"})
    assert response.text == "done"


def test_relative_redirect_uses_original_hostname(monkeypatch, public_dns):
    seen = []

    def handle(request):
        seen.append(request.url.path)
        if len(seen) == 1:
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, stream=Body([b"done"]))

    transport(monkeypatch, handle)
    assert ph.public_get("https://reports.example/start").text == "done"
    assert public_dns == ["reports.example", "reports.example"]
    assert seen == ["/start", "/final"]


@pytest.mark.parametrize("headers", [{"content-length": "99999999"}, {"content-encoding": "gzip"}])
def test_oversized_or_compressed_bodies_are_rejected_before_read(monkeypatch, public_dns, headers):
    body = Body([b"x"])
    transport(monkeypatch, lambda r: httpx.Response(200, headers=headers, stream=body))
    with pytest.raises(ValueError):
        ph.public_get("https://reports.example/report")
    assert body.closed


def test_chunked_response_byte_limit_and_connection_cleanup(monkeypatch, public_dns):
    body = Body([b"123", b"456"])
    transport(monkeypatch, lambda r: httpx.Response(200, stream=body))
    with pytest.raises(ValueError, match="byte limit"):
        ph.public_get("https://reports.example/report", max_bytes=5)
    assert body.closed


def test_redirect_loops_and_https_downgrades_fail(monkeypatch, public_dns):
    transport(monkeypatch, lambda r: httpx.Response(302, headers={"location": "/again"}))
    with pytest.raises(ValueError, match="redirect limit"):
        ph.public_get("https://reports.example/report")
    transport(monkeypatch, lambda r: httpx.Response(302, headers={"location": "http://reports.example/"}))
    with pytest.raises(ValueError, match="downgrade"):
        ph.public_get("https://reports.example/report")
