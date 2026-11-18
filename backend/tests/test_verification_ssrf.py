import socket
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.services import verification


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"])
async def test_private_and_loopback_ip_literals_are_not_public(host):
    assert await verification._resolve_public_addresses(host) == []


@pytest.mark.asyncio
async def test_hostname_resolving_to_private_address_is_rejected(monkeypatch):
    class PrivateAddressLoop:
        async def getaddrinfo(self, host, port, type):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 0))]

    monkeypatch.setattr(
        verification.asyncio,
        "get_running_loop",
        lambda: PrivateAddressLoop(),
    )
    assert await verification._resolve_public_addresses("internal.example.test") == []


@pytest.mark.parametrize(
    "domain",
    [
        "http://example.test",
        "https://user:pass@example.test",
        "https://example.test/?next=internal",
        "https://example.test/#fragment",
    ],
)
def test_https_target_rejects_unsafe_or_ambiguous_urls(domain):
    with pytest.raises(ValueError):
        verification._https_target(domain, "/")


@pytest.mark.asyncio
async def test_non_public_resolution_prevents_http_request(monkeypatch):
    monkeypatch.setattr(
        verification,
        "_resolve_public_addresses",
        AsyncMock(return_value=[]),
    )
    client_factory = Mock()
    monkeypatch.setattr(verification.httpx, "AsyncClient", client_factory)

    body, error = await verification._fetch_public_https("example.test", "/")

    assert body is None
    assert "public IP" in error
    client_factory.assert_not_called()


@pytest.mark.asyncio
async def test_http_verification_uses_verified_https_and_does_not_follow_redirects(monkeypatch):
    monkeypatch.setattr(
        verification,
        "_resolve_public_addresses",
        AsyncMock(return_value=["93.184.216.34"]),
    )
    client_options = {}

    class RedirectResponse:
        status_code = 302
        headers = {"Location": "http://127.0.0.1/"}
        text = ""

    class RecordingClient:
        def __init__(self, **kwargs):
            client_options.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return None

        async def get(self, url, headers, extensions):
            assert url == "https://93.184.216.34/"
            assert headers == {"Host": "example.test"}
            assert extensions == {"sni_hostname": "example.test"}
            return RedirectResponse()

    monkeypatch.setattr(verification.httpx, "AsyncClient", RecordingClient)

    body, error = await verification._fetch_public_https("example.test", "/")

    assert body is None
    assert "redirects are not followed" in error
    assert client_options["verify"] is True
    assert client_options["follow_redirects"] is False
    assert client_options["trust_env"] is False


@pytest.mark.asyncio
async def test_legacy_well_known_path_is_only_tried_after_canonical_404(monkeypatch):
    monkeypatch.setattr(
        verification,
        "_resolve_public_addresses",
        AsyncMock(return_value=["93.184.216.34"]),
    )
    requests = []
    responses = [
        SimpleNamespace(status_code=404, text=""),
        SimpleNamespace(status_code=200, text="aegis-verification=expected"),
    ]

    class RecordingClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return None

        async def get(self, url, headers, extensions):
            requests.append((url, headers, extensions))
            return responses.pop(0)

    monkeypatch.setattr(verification.httpx, "AsyncClient", RecordingClient)

    verified, _ = await verification.verify_well_known_file(
        "example.test",
        "expected",
    )

    assert verified
    assert [request[0] for request in requests] == [
        "https://93.184.216.34/.well-known/rakshak-verification.txt",
        "https://93.184.216.34/.well-known/aegis-verification.txt",
    ]
    assert all(request[1] == {"Host": "example.test"} for request in requests)
    assert all(request[2] == {"sni_hostname": "example.test"} for request in requests)
