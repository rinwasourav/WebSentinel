from __future__ import annotations

import socket

import httpx
import pytest
import respx

from websentinel.http.client import PolicyHTTPClient
from websentinel.scope.guard import ScopeError, ScopePolicy


def _public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, type: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
        ],
    )


def test_get_sends_identifying_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    _public_dns(monkeypatch)
    policy = ScopePolicy(frozenset({"public.test"}), True, requests_per_second=1000)
    with respx.mock(assert_all_called=True) as router:
        route = router.get("https://public.test/").mock(
            return_value=httpx.Response(200, headers={"X-Content-Type-Options": "nosniff"})
        )
        response = PolicyHTTPClient(policy).get("https://public.test")
    assert response.status_code == 200
    assert route.calls[0].request.headers["user-agent"].startswith("WebSentinel/")


def test_redirect_leaving_scope_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    _public_dns(monkeypatch)
    policy = ScopePolicy(frozenset({"public.test"}), True, requests_per_second=1000)
    with respx.mock(assert_all_called=True) as router:
        router.get("https://public.test/").mock(
            return_value=httpx.Response(302, headers={"location": "https://other.test/"})
        )
        with pytest.raises(ScopeError, match="allowlist"):
            PolicyHTTPClient(policy).get("https://public.test/")
        assert len(router.calls) == 1


def test_request_cap_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    _public_dns(monkeypatch)
    policy = ScopePolicy(frozenset({"public.test"}), True, max_requests=1, requests_per_second=1000)
    with respx.mock(assert_all_called=True) as router:
        router.get("https://public.test/").mock(return_value=httpx.Response(200))
        client = PolicyHTTPClient(policy)
        client.get("https://public.test/")
        with pytest.raises(RuntimeError, match="request limit"):
            client.get("https://public.test/")
        assert len(router.calls) == 1


def test_redirect_to_private_ip_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    _public_dns(monkeypatch)
    policy = ScopePolicy(frozenset({"public.test", "10.0.0.4"}), True, requests_per_second=1000)
    with respx.mock(assert_all_called=True) as router:
        router.get("https://public.test/").mock(
            return_value=httpx.Response(302, headers={"location": "http://10.0.0.4/"})
        )
        with pytest.raises(ScopeError, match="local-lab"):
            PolicyHTTPClient(policy).get("https://public.test/")
