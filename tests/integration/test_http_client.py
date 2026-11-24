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


def test_crawler_redirect_cannot_cross_origin_inside_broad_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _public_dns(monkeypatch)
    policy = ScopePolicy(frozenset({"public.test", "other.test"}), True, requests_per_second=1000)
    with respx.mock(assert_all_called=True) as router:
        router.get("https://public.test/").mock(
            return_value=httpx.Response(302, headers={"location": "https://other.test/"})
        )
        with pytest.raises(ScopeError, match="same-origin"):
            PolicyHTTPClient(policy).get("https://public.test/", same_origin=True)
        assert len(router.calls) == 1


def test_html_body_is_capped_and_default_request_does_not_read_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _public_dns(monkeypatch)
    policy = ScopePolicy(frozenset({"public.test"}), True, requests_per_second=1000)
    with respx.mock(assert_all_called=True) as router:
        router.get("https://public.test/").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "text/html"}, content=b"abcdefgh"
            )
        )
        client = PolicyHTTPClient(policy)
        assert client.get("https://public.test/").body == b""
        capped = client.get("https://public.test/", max_body_bytes=4)
    assert capped.body == b"abcd"
    assert capped.body_truncated


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


def test_connection_uses_validated_ip_instead_of_resolving_hostname_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(204)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    original_getaddrinfo = socket.getaddrinfo
    hostname_lookups: list[str] = []

    def getaddrinfo(
        host: str, port: int, *args: object, **kwargs: object
    ) -> list[tuple[object, ...]]:
        if host == "pinned.test":
            hostname_lookups.append(host)
            return original_getaddrinfo("127.0.0.1", port, *args, **kwargs)  # type: ignore[arg-type]
        return original_getaddrinfo(host, port, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    try:
        policy = ScopePolicy(
            frozenset({"pinned.test"}), True, local_lab=True, requests_per_second=1000
        )
        response = PolicyHTTPClient(policy).get(f"http://pinned.test:{server.server_address[1]}/")
        assert response.status_code == 204
        assert hostname_lookups == ["pinned.test"]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_redirect_re_resolves_and_rejects_rebound_private_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_getaddrinfo = socket.getaddrinfo
    hostname_lookups = 0

    def rebinding_getaddrinfo(
        host: str, port: int, *args: object, **kwargs: object
    ) -> list[tuple[object, ...]]:
        nonlocal hostname_lookups
        if host == "rebind.test":
            hostname_lookups += 1
            address = "93.184.216.34" if hostname_lookups == 1 else "10.0.0.8"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]
        return original_getaddrinfo(host, port, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "getaddrinfo", rebinding_getaddrinfo)
    policy = ScopePolicy(frozenset({"rebind.test"}), True, requests_per_second=1000)
    with respx.mock(assert_all_called=True) as router:
        router.get("https://rebind.test/").mock(
            return_value=httpx.Response(302, headers={"location": "/next"})
        )
        with pytest.raises(ScopeError, match="outside the allowed"):
            PolicyHTTPClient(policy).get("https://rebind.test/")
        assert len(router.calls) == 1
    assert hostname_lookups == 2


def test_redirect_outside_approved_lab_cidr_is_blocked() -> None:
    policy = ScopePolicy(
        frozenset({"127.0.0.1", "192.168.1.7"}),
        True,
        local_lab=True,
        requests_per_second=1000,
        lab_cidrs=frozenset({"192.168.0.0/24"}),
    )
    with respx.mock(assert_all_called=True) as router:
        router.get("http://127.0.0.1/").mock(
            return_value=httpx.Response(302, headers={"location": "http://192.168.1.7/"})
        )
        with pytest.raises(ScopeError, match="network policy"):
            PolicyHTTPClient(policy).get("http://127.0.0.1/")
        assert len(router.calls) == 1
