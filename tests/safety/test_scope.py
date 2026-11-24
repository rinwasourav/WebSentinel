import socket

import pytest

from websentinel.scope.guard import ScopeError, ScopePolicy, validate_url


def policy(**kwargs: object) -> ScopePolicy:
    values: dict[str, object] = {"allowed_hosts": frozenset({"example.test"}), "authorized": True}
    values.update(kwargs)
    return ScopePolicy(**values)  # type: ignore[arg-type]


def test_authorization_required() -> None:
    with pytest.raises(ScopeError, match="authorization"):
        validate_url("https://example.test", policy(authorized=False), resolve=False)


def test_exact_host_allowlist() -> None:
    with pytest.raises(ScopeError, match="allowlist"):
        validate_url("https://evil.test", policy(), resolve=False)


def test_credentials_rejected() -> None:
    with pytest.raises(ScopeError, match="Credential"):
        validate_url("https://user:pass@example.test", policy(), resolve=False)


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "ftp://example.test", "//example.test", "https:///missing"]
)
def test_unsupported_or_malformed_urls(url: str) -> None:
    with pytest.raises(ScopeError):
        validate_url(url, policy(), resolve=False)


def test_loopback_requires_local_lab() -> None:
    p = ScopePolicy(frozenset({"127.0.0.1"}), authorized=True)
    with pytest.raises(ScopeError, match="local-lab"):
        validate_url("http://127.0.0.1", p, resolve=False)
    assert validate_url(
        "http://127.0.0.1", ScopePolicy(frozenset({"127.0.0.1"}), True, True), resolve=False
    )


def test_wildcard_not_allowed() -> None:
    with pytest.raises(ScopeError):
        ScopePolicy(frozenset({"*"}), authorized=True)


def test_invalid_unbounded_limits_are_rejected() -> None:
    with pytest.raises(ScopeError):
        ScopePolicy(frozenset({"example.test"}), authorized=True, requests_per_second=float("nan"))
    with pytest.raises(ScopeError):
        ScopePolicy(frozenset({"example.test"}), authorized=True, timeout=float("inf"))
    with pytest.raises(ScopeError):
        ScopePolicy(frozenset({"example.test"}), authorized=True, max_redirects=-1)


def test_public_ip_can_be_allowed_by_exact_scope() -> None:
    policy = ScopePolicy(frozenset({"93.184.216.34"}), authorized=True)
    assert validate_url("https://93.184.216.34", policy, resolve=False)


def test_private_ip_requires_local_lab_opt_in() -> None:
    policy = ScopePolicy(frozenset({"10.0.0.4"}), authorized=True)
    with pytest.raises(ScopeError, match="Private or reserved"):
        validate_url("http://10.0.0.4", policy, resolve=False)


def test_international_hostname_allowlist_is_normalized() -> None:
    policy = ScopePolicy(frozenset({"bücher.example"}), authorized=True)
    assert validate_url("https://xn--bcher-kva.example/", policy, resolve=False)


def test_port_zero_is_rejected() -> None:
    with pytest.raises(ScopeError, match="Port zero"):
        validate_url("http://example.test:0", policy(), resolve=False)


def test_dns_private_resolution_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, type: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.10.0.5", port))],
    )
    with pytest.raises(ScopeError, match="resolves to a private"):
        validate_url("https://example.test", policy(), resolve=True)
