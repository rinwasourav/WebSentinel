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
    with pytest.raises(ScopeError, match="network policy"):
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
    with pytest.raises(ScopeError, match="outside the allowed"):
        validate_url("https://example.test", policy(), resolve=True)


def test_local_lab_defaults_to_ipv4_and_ipv6_loopback_only() -> None:
    local = ScopePolicy(frozenset({"127.0.0.1"}), True, local_lab=True)
    assert validate_url("http://127.0.0.1/", local, resolve=False)

    local_v6 = ScopePolicy(frozenset({"::1"}), True, local_lab=True)
    assert validate_url("http://[::1]/", local_v6, resolve=False)

    private = ScopePolicy(frozenset({"10.2.3.4"}), True, local_lab=True)
    with pytest.raises(ScopeError, match="network policy"):
        validate_url("http://10.2.3.4/", private, resolve=False)

    public = ScopePolicy(frozenset({"93.184.216.34"}), True, local_lab=True)
    with pytest.raises(ScopeError, match="network policy"):
        validate_url("http://93.184.216.34/", public, resolve=False)


def test_additional_rfc1918_and_ula_ranges_require_configuration() -> None:
    with pytest.raises(ScopeError, match="network policy"):
        validate_url(
            "http://10.2.3.4/",
            ScopePolicy(frozenset({"10.2.3.4"}), True, local_lab=True),
            resolve=False,
        )

    approved_v4 = ScopePolicy(
        frozenset({"10.2.3.4"}), True, local_lab=True, lab_cidrs=frozenset({"10.0.0.0/8"})
    )
    assert validate_url("http://10.2.3.4/", approved_v4, resolve=False)

    outside = ScopePolicy(
        frozenset({"10.2.3.4"}), True, local_lab=True, lab_cidrs=frozenset({"10.3.0.0/16"})
    )
    with pytest.raises(ScopeError, match="network policy"):
        validate_url("http://10.2.3.4/", outside, resolve=False)

    approved_v6 = ScopePolicy(
        frozenset({"fd12:3456::4"}), True, local_lab=True, lab_cidrs=frozenset({"fd12:3456::/48"})
    )
    assert validate_url("http://[fd12:3456::4]/", approved_v6, resolve=False)


def test_lab_cidr_configuration_must_be_scoped_to_private_ranges() -> None:
    with pytest.raises(ScopeError, match="require --local-lab"):
        ScopePolicy(frozenset({"example.test"}), True, lab_cidrs=frozenset({"10.0.0.0/8"}))
    with pytest.raises(ScopeError, match="RFC1918 or IPv6 ULA"):
        ScopePolicy(
            frozenset({"example.test"}), True, local_lab=True, lab_cidrs=frozenset({"0.0.0.0/0"})
        )
    with pytest.raises(ScopeError, match="Invalid lab CIDR"):
        ScopePolicy(
            frozenset({"example.test"}), True, local_lab=True, lab_cidrs=frozenset({"not-a-cidr"})
        )


@pytest.mark.parametrize(
    "host",
    ["169.254.1.10", "169.254.169.254", "169.254.170.2", "100.100.100.200", "168.63.129.16"],
)
def test_local_lab_blocks_link_local_and_cloud_metadata_ipv4(host: str) -> None:
    local = ScopePolicy(
        frozenset({host}), True, local_lab=True, lab_cidrs=frozenset({"10.0.0.0/8"})
    )
    with pytest.raises(ScopeError, match="network policy"):
        validate_url(f"http://{host}/", local, resolve=False)


def test_local_lab_blocks_cloud_metadata_ipv6_even_when_cidr_is_approved() -> None:
    local = ScopePolicy(
        frozenset({"fd00:ec2::254"}),
        True,
        local_lab=True,
        lab_cidrs=frozenset({"fd00::/8"}),
    )
    with pytest.raises(ScopeError, match="network policy"):
        validate_url("http://[fd00:ec2::254]/", local, resolve=False)


def test_ipv4_mapped_ipv6_obeys_ipv4_lab_rules() -> None:
    loopback = ScopePolicy(frozenset({"::ffff:127.0.0.1"}), True, local_lab=True)
    assert validate_url("http://[::ffff:127.0.0.1]/", loopback, resolve=False)

    mapped_private = ScopePolicy(
        frozenset({"::ffff:10.2.3.4"}),
        True,
        local_lab=True,
        lab_cidrs=frozenset({"10.0.0.0/8"}),
    )
    assert validate_url("http://[::ffff:10.2.3.4]/", mapped_private, resolve=False)


def test_local_lab_rejects_mixed_public_and_approved_private_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, type: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.10.0.5", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
        ],
    )
    local = ScopePolicy(
        frozenset({"example.test"}), True, local_lab=True, lab_cidrs=frozenset({"10.0.0.0/8"})
    )
    with pytest.raises(ScopeError, match="outside the allowed"):
        validate_url("http://example.test/", local)
