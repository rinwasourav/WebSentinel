"""Default-deny authorization, scope, URL and address validation."""

from __future__ import annotations

import ipaddress
import math
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class ScopeError(ValueError):
    """Raised when an assessment request violates its authorization policy."""


def _normalize_host(host: str) -> str:
    """Normalize IP literals and international DNS names to HTTPX host form."""
    host = host.rstrip(".").lower()
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        try:
            return host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ScopeError("Invalid internationalized hostname") from exc


_PRIVATE_LAB_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)
_CLOUD_METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(address)
    for address in (
        "169.254.169.254",  # Common cloud instance metadata endpoint.
        "169.254.170.2",  # AWS ECS task metadata endpoint.
        "100.100.100.200",  # Alibaba Cloud metadata endpoint.
        "168.63.129.16",  # Azure platform virtual IP.
        "fd00:ec2::254",  # AWS IPv6 metadata endpoint.
    )
)
_MAX_VALIDATED_ADDRESSES = 16


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    """Immutable authorization boundary and per-assessment network limits."""

    allowed_hosts: frozenset[str]
    authorized: bool = False
    local_lab: bool = False
    max_requests: int = 20
    requests_per_second: float = 1.0
    timeout: float = 5.0
    max_redirects: int = 3
    lab_cidrs: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if (
            self.max_requests < 1
            or self.max_redirects < 0
            or not math.isfinite(self.requests_per_second)
            or not math.isfinite(self.timeout)
            or self.requests_per_second <= 0
            or self.timeout <= 0
        ):
            raise ScopeError("Request limits and timeout must be positive")
        normalized = frozenset(_normalize_host(host) for host in self.allowed_hosts)
        if not normalized or "*" in normalized:
            raise ScopeError("Explicit host allowlist is required; wildcards are not supported")
        object.__setattr__(self, "allowed_hosts", normalized)
        if self.lab_cidrs and not self.local_lab:
            raise ScopeError("Additional lab CIDRs require --local-lab")
        networks: set[str] = set()
        for cidr in self.lab_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ScopeError(f"Invalid lab CIDR: {cidr}") from exc
            if not any(
                network.version == allowed.version
                and int(network.network_address) >= int(allowed.network_address)
                and int(network.broadcast_address) <= int(allowed.broadcast_address)
                for allowed in _PRIVATE_LAB_RANGES
            ):
                raise ScopeError("Lab CIDRs must be inside RFC1918 or IPv6 ULA ranges")
            networks.add(str(network))
        object.__setattr__(self, "lab_cidrs", frozenset(networks))


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    """Canonical request URL and the exact IP addresses approved for connection."""

    url: str
    host: str
    port: int
    addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]


def _unmap_ipv4(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Treat IPv4-mapped IPv6 destinations as their embedded IPv4 address."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _address_is_allowed(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    policy: ScopePolicy,
) -> bool:
    """Apply public-assessment or explicit local-lab destination policy."""
    address = _unmap_ipv4(address)
    if address in _CLOUD_METADATA_ADDRESSES or address.is_link_local:
        return False
    if address.is_loopback:
        return policy.local_lab
    if address.is_reserved or address.is_multicast or address.is_unspecified:
        return False
    if not policy.local_lab:
        return address.is_global
    if address.is_global:
        return False
    return any(address in ipaddress.ip_network(cidr) for cidr in policy.lab_cidrs)


def _canonicalize(url: str, policy: ScopePolicy) -> tuple[str, str, int]:
    if not policy.authorized:
        raise ScopeError("Explicit authorization acknowledgment is required")
    try:
        parsed = urlsplit(url)
        explicit_port = parsed.port
    except ValueError as exc:
        raise ScopeError("Malformed URL or port") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("Only absolute HTTP(S) URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ScopeError("Credential-bearing URLs are not allowed")
    host = _normalize_host(parsed.hostname)
    if host not in policy.allowed_hosts:
        raise ScopeError("Target host is outside the explicit allowlist")
    is_local_name = host == "localhost" or host.endswith(".localhost")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if is_local_name and not policy.local_lab:
        raise ScopeError("Loopback targets require explicit local-lab mode")
    if literal is not None and not _address_is_allowed(literal, policy):
        raise ScopeError("IP target is outside the local-lab network policy")
    if explicit_port == 0:
        raise ScopeError("Port zero is not a valid assessment target")
    port = explicit_port if explicit_port is not None else (443 if parsed.scheme == "https" else 80)
    clean_path = parsed.path or "/"
    canonical_url = urlunsplit((parsed.scheme, parsed.netloc, clean_path, parsed.query, ""))
    return canonical_url, host, port


def resolve_target(url: str, policy: ScopePolicy) -> ValidatedTarget:
    """Validate a URL and capture safe DNS answers for connection pinning."""
    canonical_url, host, port = _canonicalize(url, policy)
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError("Target DNS resolution failed") from exc
    addresses = {ipaddress.ip_address(str(record[4][0]).split("%", 1)[0]) for record in records}
    normalized_addresses = {_unmap_ipv4(address) for address in addresses}
    if not normalized_addresses:
        raise ScopeError("Target DNS resolution returned no addresses")
    if len(normalized_addresses) > _MAX_VALIDATED_ADDRESSES:
        raise ScopeError("Target DNS resolution returned too many addresses")
    for address in normalized_addresses:
        if not _address_is_allowed(address, policy):
            raise ScopeError("Target resolves outside the allowed public or local-lab networks")
    return ValidatedTarget(canonical_url, host, port, tuple(sorted(normalized_addresses, key=str)))


def validate_url(url: str, policy: ScopePolicy, *, resolve: bool = True) -> str:
    """Validate authorization, scope, scheme and IP policy, returning a safe URL."""
    if resolve:
        return resolve_target(url, policy).url
    canonical_url, _, _ = _canonicalize(url, policy)
    return canonical_url
