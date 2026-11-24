"""Default-deny authorization, scope, URL and address validation."""

from __future__ import annotations

import ipaddress
import math
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class ScopeError(ValueError):
    """Raised when an assessment request violates its authorization policy."""


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
        normalized = frozenset(h.rstrip(".").lower() for h in self.allowed_hosts)
        if not normalized or "*" in normalized:
            raise ScopeError("Explicit host allowlist is required; wildcards are not supported")
        object.__setattr__(self, "allowed_hosts", normalized)


def validate_url(url: str, policy: ScopePolicy, *, resolve: bool = True) -> str:
    """Validate URL authorization, exact host scope, scheme, credentials and IP policy."""
    if not policy.authorized:
        raise ScopeError("Explicit authorization acknowledgment is required")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ScopeError("Malformed URL or port") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("Only absolute HTTP(S) URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ScopeError("Credential-bearing URLs are not allowed")
    host = parsed.hostname.rstrip(".").lower()
    if host not in policy.allowed_hosts:
        raise ScopeError("Target host is outside the explicit allowlist")
    is_local_name = host == "localhost" or host.endswith(".localhost")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if is_local_name and not policy.local_lab:
        raise ScopeError("Loopback targets require explicit local-lab mode")
    if literal is not None and not literal.is_global and not policy.local_lab:
        raise ScopeError("Private or reserved IP targets require explicit local-lab mode")
    if resolve:
        try:
            records = socket.getaddrinfo(
                host, port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise ScopeError("Target DNS resolution failed") from exc
        addresses = {ipaddress.ip_address(str(record[4][0]).split("%", 1)[0]) for record in records}
        if not addresses:
            raise ScopeError("Target DNS resolution returned no addresses")
        for address in addresses:
            permitted_lab_address = policy.local_lab and (address.is_loopback or address.is_private)
            if not address.is_global and not permitted_lab_address:
                raise ScopeError("Target resolves to a private, reserved, or non-global address")
    clean_path = parsed.path or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, clean_path, parsed.query, ""))
