"""HTTPX transport that connects only to DNS addresses approved by Scope Guard."""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Iterable

import httpcore
import httpx

from websentinel.scope.guard import ValidatedTarget


class PinnedNetworkBackend(httpcore.NetworkBackend):
    """Replace hostname resolution at connect time with a prevalidated IP address."""

    def __init__(
        self,
        target: ValidatedTarget,
        socket_backend: httpcore.NetworkBackend | None = None,
    ) -> None:
        self._target = target
        self._socket_backend = socket_backend or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        if host.strip("[]").rstrip(".").lower() != self._target.host or port != self._target.port:
            raise httpcore.ConnectError("Connection origin differs from the validated target")

        last_error: httpcore.ConnectError | httpcore.ConnectTimeout | None = None
        deadline = None if timeout is None else time.monotonic() + timeout
        for address in self._target.addresses:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise httpcore.ConnectTimeout("Validated IP connection attempts exceeded timeout")
            try:
                stream = self._socket_backend.connect_tcp(
                    host=str(address),
                    port=port,
                    timeout=remaining,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
                continue

            peer = stream.get_extra_info("server_addr")
            if not isinstance(peer, tuple) or not peer:
                stream.close()
                raise httpcore.ConnectError("Connected peer address could not be verified")
            try:
                peer_address = ipaddress.ip_address(str(peer[0]).split("%", 1)[0])
            except ValueError as exc:
                stream.close()
                raise httpcore.ConnectError("Connected peer returned an invalid address") from exc
            if _normalized(peer_address) != _normalized(address):
                stream.close()
                raise httpcore.ConnectError("Connected peer differs from the validated address")
            return stream

        if last_error is not None:
            raise last_error
        raise httpcore.ConnectError("No validated destination address was available")

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        raise httpcore.ConnectError("Unix domain sockets are not supported for URL assessments")

    def sleep(self, seconds: float) -> None:
        self._socket_backend.sleep(seconds)


def _normalized(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Normalize IPv4-mapped IPv6 peer addresses for exact comparison."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


class PinnedHTTPTransport(httpx.HTTPTransport):
    """HTTP/1.1 transport pinned to validated IPs while retaining hostname SNI."""

    def __init__(self, target: ValidatedTarget) -> None:
        super().__init__(verify=True, trust_env=False, http1=True, http2=False, retries=0)
        # HTTPTransport owns the TLS context and pool configuration; swap only its
        # connection backend. The request URL remains the hostname, preserving SNI
        # and certificate hostname validation while TCP uses the validated IP.
        self._pool._network_backend = PinnedNetworkBackend(target)
