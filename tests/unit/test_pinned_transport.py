import ipaddress

import httpcore
import pytest

from websentinel.http.transport import PinnedNetworkBackend
from websentinel.scope.guard import ValidatedTarget


class _FakeStream:
    def __init__(self, peer: str) -> None:
        self.peer = peer
        self.closed = False

    def get_extra_info(self, info: str) -> object:
        if info == "server_addr":
            return (self.peer, 443)
        return None

    def close(self) -> None:
        self.closed = True


class _FakeBackend:
    def __init__(self, stream: _FakeStream) -> None:
        self.stream = stream
        self.hosts: list[str] = []

    def connect_tcp(self, host: str, **kwargs: object) -> _FakeStream:
        self.hosts.append(host)
        return self.stream

    def connect_unix_socket(self, path: str, **kwargs: object) -> _FakeStream:
        raise AssertionError("URL transport must never use Unix sockets")

    def sleep(self, seconds: float) -> None:
        return None


def _target() -> ValidatedTarget:
    return ValidatedTarget(
        "https://example.test/",
        "example.test",
        443,
        (ipaddress.ip_address("93.184.216.34"),),
    )


def test_backend_connects_to_pinned_ip_and_checks_actual_peer() -> None:
    stream = _FakeStream("93.184.216.34")
    backend = _FakeBackend(stream)
    network = PinnedNetworkBackend(_target(), backend)  # type: ignore[arg-type]

    connected = network.connect_tcp("example.test", 443)

    assert connected is stream
    assert backend.hosts == ["93.184.216.34"]


def test_backend_closes_and_rejects_unexpected_connected_peer() -> None:
    stream = _FakeStream("10.0.0.8")
    backend = _FakeBackend(stream)
    network = PinnedNetworkBackend(_target(), backend)  # type: ignore[arg-type]

    with pytest.raises(httpcore.ConnectError, match="differs"):
        network.connect_tcp("example.test", 443)
    assert stream.closed


def test_backend_rejects_changed_connection_origin() -> None:
    stream = _FakeStream("93.184.216.34")
    network = PinnedNetworkBackend(_target(), _FakeBackend(stream))  # type: ignore[arg-type]

    with pytest.raises(httpcore.ConnectError, match="origin"):
        network.connect_tcp("other.test", 443)


def test_transport_keeps_hostname_certificate_verification_enabled() -> None:
    import ssl

    from websentinel.http.transport import PinnedHTTPTransport

    transport = PinnedHTTPTransport(_target())
    try:
        context = transport._pool._ssl_context
        assert context is not None
        assert context.check_hostname
        assert context.verify_mode == ssl.CERT_REQUIRED
    finally:
        transport.close()
