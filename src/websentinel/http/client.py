"""Small policy-enforced HTTP client with validated manual redirects."""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from websentinel.http.transport import PinnedHTTPTransport
from websentinel.scope.guard import ScopeError, ScopePolicy, resolve_target


@dataclass(frozen=True, slots=True)
class SafeResponse:
    """Sanitized response metadata and an optional capped HTML body."""

    url: str
    status_code: int
    headers: dict[str, str]
    cookies: tuple[str, ...]
    elapsed_seconds: float
    tls: dict[str, str]
    body: bytes = b""
    body_truncated: bool = False


class PolicyHTTPClient:
    """Performs bounded GET requests; redirect destinations are revalidated."""

    def __init__(
        self,
        policy: ScopePolicy,
        user_agent: str = "WebSentinel/0.1 (+https://github.com/rinwasourav/WebSentinel)",
    ) -> None:
        self.policy = policy
        self.user_agent = user_agent
        self._requests = 0
        self._last_request = 0.0

    @property
    def request_count(self) -> int:
        """Return the total number of HTTP requests including redirects."""
        return self._requests

    @property
    def requests_remaining(self) -> int:
        """Return the remaining policy request budget."""
        return max(0, self.policy.max_requests - self._requests)

    def get(self, url: str, *, max_body_bytes: int = 0, same_origin: bool = False) -> SafeResponse:
        """Fetch bounded response metadata and optionally a capped HTML body."""
        if max_body_bytes < 0:
            raise ValueError("max_body_bytes cannot be negative")
        target = resolve_target(url, self.policy)
        parsed_start = urlsplit(target.url)
        expected_origin = (parsed_start.scheme, target.host, target.port)
        current = target.url
        started = time.monotonic()
        for redirect_count in range(self.policy.max_redirects + 1):
            if self._requests >= self.policy.max_requests:
                raise RuntimeError("Assessment request limit reached")
            delay = 1.0 / self.policy.requests_per_second - (time.monotonic() - self._last_request)
            if delay > 0:
                time.sleep(delay)
            self._requests += 1
            self._last_request = time.monotonic()
            redirect_url: str | None = None
            request_headers = {"User-Agent": self.user_agent}
            if max_body_bytes:
                request_headers["Accept-Encoding"] = "identity"
            with httpx.Client(
                transport=PinnedHTTPTransport(target),
                timeout=self.policy.timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    "GET", current, headers=request_headers, follow_redirects=False
                ) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location or redirect_count >= self.policy.max_redirects:
                            raise RuntimeError("Redirect limit reached or location missing")
                        redirect_url = str(response.url.join(location))
                    else:
                        cookie_headers = tuple(response.headers.get_list("set-cookie"))
                        body = b""
                        body_truncated = False
                        content_type = response.headers.get("content-type", "").lower()
                        is_html = content_type.startswith(("text/html", "application/xhtml+xml"))
                        if max_body_bytes and is_html:
                            encoding = response.headers.get("content-encoding", "identity").lower()
                            content_length = response.headers.get("content-length")
                            can_read = encoding in {"", "identity"}
                            if encoding not in {"", "identity"}:
                                body_truncated = True
                            elif content_length is not None:
                                try:
                                    body_truncated = int(content_length) > max_body_bytes
                                except ValueError:
                                    pass
                            if can_read:
                                collected = bytearray()
                                for chunk in response.iter_raw(chunk_size=16 * 1024):
                                    remaining = max_body_bytes - len(collected)
                                    if len(chunk) > remaining:
                                        collected.extend(chunk[:remaining])
                                        body_truncated = True
                                        break
                                    collected.extend(chunk)
                                body = bytes(collected)
                        tls: dict[str, str] = {}
                        stream = response.extensions.get("network_stream")
                        if stream is not None:
                            try:
                                ssl_obj = stream.get_extra_info("ssl_object")
                                if ssl_obj is not None:
                                    cert = ssl_obj.getpeercert()
                                    tls = {
                                        "version": ssl_obj.version() or "",
                                        "cipher": str(ssl_obj.cipher()),
                                        "not_after": str(cert.get("notAfter", "")),
                                    }
                            except (AttributeError, OSError, ValueError):
                                tls = {}
                        return SafeResponse(
                            str(response.url),
                            response.status_code,
                            {k.lower(): v for k, v in response.headers.items()},
                            cookie_headers,
                            time.monotonic() - started,
                            tls,
                            body,
                            body_truncated,
                        )
            if redirect_url is not None:
                redirected_target = resolve_target(redirect_url, self.policy)
                parsed_redirect = urlsplit(redirected_target.url)
                if (
                    same_origin
                    and (
                        parsed_redirect.scheme,
                        redirected_target.host,
                        redirected_target.port,
                    )
                    != expected_origin
                ):
                    raise ScopeError("Crawler redirect is outside its same-origin boundary")
                target = redirected_target
                current = target.url
                continue
        raise RuntimeError("Redirect policy exhausted")
