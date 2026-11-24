"""Small policy-enforced HTTP client with validated manual redirects."""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from websentinel.http.transport import PinnedHTTPTransport
from websentinel.scope.guard import ScopePolicy, resolve_target


@dataclass(frozen=True, slots=True)
class SafeResponse:
    """Only response metadata needed by passive checks; never holds a body."""

    url: str
    status_code: int
    headers: dict[str, str]
    cookies: tuple[str, ...]
    elapsed_seconds: float
    tls: dict[str, str]


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

    def get(self, url: str) -> SafeResponse:
        """Fetch response metadata using bounded GET and validated redirects."""
        target = resolve_target(url, self.policy)
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
            with httpx.Client(
                transport=PinnedHTTPTransport(target),
                timeout=self.policy.timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    "GET", current, headers={"User-Agent": self.user_agent}, follow_redirects=False
                ) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location or redirect_count >= self.policy.max_redirects:
                            raise RuntimeError("Redirect limit reached or location missing")
                        redirect_url = str(response.url.join(location))
                    else:
                        cookie_headers = tuple(response.headers.get_list("set-cookie"))
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
                        )
            if redirect_url is not None:
                target = resolve_target(redirect_url, self.policy)
                current = target.url
                continue
        raise RuntimeError("Redirect policy exhausted")
