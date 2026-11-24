"""URL normalization and safe same-origin link policy."""

from __future__ import annotations

import ipaddress
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit

_SENSITIVE_QUERY_KEYS = {
    "access_token",
    "auth",
    "code",
    "key",
    "password",
    "session",
    "sessionid",
    "token",
}
_TRACKING_KEYS = {"fbclid", "gclid"}
_UNSAFE_PATH_SEGMENTS = {
    "buy",
    "checkout",
    "delete",
    "destroy",
    "logout",
    "log-out",
    "purchase",
    "remove",
    "signout",
    "submit",
    "unsubscribe",
}
_UNSAFE_ACTIONS = {
    "buy",
    "checkout",
    "delete",
    "destroy",
    "logout",
    "purchase",
    "remove",
    "unsubscribe",
}
_MAX_URL_LENGTH = 2048


def _host(host: str) -> str:
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        return host.rstrip(".").encode("idna").decode("ascii").lower()


def origin(url: str) -> tuple[str, str, int] | None:
    """Return normalized scheme/host/port or None for a malformed URL."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except (ValueError, UnicodeError):
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    scheme = parsed.scheme.lower()
    return scheme, _host(host), port or (443 if scheme == "https" else 80)


def normalize_link(
    base_url: str,
    href: str,
    expected_origin: tuple[str, str, int],
    *,
    allow_sensitive_query: bool = False,
) -> tuple[str | None, str | None]:
    """Resolve and canonicalize a link, returning a rejection reason when unsafe."""
    candidate = urljoin(base_url, href.strip())
    actual_origin = origin(candidate)
    if actual_origin is None:
        return None, "unsupported URL or credentials"
    if actual_origin != expected_origin:
        return None, "outside same-origin policy"
    parsed = urlsplit(candidate)
    try:
        decoded_path = unquote(parsed.path, errors="strict").replace("\\", "/")
    except UnicodeError:
        return None, "malformed encoded path"
    segments = {part.split(";", 1)[0].casefold() for part in decoded_path.split("/")}
    if segments & _UNSAFE_PATH_SEGMENTS:
        return None, "state-changing or session-ending path"
    query: list[tuple[str, str]] = []
    try:
        params = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=200)
    except ValueError:
        return None, "malformed or excessive query parameters"
    for key, value in params:
        lowered = key.lower()
        if (
            lowered in {"action", "do", "intent", "method", "op"}
            and value.casefold() in _UNSAFE_ACTIONS
        ):
            return None, "state-changing or session-ending action"
        if lowered in _TRACKING_KEYS or lowered.startswith("utm_"):
            continue
        if not allow_sensitive_query and lowered in _SENSITIVE_QUERY_KEYS:
            return None, "sensitive query parameter"
        query.append((key, value))
    host = actual_origin[1]
    port = actual_origin[2]
    scheme = actual_origin[0]
    netloc = f"[{host}]" if ":" in host else host
    if port != (443 if scheme == "https" else 80):
        netloc += f":{port}"
    normalized = urlunsplit((scheme, netloc, parsed.path or "/", urlencode(sorted(query)), ""))
    if len(normalized) > _MAX_URL_LENGTH:
        return None, "URL exceeds maximum length"
    return normalized, None
