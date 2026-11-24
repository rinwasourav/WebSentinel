"""Evidence cleanup and deterministic finding normalization."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_SECRET = re.compile(
    r"(?i)(authorization|cookie|set-cookie|token|password|secret)\s*[:=]\s*(?:Bearer\s+)?[^&;,\s]+"
)


def redact(text: str) -> str:
    """Redact common credential material from evidence and URLs."""
    value = _SECRET.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc:
            host = parsed.hostname or ""
            netloc = host + (f":{parsed.port}" if parsed.port else "")
            value = urlunsplit(
                (parsed.scheme, netloc, parsed.path, "[REDACTED]" if parsed.query else "", "")
            )
    except ValueError:
        pass
    return value[:1000]


def redact_tree(value: Any) -> Any:
    """Recursively redact strings before serialization."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, (list, tuple)):
        return [redact_tree(item) for item in value]
    if isinstance(value, dict):
        sensitive = ("authorization", "cookie", "token", "password", "secret", "credential")
        return {
            key: "[REDACTED]"
            if any(word in str(key).lower() for word in sensitive)
            else redact_tree(item)
            for key, item in value.items()
        }
    return value
