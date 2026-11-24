from __future__ import annotations

import pytest

from websentinel.http.client import SafeResponse


@pytest.fixture
def response() -> SafeResponse:
    return SafeResponse(
        "https://example.test/",
        200,
        {"content-type": "text/html"},
        (),
        0.01,
        {"version": "TLSv1.3"},
    )
