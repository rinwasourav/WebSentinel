from __future__ import annotations

import threading

import pytest

from websentinel.http.client import SafeResponse
from websentinel.inventory.crawler import Crawler, CrawlPolicy
from websentinel.inventory.extractor import extract_links
from websentinel.inventory.models import PageStatus
from websentinel.inventory.normalizer import normalize_link, origin


class StubClient:
    def __init__(self, responses: dict[str, SafeResponse], max_requests: int = 100) -> None:
        self.responses = responses
        self.request_count = 0
        self.max_requests = max_requests

    @property
    def requests_remaining(self) -> int:
        return self.max_requests - self.request_count

    def get(self, url: str, *, max_body_bytes: int = 0, same_origin: bool = False) -> SafeResponse:
        self.request_count += 1
        return self.responses[url]


def response(url: str, body: str) -> SafeResponse:
    return SafeResponse(url, 200, {"content-type": "text/html"}, (), 0.01, {}, body.encode())


def test_extracts_only_bounded_anchor_links() -> None:
    links, truncated = extract_links(
        '<a href="/one">1</a><form action="/submit"></form><area href="/two">', maximum=1
    )
    assert links == ["/one"]
    assert truncated


def test_normalizer_removes_fragments_and_tracking_and_rejects_external() -> None:
    expected = origin("https://example.test/")
    assert expected is not None
    normalized, reason = normalize_link(
        "https://example.test/a", "../b?utm_source=x&z=2#fragment", expected
    )
    assert normalized == "https://example.test/b?z=2"
    assert reason is None
    assert normalize_link("https://example.test", "https://elsewhere.test/", expected)[0] is None
    assert normalize_link("https://example.test", "/%6cogout", expected)[0] is None
    assert normalize_link("https://example.test", "/", expected)[0] == "https://example.test/"
    assert normalize_link("https://example.test", "/?action=delete", expected)[0] is None


def test_crawler_discovers_same_origin_and_reports_exclusions() -> None:
    start = "https://example.test/"
    child = "https://example.test/child"
    client = StubClient(
        {
            start: response(
                start, '<a href="/child#top">child</a><a href="https://evil.test/">x</a>'
            ),
            child: response(child, "<p>done</p>"),
        }
    )
    result = Crawler(client).crawl(start)
    assert [page.url for page in result.pages] == [start, child]
    assert result.coverage()["pages_assessed"] == 2
    assert result.coverage()["pages_excluded_external_or_unsafe"] == 1
    assert client.request_count == 2


def test_excluded_sensitive_links_are_not_retained_in_inventory() -> None:
    start = "https://example.test/"
    client = StubClient(
        {start: response(start, '<a href="/account?sessionid=top-secret">account</a>')}
    )
    result = Crawler(client).crawl(start)
    assert result.excluded_count == 1
    assert "top-secret" not in str(result.to_dict())


def test_crawler_respects_page_and_depth_limits() -> None:
    start = "https://example.test/"
    result = Crawler(
        StubClient({start: response(start, '<a href="/one">1</a><a href="/two">2</a>')}),
        CrawlPolicy(max_pages=1),
    ).crawl(start)
    assert len(result.pages) == 1
    assert result.overflow_count == 2
    assert result.coverage()["pages_skipped"] == 2


def test_crawler_stops_cleanly_when_http_request_budget_is_exhausted() -> None:
    start = "https://example.test/"
    client = StubClient({start: response(start, '<a href="/child">child</a>')}, max_requests=1)
    result = Crawler(client).crawl(start)
    assert len(result.pages) == 1
    assert result.pages[0].status is PageStatus.ASSESSED
    assert result.coverage()["pages_skipped"] == 1


def test_crawler_records_truncated_page_as_partial() -> None:
    start = "https://example.test/"
    truncated = SafeResponse(start, 200, {"content-type": "text/html"}, (), 0.01, {}, b"", True)
    result = Crawler(StubClient({start: truncated})).crawl(start)
    assert result.pages[0].status is PageStatus.PARTIAL
    assert result.coverage()["page_coverage_percent"] == 100


def test_crawler_honors_cancellation_before_request() -> None:
    event = threading.Event()
    event.set()
    result = Crawler(StubClient({})).crawl("https://example.test/", cancel=event)
    assert result.cancelled
    assert result.pages == []
    assert result.coverage()["pages_discovered"] == 1
    assert result.coverage()["pages_skipped"] == 1


def test_policy_rejects_unbounded_limits() -> None:
    with pytest.raises(ValueError):
        CrawlPolicy(max_pages=501)
