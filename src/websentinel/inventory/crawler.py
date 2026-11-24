"""Sequential, bounded crawler built on the policy-enforced HTTP client."""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from websentinel.checks.baseline import inspect_response
from websentinel.http.client import PolicyHTTPClient, SafeResponse
from websentinel.inventory.extractor import extract_links
from websentinel.inventory.models import CrawlProgress, CrawlResult, PageRecord, PageStatus
from websentinel.inventory.normalizer import normalize_link, origin
from websentinel.models import Finding
from websentinel.scope.guard import ScopeError


@dataclass(frozen=True, slots=True)
class CrawlPolicy:
    """Resource limits for a crawl. Requests are always made sequentially."""

    max_depth: int = 3
    max_pages: int = 50
    max_body_bytes: int = 1_048_576
    max_links_per_page: int = 250

    def __post_init__(self) -> None:
        if not 0 <= self.max_depth <= 20:
            raise ValueError("max_depth must be between 0 and 20")
        if not 1 <= self.max_pages <= 500:
            raise ValueError("max_pages must be between 1 and 500")
        if not 1 <= self.max_body_bytes <= 8_388_608:
            raise ValueError("max_body_bytes must be between 1 byte and 8 MiB")
        if not 1 <= self.max_links_per_page <= 5000:
            raise ValueError("max_links_per_page must be between 1 and 5000")


class Crawler:
    """Discover and inspect same-origin HTML pages with strict resource bounds."""

    def __init__(
        self,
        client: PolicyHTTPClient,
        policy: CrawlPolicy | None = None,
        *,
        check: Callable[[SafeResponse], list[Finding]] = inspect_response,
    ) -> None:
        self.client = client
        self.policy = policy or CrawlPolicy()
        self.check = check

    def crawl(
        self,
        start_url: str,
        *,
        cancel: threading.Event | None = None,
        progress: Callable[[CrawlProgress], None] | None = None,
    ) -> CrawlResult:
        expected = origin(start_url)
        if expected is None:
            raise ValueError("crawl start URL must be an HTTP(S) URL without credentials")
        start, reason = normalize_link(start_url, start_url, expected)
        if start is None:
            raise ValueError(f"crawl start URL rejected: {reason}")
        queue: deque[tuple[str, int, str | None]] = deque([(start, 0, None)])
        seen = {start}
        pages: list[PageRecord] = []
        findings: list[Finding] = []
        excluded_count = 0
        excluded_samples: list[dict[str, str]] = []
        overflow_count = 0
        previous_requests = self.client.request_count
        cancelled = False
        while queue and len(pages) < self.policy.max_pages:
            if cancel is not None and cancel.is_set():
                cancelled = True
                break
            if self.client.requests_remaining <= 0:
                break
            url, depth, parent = queue.popleft()
            request_before = self.client.request_count
            try:
                response = self.client.get(
                    url, max_body_bytes=self.policy.max_body_bytes, same_origin=True
                )
            except ScopeError:
                if not pages and self.client.request_count == request_before:
                    raise
                pages.append(
                    PageRecord(
                        url,
                        depth,
                        parent,
                        PageStatus.INACCESSIBLE,
                        requests=self.client.request_count - request_before,
                        reason="ScopeError",
                    )
                )
            except (httpx.HTTPError, OSError, RuntimeError) as exc:
                pages.append(
                    PageRecord(
                        url,
                        depth,
                        parent,
                        PageStatus.INACCESSIBLE,
                        requests=self.client.request_count - request_before,
                        reason=type(exc).__name__,
                    )
                )
            else:
                content_type = response.headers.get("content-type", "")
                is_html = content_type.lower().startswith(("text/html", "application/xhtml+xml"))
                response_origin = origin(response.url)
                if response_origin != expected:
                    status = PageStatus.SKIPPED
                    page_findings: list[Finding] = []
                    reason_text = "redirect landed outside crawler same-origin policy"
                elif not 200 <= response.status_code < 400:
                    status = PageStatus.INACCESSIBLE
                    page_findings = []
                    reason_text = f"HTTP {response.status_code}"
                else:
                    page_findings = self.check(response)
                    findings.extend(page_findings)
                    status = PageStatus.PARTIAL if response.body_truncated else PageStatus.ASSESSED
                    reason_text = "response body exceeded limit" if response.body_truncated else ""
                record = PageRecord(
                    response.url,
                    depth,
                    parent,
                    status,
                    response.status_code,
                    content_type,
                    ["passive-baseline"]
                    if response_origin == expected and 200 <= response.status_code < 400
                    else [],
                    [],
                    [finding.id for finding in page_findings],
                    self.client.request_count - request_before,
                    reason_text,
                )
                if (
                    response_origin == expected
                    and is_html
                    and response.body
                    and not response.body_truncated
                    and depth < self.policy.max_depth
                ):
                    document = response.body.decode("utf-8", errors="replace")
                    links, links_truncated = extract_links(
                        document, maximum=self.policy.max_links_per_page
                    )
                    if links_truncated:
                        record.status = PageStatus.PARTIAL
                        record.reason = "link extraction limit reached"
                    for href in links:
                        normalized, rejection = normalize_link(response.url, href, expected)
                        if normalized is None:
                            excluded_count += 1
                            if len(excluded_samples) < 20:
                                excluded_samples.append({"reason": rejection or "rejected"})
                        elif normalized not in seen:
                            seen.add(normalized)
                            if len(seen) > self.policy.max_pages:
                                overflow_count += 1
                            else:
                                queue.append((normalized, depth + 1, response.url))
                pages.append(record)
            if progress is not None:
                progress(
                    CrawlProgress(
                        len(seen),
                        len(pages),
                        sum(
                            page.status in {PageStatus.ASSESSED, PageStatus.PARTIAL}
                            for page in pages
                        ),
                        self.client.request_count - previous_requests,
                        len(queue),
                    )
                )
        # Pages beyond max_depth are intentionally represented as skipped when discovered.
        if queue:
            overflow_count += len(queue)
        return CrawlResult(
            pages,
            findings,
            excluded_count,
            excluded_samples,
            overflow_count,
            self.client.request_count - previous_requests,
            cancelled,
        )
