"""Bounded page inventory records and assessment coverage summaries."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class PageStatus(StrEnum):
    """Terminal outcome for a discovered page."""

    ASSESSED = "assessed"
    PARTIAL = "partial"
    INACCESSIBLE = "inaccessible"
    SKIPPED = "skipped"


@dataclass(slots=True)
class PageRecord:
    """Sanitized result and check execution history for one discovered page."""

    url: str
    depth: int
    discovered_from: str | None
    status: PageStatus
    response_status: int | None = None
    content_type: str = ""
    checks_run: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    requests: int = 0
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the page record for reports and database persistence."""
        return asdict(self)


@dataclass(slots=True)
class CrawlProgress:
    """Snapshot supplied to optional progress callbacks."""

    pages_discovered: int
    pages_processed: int
    pages_assessed: int
    requests_sent: int
    pending_pages: int


@dataclass(slots=True)
class CrawlResult:
    """Complete bounded crawl inventory and check results."""

    pages: list[PageRecord]
    findings: list[Any]
    excluded_count: int
    excluded_samples: list[dict[str, str]]
    overflow_count: int
    requests_sent: int
    cancelled: bool = False

    def coverage(self) -> dict[str, Any]:
        """Return page and check execution coverage without treating gaps as passes."""
        counts = {status.value: 0 for status in PageStatus}
        check_runs: dict[str, int] = {}
        check_failures: dict[str, int] = {}
        check_skips: dict[str, int] = {}
        for page in self.pages:
            counts[page.status.value] += 1
            for check_id in page.checks_run:
                check_runs[check_id] = check_runs.get(check_id, 0) + 1
            for check_id in page.checks_failed:
                check_failures[check_id] = check_failures.get(check_id, 0) + 1
            if page.status in {PageStatus.INACCESSIBLE, PageStatus.SKIPPED}:
                for check_id in {"passive-baseline"}:
                    check_skips[check_id] = check_skips.get(check_id, 0) + 1
        if self.overflow_count:
            check_skips["passive-baseline"] = (
                check_skips.get("passive-baseline", 0) + self.overflow_count
            )
        pages_discovered = len(self.pages) + self.overflow_count
        pages_assessed = counts[PageStatus.ASSESSED.value] + counts[PageStatus.PARTIAL.value]
        return {
            "pages_discovered": pages_discovered,
            "pages_assessed": pages_assessed,
            "pages_partial": counts[PageStatus.PARTIAL.value],
            "pages_inaccessible": counts[PageStatus.INACCESSIBLE.value],
            "pages_skipped": counts[PageStatus.SKIPPED.value] + self.overflow_count,
            "pages_excluded_external_or_unsafe": self.excluded_count,
            "page_coverage_percent": round(100 * pages_assessed / pages_discovered, 1)
            if pages_discovered
            else 0.0,
            "check_runs": check_runs,
            "check_failures": check_failures,
            "checks_skipped": check_skips,
            "requests_sent": self.requests_sent,
            "cancelled": self.cancelled,
            "excluded_sample": self.excluded_samples,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize inventory and its coverage summary."""
        return {"pages": [page.to_dict() for page in self.pages], "coverage": self.coverage()}
