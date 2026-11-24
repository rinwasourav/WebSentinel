"""Shared assessment and finding data structures."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Finding severity classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    """Confidence in the finding evidence."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Finding:
    """Normalized, redaction-safe observation with remediation and mapping metadata."""

    check_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    evidence: str
    impact: str
    remediation: str
    url: str
    owasp: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    detected_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    cwe: str | None = None
    kind: str = "finding"

    def __post_init__(self) -> None:
        if not self.id:
            import hashlib

            digest = hashlib.sha256(
                f"{self.check_id}|{self.url}|{self.title}".encode()
            ).hexdigest()[:16]
            object.__setattr__(self, "id", digest)
        if self.severity is Severity.INFO and self.kind == "finding":
            object.__setattr__(self, "kind", "observation")


@dataclass(slots=True)
class Assessment:
    """Single bounded assessment run and its normalized findings."""

    target: str
    scope: tuple[str, ...]
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    tool_version: str = "0.1.0"
    checks_executed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    id: str = ""
    inventory: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    configuration: dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0

    def __post_init__(self) -> None:
        if not self.id:
            self.id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")

    def to_dict(self) -> dict[str, Any]:
        from websentinel.findings.risk import risk_score

        findings = [
            {**asdict(finding), "priority": risk_score(finding)} for finding in self.findings
        ]
        return {**asdict(self), "findings": findings}
