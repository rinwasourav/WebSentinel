"""Risk score mapping kept separate from detection logic."""

from websentinel.models import Confidence, Finding, Severity

_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}
_CONFIDENCE_WEIGHT = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.4,
}


def risk_score(finding: Finding) -> float:
    """Return the documented severity-confidence score on a 0–10 scale."""
    return round(_SEVERITY_WEIGHT[finding.severity] * _CONFIDENCE_WEIGHT[finding.confidence], 1)
