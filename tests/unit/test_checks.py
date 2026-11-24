from websentinel.checks.baseline import inspect_response
from websentinel.http.client import SafeResponse
from websentinel.models import Severity


def test_missing_baseline_headers_are_reported(response: SafeResponse) -> None:
    findings = inspect_response(response)
    assert {f.check_id for f in findings} >= {"headers.csp", "headers.hsts", "headers.nosniff"}


def test_http_does_not_report_hsts() -> None:
    r = SafeResponse("http://example.test", 200, {}, (), 0, {})
    assert "headers.hsts" not in {f.check_id for f in inspect_response(r)}


def test_cookie_values_are_not_in_evidence() -> None:
    r = SafeResponse("https://example.test", 200, {}, ("session=topsecret; SameSite=None",), 0, {})
    findings = inspect_response(r)
    assert findings
    assert all("topsecret" not in f.evidence for f in findings)
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_hsts_when_present_passes() -> None:
    r = SafeResponse(
        "https://example.test",
        200,
        {"strict-transport-security": "max-age=31536000"},
        (),
        0,
        {"version": "TLSv1.3"},
    )
    assert "headers.hsts" not in {f.check_id for f in inspect_response(r)}


def test_risk_priority_combines_severity_and_confidence() -> None:
    from websentinel.findings.risk import risk_score
    from websentinel.models import Confidence, Finding, Severity

    finding = Finding(
        "x",
        "title",
        "description",
        Severity.HIGH,
        Confidence.MEDIUM,
        "evidence",
        "impact",
        "fix",
        "https://example.test",
    )
    assert risk_score(finding) == 5.6
