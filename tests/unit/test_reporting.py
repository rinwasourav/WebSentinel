from pathlib import Path

from websentinel.models import Assessment, Confidence, Finding, Severity
from websentinel.reporting.render import render_html, write_json, write_pdf


def test_html_escapes_untrusted_finding_text() -> None:
    a = Assessment("https://example.test", ("example.test",))
    a.findings.append(
        Finding(
            "x",
            "<script>alert(1)</script>",
            "<b>bad</b>",
            Severity.LOW,
            Confidence.HIGH,
            "<script>",
            "impact",
            "fix",
            "https://example.test",
        )
    )
    out = render_html(a)
    assert "<script>alert" not in out
    assert "&lt;script&gt;" in out


def test_json_written(tmp_path: Path) -> None:
    a = Assessment("https://example.test", ("example.test",))
    p = tmp_path / "r.json"
    write_json(a, p)
    assert '"findings": []' in p.read_text()


def test_json_redacts_target_queries_and_serializes_priority(tmp_path: Path) -> None:
    a = Assessment("https://example.test/?token=hidden", ("example.test",))
    a.findings.append(
        Finding(
            "x",
            "Title",
            "Description",
            Severity.HIGH,
            Confidence.MEDIUM,
            "Authorization: Bearer hidden",
            "Impact",
            "Fix",
            "https://example.test/?token=hidden",
        )
    )
    path = tmp_path / "safe.json"
    write_json(a, path)
    text = path.read_text()
    assert "hidden" not in text
    assert '"priority": 5.6' in text


def test_pdf_written_when_optional_extra_is_installed(tmp_path: Path) -> None:
    assessment = Assessment("https://example.test", ("example.test",))
    p = tmp_path / "report.pdf"
    write_pdf(assessment, p)
    assert p.read_bytes().startswith(b"%PDF-")
