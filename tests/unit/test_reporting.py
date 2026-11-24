import json
import os
from pathlib import Path

from jsonschema import validate

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
    assert "Executive summary" in out
    assert "Affected URL" in out


def test_json_written(tmp_path: Path) -> None:
    a = Assessment("https://example.test", ("example.test",))
    p = tmp_path / "r.json"
    write_json(a, p)
    assert '"findings": []' in p.read_text()
    if os.name == "posix":
        assert p.stat().st_mode & 0o777 == 0o600


def test_assessment_report_matches_published_schema() -> None:
    schema_path = Path(__file__).parents[2] / "docs" / "finding-schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assessment = Assessment("https://example.test", ("example.test",))
    assessment.findings.append(
        Finding(
            "test.check",
            "Example finding",
            "Explanation",
            Severity.LOW,
            Confidence.MEDIUM,
            "Header was absent",
            "Limited impact",
            "Configure the header",
            "https://example.test/",
        )
    )
    assessment.inventory.append(
        {
            "url": "https://example.test/",
            "depth": 0,
            "discovered_from": None,
            "status": "assessed",
            "checks_run": ["passive-baseline"],
            "checks_failed": [],
            "finding_ids": [assessment.findings[0].id],
            "requests": 1,
        }
    )
    validate(json.loads(json.dumps(assessment.to_dict())), schema)


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
