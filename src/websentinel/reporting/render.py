"""Escaped HTML and JSON report writers."""

from __future__ import annotations

import html
import json
from pathlib import Path

from websentinel.findings.normalize import redact_tree
from websentinel.models import Assessment


def write_json(assessment: Assessment, path: Path) -> None:
    """Write a redacted JSON snapshot."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(redact_tree(assessment.to_dict()), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def render_html(assessment: Assessment) -> str:
    """Render a redacted HTML report with escaped untrusted values."""
    data = redact_tree(assessment.to_dict())
    rows = []
    counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
    for f in data["findings"]:
        counts[f["severity"]] += 1
        rows.append(
            "<article><h2>"
            + html.escape(f["title"])
            + "</h2><p><b>"
            + html.escape(f["severity"])
            + "</b> · "
            + html.escape(f["confidence"])
            + " · Priority "
            + html.escape(str(f["priority"]))
            + "</p><p>"
            + html.escape(f["description"])
            + "</p><pre>"
            + html.escape(f["evidence"])
            + "</pre><p>Remediation: "
            + html.escape(f["remediation"])
            + "</p></article>"
        )
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'><title>WebSentinel Assessment</title>"
        "<h1>WebSentinel Assessment</h1><p>Target: "
        + html.escape(str(data["target"]))
        + "</p><p>Started: "
        + html.escape(str(data["started_at"]))
        + "</p>"
        + "<p>Scope: "
        + html.escape(", ".join(data["scope"]))
        + "</p><p>Checks: "
        + html.escape(", ".join(data["checks_executed"]))
        + "</p><p>Severity counts: "
        + html.escape(", ".join(f"{key}={value}" for key, value in counts.items()))
        + "</p>"
        + "".join(rows)
        + "</html>"
    )


def write_html(assessment: Assessment, path: Path) -> None:
    """Write a redacted HTML report to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(assessment), encoding="utf-8")


def write_pdf(assessment: Assessment, path: Path) -> None:
    """Write a PDF report using the optional reportlab dependency."""
    try:
        from reportlab.lib.pagesizes import letter  # type: ignore[import-untyped]
        from reportlab.lib.styles import getSampleStyleSheet  # type: ignore[import-untyped]
        from reportlab.lib.units import inch  # type: ignore[import-untyped]
        from reportlab.platypus import (  # type: ignore[import-untyped]
            Paragraph,
            SimpleDocTemplate,
            Spacer,
        )
    except ImportError as exc:
        raise RuntimeError("PDF output requires the 'pdf' extra: uv sync --extra pdf") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    data = redact_tree(assessment.to_dict())
    styles = getSampleStyleSheet()
    story = [
        Paragraph("WebSentinel Assessment", styles["Title"]),
        Paragraph("Target: " + html.escape(str(data["target"])), styles["BodyText"]),
        Paragraph("Started: " + html.escape(str(data["started_at"])), styles["BodyText"]),
        Paragraph("Scope: " + html.escape(", ".join(data["scope"])), styles["BodyText"]),
        Paragraph("Checks: " + html.escape(", ".join(data["checks_executed"])), styles["BodyText"]),
        Spacer(1, 0.2 * inch),
    ]
    for finding in data["findings"]:
        story.extend(
            [
                Paragraph(html.escape(str(finding["title"])), styles["Heading2"]),
                Paragraph(
                    html.escape(str(finding["severity"]))
                    + " · "
                    + html.escape(str(finding["confidence"]))
                    + " · Priority "
                    + html.escape(str(finding["priority"])),
                    styles["BodyText"],
                ),
                Paragraph(html.escape(str(finding["description"])), styles["BodyText"]),
                Paragraph("Evidence: " + html.escape(str(finding["evidence"])), styles["Code"]),
                Paragraph(
                    "Remediation: " + html.escape(str(finding["remediation"])), styles["BodyText"]
                ),
                Spacer(1, 0.15 * inch),
            ]
        )
    SimpleDocTemplate(str(path), pagesize=letter).build(story)
