"""Escaped HTML and JSON report writers."""

from __future__ import annotations

import html
import json
import os
from pathlib import Path

from websentinel.findings.normalize import redact_tree
from websentinel.models import Assessment


def _prepare_output(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("Report path must not be a symbolic link")
    parent_exists = path.parent.exists()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix" and not parent_exists:
        path.parent.chmod(0o700)


def write_json(assessment: Assessment, path: Path) -> None:
    """Write a redacted JSON snapshot."""
    _prepare_output(path)
    path.write_text(
        json.dumps(redact_tree(assessment.to_dict()), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    if os.name == "posix":
        path.chmod(0o600)


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
            + "</pre><p>Affected URL: "
            + html.escape(str(f["url"]))
            + "</p><p>Remediation: "
            + html.escape(f["remediation"])
            + "</p><p>Mapping: "
            + html.escape(", ".join(f.get("owasp", [])))
            + " · CWE: "
            + html.escape(str(f.get("cwe") or "not assigned"))
            + "</p><p>References: "
            + html.escape(", ".join(f.get("references", [])))
            + "</p></article>"
        )
    counts_text = ", ".join(f"{key}={value}" for key, value in counts.items())
    coverage_text = data.get("coverage", {}).get("page_coverage_percent")
    summary = f"{len(data['findings'])} findings. Severity counts: {counts_text}."
    if coverage_text is not None:
        summary += f" Page coverage: {coverage_text}%."
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'><title>WebSentinel Assessment</title>"
        "<h1>WebSentinel Assessment</h1><p>Target: "
        + html.escape(str(data["target"]))
        + "</p><p>Started: "
        + html.escape(str(data["started_at"]))
        + "</p><h2>Executive summary</h2><p>"
        + html.escape(summary)
        + "</p>"
        + "<p>Scope: "
        + html.escape(", ".join(data["scope"]))
        + "</p><p>Checks: "
        + html.escape(", ".join(data["checks_executed"]))
        + "</p><h2>Coverage</h2><p>"
        + html.escape(json.dumps(data.get("coverage", {}), ensure_ascii=False, sort_keys=True))
        + "</p><h2>Configuration</h2><p>"
        + html.escape(json.dumps(data.get("configuration", {}), ensure_ascii=False, sort_keys=True))
        + " · Duration: "
        + html.escape(str(data.get("duration_seconds", 0)))
        + " seconds</p><h2>Site inventory</h2><ul>"
        + "".join(
            "<li>"
            + html.escape(str(page.get("status", "")))
            + " — "
            + html.escape(str(page.get("url", "")))
            + "</li>"
            for page in data.get("inventory", [])
        )
        + "</ul><h2>Limitations</h2><ul>"
        + "".join("<li>" + html.escape(str(item)) + "</li>" for item in data.get("limitations", []))
        + "</ul>"
        + "".join(rows)
        + "</html>"
    )


def write_html(assessment: Assessment, path: Path) -> None:
    """Write a redacted HTML report to disk."""
    _prepare_output(path)
    path.write_text(render_html(assessment), encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)


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
    _prepare_output(path)
    data = redact_tree(assessment.to_dict())
    styles = getSampleStyleSheet()
    counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
    for finding in data["findings"]:
        counts[finding["severity"]] += 1
    summary = f"{len(data['findings'])} findings. " + ", ".join(
        f"{key}={value}" for key, value in counts.items()
    )
    if data.get("coverage", {}).get("page_coverage_percent") is not None:
        summary += f". Page coverage: {data['coverage']['page_coverage_percent']}%."
    story = [
        Paragraph("WebSentinel Assessment", styles["Title"]),
        Paragraph("Executive summary: " + html.escape(summary), styles["Heading2"]),
        Paragraph("Target: " + html.escape(str(data["target"])), styles["BodyText"]),
        Paragraph("Started: " + html.escape(str(data["started_at"])), styles["BodyText"]),
        Paragraph("Scope: " + html.escape(", ".join(data["scope"])), styles["BodyText"]),
        Paragraph("Checks: " + html.escape(", ".join(data["checks_executed"])), styles["BodyText"]),
        Paragraph(
            "Coverage: " + html.escape(json.dumps(data.get("coverage", {}), sort_keys=True)),
            styles["BodyText"],
        ),
        Paragraph(
            "Configuration: "
            + html.escape(json.dumps(data.get("configuration", {}), sort_keys=True)),
            styles["BodyText"],
        ),
        Paragraph(
            "Duration: " + html.escape(str(data.get("duration_seconds", 0))) + " seconds",
            styles["BodyText"],
        ),
        Paragraph("Inventory pages: " + str(len(data.get("inventory", []))), styles["BodyText"]),
        Paragraph(
            "Limitations: " + html.escape("; ".join(data.get("limitations", []))),
            styles["BodyText"],
        ),
        Spacer(1, 0.2 * inch),
    ]
    if data.get("inventory"):
        story.append(Paragraph("Site inventory", styles["Heading1"]))
        story.extend(
            Paragraph(
                html.escape(str(page.get("status", "")))
                + " — "
                + html.escape(str(page.get("url", ""))),
                styles["BodyText"],
            )
            for page in data["inventory"]
        )
        story.append(Spacer(1, 0.2 * inch))
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
                Paragraph("Affected URL: " + html.escape(str(finding["url"])), styles["BodyText"]),
                Paragraph(
                    "Remediation: " + html.escape(str(finding["remediation"])), styles["BodyText"]
                ),
                Paragraph(
                    "OWASP: " + html.escape(", ".join(finding.get("owasp", []))),
                    styles["BodyText"],
                ),
                Paragraph(
                    "CWE: " + html.escape(str(finding.get("cwe") or "not assigned")),
                    styles["BodyText"],
                ),
                Paragraph(
                    "References: " + html.escape(", ".join(finding.get("references", []))),
                    styles["BodyText"],
                ),
                Spacer(1, 0.15 * inch),
            ]
        )
    SimpleDocTemplate(str(path), pagesize=letter).build(story)
    if os.name == "posix":
        path.chmod(0o600)
