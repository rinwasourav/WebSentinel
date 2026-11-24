"""Command-line interface for authorized passive assessments."""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path

import httpx
from platformdirs import user_data_path

from websentinel import __version__
from websentinel.checks.baseline import inspect_response
from websentinel.findings.normalize import redact
from websentinel.http.client import PolicyHTTPClient
from websentinel.inventory.crawler import Crawler, CrawlPolicy
from websentinel.models import Assessment
from websentinel.reporting.render import write_html, write_json, write_pdf
from websentinel.scope.guard import ScopeError, ScopePolicy
from websentinel.storage.sqlite import AssessmentStore


def main(argv: list[str] | None = None) -> int:
    """Run the WebSentinel command line and return a process exit code."""
    parser = argparse.ArgumentParser(
        prog="websentinel", description="Authorized passive web security baseline scanner"
    )
    parser.add_argument("--version", action="version", version=f"WebSentinel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    assess = sub.add_parser("assess", help="Run passive checks against one authorized URL")
    assess.add_argument("--target", required=True)
    assess.add_argument(
        "--scope", action="append", required=True, help="Exact allowed hostname; repeatable"
    )
    assess.add_argument(
        "--authorized", action="store_true", help="Acknowledge explicit authorization"
    )
    assess.add_argument(
        "--local-lab",
        action="store_true",
        help="Allow loopback targets for an explicitly authorized local lab",
    )
    assess.add_argument(
        "--lab-cidr",
        action="append",
        default=[],
        metavar="CIDR",
        help="Additional approved RFC1918/IPv6 ULA network; requires --local-lab",
    )
    assess.add_argument("--max-requests", type=int, default=10)
    assess.add_argument("--rate", type=float, default=1.0)
    assess.add_argument("--timeout", type=float, default=5.0)
    assess.add_argument("--output", type=Path, default=Path("reports"))
    assess.add_argument("--pdf", action="store_true", help="Also write an optional PDF report")
    assess.add_argument(
        "--crawl", action="store_true", help="Discover same-origin pages within configured limits"
    )
    assess.add_argument("--max-pages", type=int, default=50)
    assess.add_argument("--max-depth", type=int, default=3)
    assess.add_argument(
        "--database",
        type=Path,
        default=user_data_path("websentinel", appauthor=False) / "assessments.sqlite3",
    )
    history = sub.add_parser("history", help="List stored assessment IDs")
    history.add_argument(
        "--database",
        type=Path,
        default=user_data_path("websentinel", appauthor=False) / "assessments.sqlite3",
    )
    checks = sub.add_parser("checks", help="Inspect available passive security checks")
    checks.add_argument("action", choices=("list",), help="List registered checks")
    args = parser.parse_args(argv)
    if args.command == "assess":
        try:
            policy = ScopePolicy(
                frozenset(args.scope),
                args.authorized,
                args.local_lab,
                args.max_requests,
                args.rate,
                args.timeout,
                lab_cidrs=frozenset(args.lab_cidr),
            )
            assessment = Assessment(args.target, tuple(sorted(policy.allowed_hosts)))
            run_started = time.monotonic()
            assessment.configuration = {
                "local_lab": policy.local_lab,
                "lab_cidrs": sorted(policy.lab_cidrs),
                "max_requests": policy.max_requests,
                "requests_per_second": policy.requests_per_second,
                "timeout_seconds": policy.timeout,
                "crawl_enabled": args.crawl,
                "max_pages": args.max_pages if args.crawl else 1,
                "max_depth": args.max_depth if args.crawl else 0,
                "max_html_bytes": 1_048_576 if args.crawl else 0,
                "max_links_per_page": 250 if args.crawl else 0,
            }
            client = PolicyHTTPClient(policy)
            final_status: int | None = None
            if args.crawl:
                crawl_result = Crawler(
                    client, CrawlPolicy(max_depth=args.max_depth, max_pages=args.max_pages)
                ).crawl(args.target)
                assessment.target = args.target
                assessment.inventory = [page.to_dict() for page in crawl_result.pages]
                assessment.coverage = crawl_result.coverage()
                assessment.findings.extend(crawl_result.findings)
                final_status = crawl_result.pages[0].response_status if crawl_result.pages else None
                assessment.checks_executed.append("passive-baseline")
                if crawl_result.cancelled:
                    assessment.limitations.append("Crawl cancelled before completing the queue.")
                if crawl_result.overflow_count:
                    assessment.limitations.append(
                        "Page limit reached; some discovered pages were skipped."
                    )
            else:
                response = client.get(args.target)
                final_status = response.status_code
                assessment.target = response.url
                assessment.checks_executed.append("passive-baseline")
                assessment.findings.extend(inspect_response(response))
                assessment.inventory = [
                    {
                        "url": response.url,
                        "depth": 0,
                        "discovered_from": None,
                        "status": "assessed",
                        "response_status": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                        "checks_run": ["passive-baseline"],
                        "checks_failed": [],
                        "finding_ids": [finding.id for finding in assessment.findings],
                        "requests": client.request_count,
                        "reason": "",
                    }
                ]
                assessment.coverage = {
                    "pages_discovered": 1,
                    "pages_assessed": 1,
                    "pages_partial": 0,
                    "pages_inaccessible": 0,
                    "pages_skipped": 0,
                    "pages_excluded_external_or_unsafe": 0,
                    "page_coverage_percent": 100.0,
                    "check_runs": {"passive-baseline": 1},
                    "check_failures": {},
                    "checks_skipped": {},
                    "requests_sent": client.request_count,
                    "cancelled": False,
                    "excluded_sample": [],
                }
            assessment.duration_seconds = round(time.monotonic() - run_started, 3)
            AssessmentStore(args.database).save(assessment)
            write_json(assessment, args.output / f"{assessment.id}.json")
            write_html(assessment, args.output / f"{assessment.id}.html")
            if args.pdf:
                write_pdf(assessment, args.output / f"{assessment.id}.pdf")
            print(
                json.dumps(
                    {
                        "assessment_id": assessment.id,
                        "findings": len(assessment.findings),
                        "status": final_status,
                        "reports": str(args.output),
                    }
                )
            )
            return 0
        except (
            ScopeError,
            RuntimeError,
            ValueError,
            OSError,
            sqlite3.Error,
            httpx.HTTPError,
        ) as exc:
            logging.error("Assessment stopped: %s", redact(str(exc)))
            return 2
    if args.command == "history":
        if not args.database.exists():
            print("[]")
            return 0
        with closing(sqlite3.connect(args.database)) as connection, connection:
            rows = connection.execute(
                "SELECT id, target, started_at FROM assessments ORDER BY started_at DESC"
            ).fetchall()
        print(json.dumps([{"id": row[0], "target": row[1], "started_at": row[2]} for row in rows]))
        return 0
    if args.command == "checks":
        from websentinel.checks.registry import builtins

        print(
            json.dumps(
                [
                    {"id": item.id, "name": item.name, "capability": item.capability}
                    for item in builtins()
                ]
            )
        )
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
