"""Command-line interface for authorized passive assessments."""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import httpx
from platformdirs import user_data_path

from websentinel import __version__
from websentinel.checks.baseline import inspect_response
from websentinel.findings.normalize import redact
from websentinel.http.client import PolicyHTTPClient
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
            response = PolicyHTTPClient(policy).get(args.target)
            assessment.target = response.url
            assessment.checks_executed.append("passive-baseline")
            assessment.findings.extend(inspect_response(response))
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
                        "status": response.status_code,
                        "reports": str(args.output),
                    }
                )
            )
            return 0
        except (ScopeError, RuntimeError, OSError, sqlite3.Error, httpx.HTTPError) as exc:
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
    return 2


if __name__ == "__main__":
    sys.exit(main())
