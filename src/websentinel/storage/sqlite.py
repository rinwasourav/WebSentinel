"""Transactional SQLite assessment persistence with schema versioning."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from websentinel.findings.normalize import redact, redact_tree
from websentinel.models import Assessment

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments(
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    scope TEXT NOT NULL,
    started_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    check_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_check ON findings(check_id);
"""
_CURRENT_SCHEMA = 2


class AssessmentStore:
    """Stores redacted assessment snapshots in SQLite."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ValueError("Database path must not be a symbolic link")
        self.path.touch(mode=0o600, exist_ok=True)
        self._migrate()
        if os.name == "posix":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _migrate(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL)"
                )
                row = connection.execute("SELECT version FROM schema_meta LIMIT 1").fetchone()
                if row is None:
                    for statement in _SCHEMA.split(";"):
                        if statement.strip():
                            connection.execute(statement)
                    connection.execute("INSERT INTO schema_meta(version) VALUES (1)")
                    version = 1
                else:
                    version = int(row[0])
                if version > _CURRENT_SCHEMA:
                    message = (
                        f"Database schema {version} is newer than "
                        f"supported schema {_CURRENT_SCHEMA}"
                    )
                    raise RuntimeError(message)
                if version < 2:
                    connection.execute("""CREATE TABLE assessment_pages(
                        assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                        ordinal INTEGER NOT NULL,
                        url TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        PRIMARY KEY(assessment_id, ordinal)
                    )""")
                    connection.execute("UPDATE schema_meta SET version=2")
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def save(self, assessment: Assessment) -> None:
        """Persist one assessment and all findings atomically."""
        payload: dict[str, Any] = redact_tree(assessment.to_dict())
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "INSERT INTO assessments VALUES (?, ?, ?, ?, ?)",
                (
                    assessment.id,
                    redact(assessment.target),
                    json.dumps(assessment.scope),
                    assessment.started_at,
                    json.dumps(payload),
                ),
            )
            connection.executemany(
                "INSERT INTO findings VALUES (?, ?, ?, ?, ?)",
                [
                    (f["id"], assessment.id, f["check_id"], f["severity"], json.dumps(f))
                    for f in payload["findings"]
                ],
            )
            connection.executemany(
                "INSERT INTO assessment_pages VALUES (?, ?, ?, ?)",
                [
                    (
                        assessment.id,
                        index,
                        redact(page.get("url", "")),
                        json.dumps(redact_tree(page)),
                    )
                    for index, page in enumerate(payload.get("inventory", []))
                ],
            )

    def get(self, assessment_id: str) -> dict[str, Any] | None:
        """Return a stored redacted payload by assessment ID."""
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT payload FROM assessments WHERE id=?", (assessment_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def delete(self, assessment_id: str) -> bool:
        """Delete an assessment and its findings/pages using foreign-key cascades."""
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute("DELETE FROM assessments WHERE id=?", (assessment_id,))
            return cursor.rowcount > 0

    def backup(self, destination: Path) -> None:
        """Create a consistent SQLite backup at a new, non-symlink destination."""
        if destination.resolve() == self.path.resolve() or destination.is_symlink():
            raise ValueError("Backup destination must be a different, non-symbolic-link path")
        if destination.exists():
            raise FileExistsError("Backup destination already exists")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with closing(self._connect()) as source:
            target = sqlite3.connect(destination)
            try:
                source.backup(target)
            finally:
                target.close()
        if os.name == "posix":
            destination.chmod(0o600)
