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
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);
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


class AssessmentStore:
    """Stores redacted assessment snapshots in SQLite."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ValueError("Database path must not be a symbolic link")
        self.path.touch(mode=0o600, exist_ok=True)
        with closing(self._connect()) as connection, connection:
            connection.executescript(_SCHEMA)
            if connection.execute("SELECT COUNT(*) FROM schema_meta").fetchone()[0] == 0:
                connection.execute("INSERT INTO schema_meta(version) VALUES (1)")
        if os.name == "posix":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

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

    def get(self, assessment_id: str) -> dict[str, Any] | None:
        """Return a stored redacted payload by assessment ID."""
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT payload FROM assessments WHERE id=?", (assessment_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None
