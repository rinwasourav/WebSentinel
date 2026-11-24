import sqlite3
from pathlib import Path

import pytest

from websentinel.models import Assessment, Confidence, Finding, Severity
from websentinel.storage.sqlite import AssessmentStore


def test_round_trip_and_sensitive_evidence_redaction(tmp_path: Path) -> None:
    assessment = Assessment("https://example.test", ("example.test",))
    assessment.findings.append(
        Finding(
            "x",
            "Title",
            "Desc",
            Severity.LOW,
            Confidence.HIGH,
            "Authorization: Bearer topsecret",
            "Impact",
            "Fix",
            "https://example.test/",
        )
    )
    store = AssessmentStore(tmp_path / "test.sqlite3")
    store.save(assessment)
    saved = store.get(assessment.id)
    assert saved is not None
    assert "topsecret" not in str(saved)
    assert (tmp_path / "test.sqlite3").stat().st_mode & 0o777 == 0o600


def test_duplicate_assessment_rolls_back(tmp_path: Path) -> None:
    store = AssessmentStore(tmp_path / "test.db")
    a = Assessment("https://example.test", ("example.test",))
    store.save(a)
    with pytest.raises(sqlite3.IntegrityError):
        store.save(a)
    assert store.get(a.id) is not None


def test_migrates_existing_v1_database_and_persists_pages(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE schema_meta(version INTEGER NOT NULL);
        INSERT INTO schema_meta VALUES (1);
        CREATE TABLE assessments(id TEXT PRIMARY KEY, target TEXT NOT NULL, scope TEXT NOT NULL,
            started_at TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE findings(id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL
            REFERENCES assessments(id) ON DELETE CASCADE, check_id TEXT NOT NULL,
            severity TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE INDEX idx_findings_assessment ON findings(assessment_id);
        CREATE INDEX idx_findings_severity ON findings(severity);
        CREATE INDEX idx_findings_check ON findings(check_id);
    """)
    connection.close()
    store = AssessmentStore(path)
    assessment = Assessment("https://example.test", ("example.test",))
    assessment.inventory.append({"url": "https://example.test/a", "status": "assessed"})
    store.save(assessment)
    with sqlite3.connect(path) as migrated:
        assert migrated.execute("SELECT version FROM schema_meta").fetchone() == (2,)
        assert migrated.execute("SELECT COUNT(*) FROM assessment_pages").fetchone() == (1,)


def test_assessment_delete_cascades_and_backup_is_consistent(tmp_path: Path) -> None:
    store = AssessmentStore(tmp_path / "test.db")
    assessment = Assessment("https://example.test", ("example.test",))
    store.save(assessment)
    backup = tmp_path / "backup.db"
    store.backup(backup)
    assert AssessmentStore(backup).get(assessment.id) is not None
    assert store.delete(assessment.id)
    assert store.get(assessment.id) is None
    assert not store.delete(assessment.id)


def test_rejects_database_from_newer_schema(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE schema_meta(version INTEGER NOT NULL)")
        connection.execute("INSERT INTO schema_meta VALUES (99)")
    with pytest.raises(RuntimeError, match="newer than supported"):
        AssessmentStore(path)
