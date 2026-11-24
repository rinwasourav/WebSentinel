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
