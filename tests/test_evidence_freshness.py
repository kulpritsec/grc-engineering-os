"""Ground-truth cases for the CVP evidence freshness gate.

Stale, undated or contradictory evidence must never support a verified or
failed conclusion. Declared collection times and Vault ingestion times are
host/caller claims, so the gate only ever makes conclusions more conservative.
"""

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from grcctl.assurance.catalog import CatalogError, LocalAssuranceCatalog
from grcctl.assurance.engine import (
    AssessmentInputError,
    evaluate_assessment,
    evaluate_file,
)
from grcctl.assurance.models import AssessmentInput, ControlVerificationProcedure
from grcctl.cli import app
from grcctl.doctor import hash_payload
from grcctl.evidence import verify_evidence_file
from grcctl.vault import LocalEvidenceVault, VaultArtifact

DAY = 86_400
T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _procedure(max_age: int | None = DAY, kinds: list[str] | None = None) -> dict:
    procedure: dict[str, Any] = {
        "id": "CVP-FRESH-001",
        "title": "Synthetic freshness fixture",
        "assertion": "Synthetic test identity is denied access",
        "scope": "synthetic sandbox",
        "required_check_ids": ["deny"],
        "required_evidence_kinds": kinds or ["test-result"],
    }
    if max_age is not None:
        procedure["max_evidence_age_seconds"] = max_age
    return procedure


def local_input(
    tmp_path: Path,
    *,
    collected_at: datetime | None = T0,
    max_age: int | None = DAY,
    outcome: str = "pass",
) -> AssessmentInput:
    source = tmp_path / "observation.txt"
    source.write_text("synthetic control observation", encoding="utf-8")
    evidence: dict[str, Any] = {
        "id": "EV-1",
        "kind": "test-result",
        "relative_path": "observation.txt",
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    if collected_at is not None:
        evidence["collected_at"] = _iso(collected_at)
    return AssessmentInput.model_validate(
        {
            "assessment_id": "ASMT-FRESH-001",
            "procedure": _procedure(max_age),
            "observations": [
                {"check_id": "deny", "outcome": outcome, "evidence_ids": ["EV-1"]}
            ],
            "evidence": [evidence],
            "scope_confirmed": True,
            "coverage_complete": True,
        }
    )


def vault_input(
    tmp_path: Path, *, collected_at: datetime | None, outcome: str = "pass"
) -> tuple[Path, VaultArtifact, AssessmentInput]:
    root = tmp_path / "vault"
    source = tmp_path / "result.txt"
    source.write_text("synthetic denied-access result", encoding="utf-8")
    stored = LocalEvidenceVault(root).ingest(source, kind="test-result")
    evidence: dict[str, Any] = {
        "id": "EV-1",
        "kind": "test-result",
        "vault_artifact_id": stored.artifact_id,
        "sha256": stored.sha256,
    }
    if collected_at is not None:
        evidence["collected_at"] = _iso(collected_at)
    data = {
        "assessment_id": "ASMT-FRESH-VAULT",
        "procedure": _procedure(),
        "observations": [
            {"check_id": "deny", "outcome": outcome, "evidence_ids": ["EV-1"]}
        ],
        "evidence": [evidence],
        "scope_confirmed": True,
        "coverage_complete": True,
    }
    return root, stored, AssessmentInput.model_validate(data)


def ingested(stored: VaultArtifact) -> datetime:
    return datetime.fromisoformat(stored.ingested_at)


# Positive cases


def test_fresh_local_evidence_can_verify(tmp_path: Path) -> None:
    report = evaluate_assessment(
        local_input(tmp_path), tmp_path, at=T0 + timedelta(hours=1)
    )
    assert report.verdict == "verified"
    assert report.freshness_checks == {"EV-1": "fresh"}
    assert report.evaluated_at == T0 + timedelta(hours=1)
    assert any("not trusted time" in item for item in report.limitations)


def test_age_boundary_is_inclusive(tmp_path: Path) -> None:
    case = local_input(tmp_path)
    at_limit = evaluate_assessment(case, tmp_path, at=T0 + timedelta(seconds=DAY))
    assert at_limit.freshness_checks == {"EV-1": "fresh"}
    assert at_limit.verdict == "verified"
    past = evaluate_assessment(case, tmp_path, at=T0 + timedelta(seconds=DAY + 1))
    assert past.freshness_checks == {"EV-1": "stale"}
    assert past.verdict == "inconclusive"


def test_fresh_vault_evidence_can_verify(tmp_path: Path) -> None:
    probe = datetime.now(UTC)
    root, stored, case = vault_input(tmp_path, collected_at=probe)
    collected = ingested(stored) - timedelta(minutes=5)
    case.evidence[0].collected_at = collected
    report = evaluate_assessment(
        case, tmp_path, root, at=ingested(stored) + timedelta(minutes=1)
    )
    assert report.freshness_checks == {"EV-1": "fresh"}
    assert report.verdict == "verified"


def test_fresh_evidenced_failure_is_failed(tmp_path: Path) -> None:
    report = evaluate_assessment(
        local_input(tmp_path, outcome="fail"), tmp_path, at=T0 + timedelta(hours=1)
    )
    assert report.verdict == "failed"


# Missing policy and missing evidence time


def test_missing_policy_blocks_verified_and_failed(tmp_path: Path) -> None:
    for outcome in ("pass", "fail"):
        report = evaluate_assessment(
            local_input(tmp_path, max_age=None, outcome=outcome),
            tmp_path,
            at=T0 + timedelta(hours=1),
        )
        assert report.verdict == "inconclusive"
        assert report.freshness_checks == {"EV-1": "no_policy"}
        assert any("freshness policy" in reason for reason in report.reasons)


def test_undated_local_evidence_is_inconclusive(tmp_path: Path) -> None:
    report = evaluate_assessment(
        local_input(tmp_path, collected_at=None), tmp_path, at=T0
    )
    assert report.freshness_checks == {"EV-1": "unknown_collection_time"}
    assert report.verdict == "inconclusive"
    assert "Required evidence kind test-result is missing." in report.reasons


def test_undated_recent_vault_evidence_is_inconclusive(tmp_path: Path) -> None:
    root, stored, case = vault_input(tmp_path, collected_at=None)
    report = evaluate_assessment(
        case, tmp_path, root, at=ingested(stored) + timedelta(minutes=1)
    )
    assert report.freshness_checks == {"EV-1": "unknown_collection_time"}
    assert report.verdict == "inconclusive"


# Stale evidence


def test_stale_pass_and_stale_fail_are_inconclusive(tmp_path: Path) -> None:
    late = T0 + timedelta(days=3)
    for outcome in ("pass", "fail"):
        report = evaluate_assessment(
            local_input(tmp_path, outcome=outcome), tmp_path, at=late
        )
        assert report.freshness_checks == {"EV-1": "stale"}
        assert report.verdict == "inconclusive"
        assert any("EV-1: stale" in reason for reason in report.reasons)


def test_old_ingestion_proves_staleness_despite_fresh_claim(tmp_path: Path) -> None:
    probe = datetime.now(UTC)
    root, stored, case = vault_input(tmp_path, collected_at=probe)
    late = ingested(stored) + timedelta(days=2)
    # A caller claims collection one minute ago, after the bytes were ingested.
    case.evidence[0].collected_at = late - timedelta(minutes=1)
    report = evaluate_assessment(case, tmp_path, root, at=late)
    assert report.freshness_checks == {"EV-1": "collected_after_ingestion"}
    assert report.verdict == "inconclusive"
    # Without any declared time, the old ingestion alone is decisive.
    case.evidence[0].collected_at = None
    undated = evaluate_assessment(case, tmp_path, root, at=late)
    assert undated.freshness_checks == {"EV-1": "stale"}
    assert undated.verdict == "inconclusive"


def test_one_stale_kind_blocks_verified(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh.txt"
    fresh.write_text("fresh synthetic result", encoding="utf-8")
    old = tmp_path / "old.txt"
    old.write_text("old synthetic configuration", encoding="utf-8")
    case = AssessmentInput.model_validate(
        {
            "assessment_id": "ASMT-MIXED",
            "procedure": {
                **_procedure(kinds=["test-result", "configuration"]),
                "required_check_ids": ["deny", "config"],
            },
            "observations": [
                {"check_id": "deny", "outcome": "pass", "evidence_ids": ["EV-1"]},
                {"check_id": "config", "outcome": "pass", "evidence_ids": ["EV-2"]},
            ],
            "evidence": [
                {
                    "id": "EV-1",
                    "kind": "test-result",
                    "relative_path": "fresh.txt",
                    "sha256": hashlib.sha256(fresh.read_bytes()).hexdigest(),
                    "collected_at": _iso(T0 + timedelta(days=2)),
                },
                {
                    "id": "EV-2",
                    "kind": "configuration",
                    "relative_path": "old.txt",
                    "sha256": hashlib.sha256(old.read_bytes()).hexdigest(),
                    "collected_at": _iso(T0),
                },
            ],
            "scope_confirmed": True,
            "coverage_complete": True,
        }
    )
    report = evaluate_assessment(case, tmp_path, at=T0 + timedelta(days=2, hours=1))
    assert report.freshness_checks == {"EV-1": "fresh", "EV-2": "stale"}
    assert report.verdict == "inconclusive"
    assert "Required evidence kind configuration is missing." in report.reasons


# Contradictory or tampered time and bytes


def test_future_collection_time_is_inconclusive(tmp_path: Path) -> None:
    report = evaluate_assessment(
        local_input(tmp_path, collected_at=T0 + timedelta(seconds=1)),
        tmp_path,
        at=T0,
    )
    assert report.freshness_checks == {"EV-1": "future_timestamp"}
    assert report.verdict == "inconclusive"


def test_collection_after_ingestion_is_inconclusive(tmp_path: Path) -> None:
    probe = datetime.now(UTC)
    root, stored, case = vault_input(tmp_path, collected_at=probe)
    case.evidence[0].collected_at = ingested(stored) + timedelta(seconds=1)
    report = evaluate_assessment(
        case, tmp_path, root, at=ingested(stored) + timedelta(minutes=1)
    )
    assert report.freshness_checks == {"EV-1": "collected_after_ingestion"}
    assert report.verdict == "inconclusive"


@pytest.mark.parametrize(
    ("stored_time", "expected"),
    [
        ("not-a-time", "invalid_ingestion_time"),
        ("2026-10-01T12:00:00", "invalid_ingestion_time"),
        ("2099-01-01T00:00:00+00:00", "future_timestamp"),
        ("2000-01-01T00:00:00+00:00", "collected_after_ingestion"),
    ],
)
def test_tampered_ingestion_time_cannot_verify(
    tmp_path: Path, stored_time: str, expected: str
) -> None:
    root, stored, case = vault_input(tmp_path, collected_at=datetime.now(UTC))
    case.evidence[0].collected_at = ingested(stored)
    with closing(sqlite3.connect(root / "vault.db")) as db, db:
        db.execute(
            "UPDATE artifacts SET ingested_at = ? WHERE artifact_id = ?",
            (stored_time, stored.artifact_id),
        )
    report = evaluate_assessment(
        case, tmp_path, root, at=ingested(stored) + timedelta(minutes=1)
    )
    assert report.artifact_checks == {"EV-1": "matched"}
    assert report.freshness_checks == {"EV-1": expected}
    assert report.verdict == "inconclusive"


def test_tampered_bytes_are_not_freshness_checked(tmp_path: Path) -> None:
    case = local_input(tmp_path)
    (tmp_path / "observation.txt").write_text("tampered", encoding="utf-8")
    report = evaluate_assessment(case, tmp_path, at=T0 + timedelta(hours=1))
    assert report.artifact_checks == {"EV-1": "hash_mismatch"}
    assert report.freshness_checks == {"EV-1": "not_checked"}
    assert report.verdict == "inconclusive"


def test_naive_evaluation_time_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(AssessmentInputError, match="timezone"):
        evaluate_assessment(local_input(tmp_path), tmp_path, at=T0.replace(tzinfo=None))


@pytest.mark.parametrize("bad", [0, -1, 1.5, True, "86400", 315_360_001])
def test_invalid_freshness_policy_rejected(bad: object) -> None:
    with pytest.raises(ValidationError):
        ControlVerificationProcedure.model_validate(
            {**_procedure(), "max_evidence_age_seconds": bad}
        )


@pytest.mark.parametrize("bad", ["2026-10-01T12:00:00", "yesterday", 1_790_000_000])
def test_invalid_collection_time_rejected(tmp_path: Path, bad: object) -> None:
    data = local_input(tmp_path).model_dump(mode="json")
    data["evidence"][0]["collected_at"] = bad
    with pytest.raises(ValidationError):
        AssessmentInput.model_validate(data)


# Reports and publication


def test_report_records_freshness_and_hash_verifies(tmp_path: Path) -> None:
    case = local_input(tmp_path, collected_at=datetime.now(UTC))
    input_path = tmp_path / "input.json"
    input_path.write_text(case.model_dump_json(), encoding="utf-8")
    output = tmp_path / "report.json"
    report = evaluate_file(input_path, output)
    assert report.verdict == "verified"
    assert report.schema_version == "0.2.0"
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["freshness_checks"] == {"EV-1": "fresh"}
    assert saved["procedure"]["max_evidence_age_seconds"] == DAY
    assert verify_evidence_file(output).valid


def _published_case(tmp_path: Path) -> tuple[Path, Path, VaultArtifact]:
    root, stored, case = vault_input(tmp_path, collected_at=datetime.now(UTC))
    case.evidence[0].collected_at = ingested(stored) - timedelta(minutes=1)
    input_path = tmp_path / "input.json"
    input_path.write_text(case.model_dump_json(), encoding="utf-8")
    report_path = tmp_path / "report.json"
    assert evaluate_file(input_path, report_path, vault_root=root).verdict == (
        "verified"
    )
    return root, report_path, stored


def test_publication_rechecks_freshness_at_publication_time(tmp_path: Path) -> None:
    root, report_path, stored = _published_case(tmp_path)
    catalog = LocalAssuranceCatalog(root)
    with pytest.raises(CatalogError, match="freshness"):
        catalog.publish(report_path, at=ingested(stored) + timedelta(days=2))
    assert catalog.history("CVP-FRESH-001") == []
    publication = catalog.publish(report_path)
    assert publication.verdict == "verified"


def test_publication_time_cannot_be_backdated_or_naive(tmp_path: Path) -> None:
    root, report_path, _stored = _published_case(tmp_path)
    catalog = LocalAssuranceCatalog(root)
    for bad in (
        datetime.now(UTC) - timedelta(minutes=1),
        T0.replace(year=2099, tzinfo=None),
    ):
        with pytest.raises(CatalogError, match="Publication time"):
            catalog.publish(report_path, at=bad)
    assert catalog.history("CVP-FRESH-001") == []


def test_rehashed_report_cannot_relabel_stale_evidence(tmp_path: Path) -> None:
    root, report_path, stored = _published_case(tmp_path)
    edited = json.loads(report_path.read_text(encoding="utf-8"))
    edited["procedure"]["max_evidence_age_seconds"] = 315_360_000
    edited.pop("evidence_hash")
    edited["evidence_hash"] = hash_payload(edited)
    report_path.write_text(json.dumps(edited), encoding="utf-8")
    # The widened policy is still honoured as declared, so this is the
    # documented limitation: the procedure itself is caller-controlled.
    assert LocalAssuranceCatalog(root).publish(report_path).verdict == "verified"

    late = ingested(stored) + timedelta(days=2)
    edited["procedure"]["max_evidence_age_seconds"] = DAY
    edited["freshness_checks"] = {"EV-1": "fresh"}
    edited.pop("evidence_hash")
    edited["evidence_hash"] = hash_payload(edited)
    report_path.write_text(json.dumps(edited), encoding="utf-8")
    with pytest.raises(CatalogError, match="freshness"):
        LocalAssuranceCatalog(root).publish(report_path, at=late)


def test_legacy_policy_free_verified_report_is_refused(tmp_path: Path) -> None:
    root, report_path, _stored = _published_case(tmp_path)
    legacy = json.loads(report_path.read_text(encoding="utf-8"))
    legacy["schema_version"] = "0.1.0"
    legacy["procedure"].pop("max_evidence_age_seconds")
    legacy.pop("freshness_checks")
    for item in legacy["evidence"]:
        item.pop("collected_at")
    legacy.pop("evidence_hash")
    legacy["evidence_hash"] = hash_payload(legacy)
    report_path.write_text(json.dumps(legacy), encoding="utf-8")
    assert verify_evidence_file(report_path).valid
    with pytest.raises(CatalogError, match="freshness"):
        LocalAssuranceCatalog(root).publish(report_path)


def test_cli_reports_freshness_without_policy(tmp_path: Path) -> None:
    case = local_input(tmp_path, max_age=None, collected_at=datetime.now(UTC))
    input_path = tmp_path / "input.json"
    input_path.write_text(case.model_dump_json(), encoding="utf-8")
    output = tmp_path / "out.json"
    response = CliRunner().invoke(
        app, ["assurance", "evaluate", str(input_path), "--output", str(output)]
    )
    assert response.exit_code == 0, response.output
    assert "INCONCLUSIVE" in response.output
    assert "freshness policy" in response.output
    assert "Freshness EV-1: no_policy" in response.output
