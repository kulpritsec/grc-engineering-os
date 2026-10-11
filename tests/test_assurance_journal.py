"""Adversarial fixtures for the local-only chained publication journal."""

import json
import sqlite3
from pathlib import Path

from typer.testing import CliRunner

from grcctl.assurance.catalog import CatalogError, LocalAssuranceCatalog
from grcctl.assurance.engine import evaluate_file
from grcctl.cli import app
from grcctl.vault import LocalEvidenceVault

runner = CliRunner()


def _demo(tmp_path: Path) -> tuple[LocalAssuranceCatalog, Path]:
    root = tmp_path / "vault"
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("synthetic data", encoding="utf-8")
    stored = LocalEvidenceVault(root).ingest(evidence, kind="test-result")
    data = {
        "assessment_id": "ASMT-JOURNAL-1",
        "procedure": {
            "id": "CVP-JOURNAL-1",
            "title": "Journal validation synthetic fixture",
            "assertion": "Synthetic access check passes",
            "scope": "test environment only",
            "required_check_ids": ["check"],
            "required_evidence_kinds": ["test-result"],
        },
        "observations": [
            {"check_id": "check", "outcome": "pass", "evidence_ids": ["E1"]}
        ],
        "evidence": [
            {
                "id": "E1",
                "kind": "test-result",
                "sha256": stored.sha256,
                "vault_artifact_id": stored.artifact_id,
            }
        ],
        "scope_confirmed": True,
        "coverage_complete": True,
    }
    input_file = tmp_path / "input.json"
    report_file = tmp_path / "report.json"
    input_file.write_text(json.dumps(data), encoding="utf-8")
    evaluate_file(input_file, report_file, vault_root=root)
    return LocalAssuranceCatalog(root), report_file


def _mutate(database: Path, statement: str, params: tuple[str, ...] = ()) -> None:
    with sqlite3.connect(database) as db:
        db.execute(statement, params)


def test_empty_and_single_publication_journal(tmp_path: Path) -> None:
    catalog, report = _demo(tmp_path)
    empty = catalog.journal_status()
    assert empty.valid
    assert empty.events_checked == 0
    pub = catalog.publish(report)
    check = catalog.journal_status()
    assert check.valid
    assert check.events_checked == 1
    assert catalog.publication_integrity(pub.publication_id)["report"] == "matched"


def test_multiple_publications_form_consistent_chain(tmp_path: Path) -> None:
    catalog, report = _demo(tmp_path)
    catalog.publish(report)
    catalog.publish(report)
    catalog.publish(report)
    assert catalog.journal_status().valid
    assert catalog.journal_status().events_checked == 3
    result = runner.invoke(
        app,
        [
            "assurance",
            "journal-verify",
            "--vault-root",
            str(catalog.vault.root),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "LOCAL JOURNAL CONSISTENT" in result.output


def test_journal_tampered_middle_hash_detected(tmp_path: Path) -> None:
    catalog, report = _demo(tmp_path)
    catalog.publish(report)
    catalog.publish(report)
    db = catalog.vault.db_path
    _mutate(
        db,
        "UPDATE publication_journal SET event_hash = ? WHERE sequence = ?",
        ("f" * 64, "1"),
    )
    result = catalog.journal_status()
    assert not result.valid
    assert any("Event hash mismatch" in item for item in result.problems)
    assert any("Broken previous-hash" in item for item in result.problems)
    rejected = runner.invoke(
        app,
        [
            "assurance",
            "journal-verify",
            "--vault-root",
            str(catalog.vault.root),
        ],
    )
    assert rejected.exit_code == 1
    assert "JOURNAL CHECK FAILED" in rejected.output


def test_changed_evidence_link_detected_and_publication_blocked(
    tmp_path: Path,
) -> None:
    catalog, report = _demo(tmp_path)
    pub = catalog.publish(report)
    _mutate(
        catalog.vault.db_path,
        "UPDATE assessment_evidence_links SET kind = ? WHERE publication_id = ?",
        ("modified", pub.publication_id),
    )
    result = catalog.journal_status()
    assert not result.valid
    assert any("relationship digest mismatch" in x for x in result.problems)
    try:
        catalog.publish(report)
    except CatalogError as exc:
        assert "inconsistent" in str(exc)
    else:
        raise AssertionError("Invalid journal cannot be extended.")


def test_removed_event_and_removed_publication_detected(tmp_path: Path) -> None:
    catalog, report = _demo(tmp_path)
    first = catalog.publish(report)
    catalog.publish(report)
    _mutate(
        catalog.vault.db_path,
        "DELETE FROM publication_journal WHERE publication_id = ?",
        (first.publication_id,),
    )
    result = catalog.journal_status()
    assert not result.valid
    assert any("count mismatch" in x for x in result.problems)
    assert any("sequence gap" in x for x in result.problems)


def test_blob_tamper_is_separate_from_local_journal_integrity(
    tmp_path: Path,
) -> None:
    catalog, report = _demo(tmp_path)
    pub = catalog.publish(report)
    root = catalog.vault.root
    evidence = next(
        item for item in catalog.vault.list_artifacts() if item.kind == "test-result"
    )
    digest = evidence.sha256
    blob = root / "objects" / "sha256" / digest[:2] / digest
    blob.write_text("tampered", encoding="utf-8")
    assert catalog.journal_status().valid
    assert catalog.publication_integrity(pub.publication_id)["E1"] == "hash_mismatch"
