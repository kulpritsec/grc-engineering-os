"""Ground-truth checks for persisted assessment/evidence relationships."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from grcctl.assurance.catalog import CatalogError, LocalAssuranceCatalog
from grcctl.assurance.engine import evaluate_file
from grcctl.cli import app
from grcctl.doctor import hash_payload
from grcctl.vault import LocalEvidenceVault

runner = CliRunner()


def fixture_run(tmp_path: Path, *, outcome: str = "pass"):
    root = tmp_path / "vault"
    vault = LocalEvidenceVault(root)
    origin = tmp_path / "record.txt"
    origin.write_text("synthetic verified control observation", encoding="utf-8")
    stored = vault.ingest(origin, kind="test-result")
    data = {
        "assessment_id": "RUN-001",
        "procedure": {
            "id": "CVP-001",
            "title": "Synthetic access validation",
            "assertion": "Test role access is denied",
            "scope": "sandbox",
            "required_check_ids": ["deny"],
            "required_evidence_kinds": ["test-result"],
        },
        "observations": [
            {"check_id": "deny", "outcome": outcome, "evidence_ids": ["EV-1"]}
        ],
        "evidence": [
            {
                "id": "EV-1",
                "kind": "test-result",
                "vault_artifact_id": stored.artifact_id,
                "sha256": stored.sha256,
            }
        ],
        "scope_confirmed": True,
        "coverage_complete": True,
    }
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps(data), encoding="utf-8")
    report_path = tmp_path / "report.json"
    evaluate_file(input_file, report_path, vault_root=root)
    return root, stored, report_path


def test_publish_persists_relationship_and_report(tmp_path: Path) -> None:
    root, stored, report = fixture_run(tmp_path)
    catalog = LocalAssuranceCatalog(root)
    pub = catalog.publish(report)
    assert pub.verdict == "verified"
    assert pub.procedure_id == "CVP-001"
    assert catalog.history("CVP-001") == [pub]
    links = catalog.evidence_usage(stored.artifact_id)
    assert len(links) == 1
    assert links[0].publication_id == pub.publication_id
    assert links[0].sha256 == stored.sha256
    assert catalog.publication_integrity(pub.publication_id) == {
        "report": "matched",
        "EV-1": "matched",
    }
    report.unlink()
    reopened = LocalAssuranceCatalog(root)
    assert reopened.history("CVP-001") == [pub]
    assert reopened.publication_integrity(pub.publication_id)["report"] == "matched"
    assert reopened.history("other") == []


def test_repeated_publication_is_new_history_not_overwrite(tmp_path: Path) -> None:
    root, stored, report = fixture_run(tmp_path)
    catalog = LocalAssuranceCatalog(root)
    first = catalog.publish(report)
    second = catalog.publish(report)
    assert first.publication_id != second.publication_id
    assert first.report_artifact_id != second.report_artifact_id
    assert first.report_sha256 == second.report_sha256
    assert len(catalog.history("CVP-001")) == 2
    assert len(catalog.evidence_usage(stored.artifact_id)) == 2


def test_publish_failed_observation_with_valid_evidence(tmp_path: Path) -> None:
    root, stored, report = fixture_run(tmp_path, outcome="fail")
    catalog = LocalAssuranceCatalog(root)
    publication = catalog.publish(report)
    assert publication.verdict == "failed"
    assert catalog.evidence_usage(stored.artifact_id)[0].publication_id == (
        publication.publication_id
    )


def test_report_rewrite_with_recomputed_hash_cannot_force_verdict(tmp_path: Path) -> None:
    root, _stored, report = fixture_run(tmp_path, outcome="fail")
    changed = json.loads(report.read_text(encoding="utf-8"))
    changed["verdict"] = "verified"
    unsigned_payload = dict(changed)
    unsigned_payload.pop("evidence_hash")
    changed["evidence_hash"] = hash_payload(unsigned_payload)
    report.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(CatalogError, match="verdict differs"):
        LocalAssuranceCatalog(root).publish(report)


def test_tampered_evidence_blocks_publication(tmp_path: Path) -> None:
    root, stored, report = fixture_run(tmp_path)
    blob = root / "objects" / "sha256" / stored.sha256[:2] / stored.sha256
    blob.write_text("corrupted", encoding="utf-8")
    with pytest.raises(CatalogError, match="Current evidence checks differ"):
        LocalAssuranceCatalog(root).publish(report)


def test_source_report_must_be_valid_and_vault_backed(tmp_path: Path) -> None:
    root, _stored, report = fixture_run(tmp_path)
    catalog = LocalAssuranceCatalog(root)
    edited = json.loads(report.read_text(encoding="utf-8"))
    edited["scope_confirmed"] = False
    report.write_text(json.dumps(edited), encoding="utf-8")
    with pytest.raises(CatalogError, match="schema/hash"):
        catalog.publish(report)

    # A valid file-backed report may be evaluated, but is not eligible
    # for a stable Vault UUID publication.
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    local = workspace / "local.txt"
    local.write_text("local", encoding="utf-8")
    with open(workspace / "input.json", "w", encoding="utf-8") as file:
        file.write(
            json.dumps(
                {
                    "assessment_id": "LOCAL-001",
                    "procedure": {
                        "id": "CVP-LOCAL",
                        "title": "File only",
                        "assertion": "Synthetic test",
                        "scope": "sandbox",
                        "required_check_ids": ["test"],
                        "required_evidence_kinds": ["test-result"],
                    },
                    "observations": [
                        {
                            "check_id": "test",
                            "outcome": "pass",
                            "evidence_ids": ["EV-1"],
                        }
                    ],
                    "evidence": [
                        {
                            "id": "EV-1",
                            "kind": "test-result",
                            "relative_path": "local.txt",
                            "sha256": __import__("hashlib").sha256(
                                local.read_bytes()
                            ).hexdigest(),
                        }
                    ],
                    "scope_confirmed": True,
                    "coverage_complete": True,
                }
            )
        )
    local_report = workspace / "report.json"
    evaluate_file(workspace / "input.json", local_report)
    with pytest.raises(CatalogError, match="Vault UUIDs"):
        catalog.publish(local_report)


def test_history_limit_and_integrity_changes(tmp_path: Path) -> None:
    root, stored, report = fixture_run(tmp_path)
    catalog = LocalAssuranceCatalog(root)
    pub = catalog.publish(report)
    with pytest.raises(CatalogError, match="limit"):
        catalog.history("CVP-001", limit=0)
    with pytest.raises(CatalogError, match="Unknown publication"):
        catalog.publication_integrity("nonexistent")
    original = root / "objects" / "sha256" / stored.sha256[:2] / stored.sha256
    original.unlink()
    assert catalog.publication_integrity(pub.publication_id)["EV-1"] == "missing"


def test_publish_cli_and_read_only_history(tmp_path: Path) -> None:
    root, stored, report = fixture_run(tmp_path)
    response = runner.invoke(
        app, ["assurance", "publish", str(report), "--vault-root", str(root)]
    )
    assert response.exit_code == 0, response.output
    assert "PUBLISHED" in response.output
    history = runner.invoke(
        app, ["assurance", "history", "CVP-001", "--vault-root", str(root)]
    )
    assert history.exit_code == 0, history.output
    assert "CVP-001" in history.output
    usage = runner.invoke(
        app,
        ["assurance", "evidence-usage", stored.artifact_id, "--vault-root", str(root)],
    )
    assert usage.exit_code == 0, usage.output
    assert "EV-1" in usage.output
