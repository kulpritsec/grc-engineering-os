"""Vault-backed CVP regression and known-ground-truth negative cases."""

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from grcctl.assurance.engine import evaluate_file
from grcctl.assurance.models import ArtifactReference
from grcctl.cli import app
from grcctl.evidence import verify_evidence_file
from grcctl.vault import LocalEvidenceVault

runner = CliRunner()


def create_case(tmp_path: Path, *, outcome: str = "pass"):
    root = tmp_path / "vault"
    workspace = tmp_path / "assessment"
    workspace.mkdir()
    source = tmp_path / "synthetic-control-result.txt"
    source.write_text("synthetic denied-access test result", encoding="utf-8")
    vault = LocalEvidenceVault(root)
    artifact = vault.ingest(source, kind="test-result")
    input_data = {
        "assessment_id": "ASMT-VAULT-001",
        "procedure": {
            "id": "CVP-SYNTHETIC-001",
            "title": "Restricted record test",
            "assertion": "Synthetic test identity cannot read the record.",
            "scope": "isolated test network",
            "required_check_ids": ["deny-access"],
            "required_evidence_kinds": ["test-result"],
        },
        "observations": [
            {"check_id": "deny-access", "outcome": outcome, "evidence_ids": ["EV-1"]}
        ],
        "evidence": [
            {
                "id": "EV-1",
                "kind": "test-result",
                "vault_artifact_id": artifact.artifact_id,
                "sha256": artifact.sha256,
            }
        ],
        "scope_confirmed": True,
        "coverage_complete": True,
    }
    input_path = workspace / "cvp.json"
    input_path.write_text(json.dumps(input_data), encoding="utf-8")
    return root, source, vault, artifact, input_path, input_data


def test_saved_vault_reference_survives_deleted_source(tmp_path: Path) -> None:
    root, source, _vault, artifact, input_path, _data = create_case(tmp_path)
    source.unlink()
    result = evaluate_file(
        input_path, tmp_path / "cvp-result.json", vault_root=root
    )
    assert result.verdict == "verified"
    assert result.artifact_checks["EV-1"] == "matched"
    assert result.evidence[0].vault_artifact_id == artifact.artifact_id
    assert result.evidence[0].relative_path is None
    assert verify_evidence_file(tmp_path / "cvp-result.json").valid


def test_cli_vault_reference_and_bad_scope(tmp_path: Path) -> None:
    root, _source, _vault, _artifact, input_path, data = create_case(tmp_path)
    result = runner.invoke(
        app,
        [
            "assurance", "evaluate", str(input_path),
            "--vault-root", str(root), "--output", str(tmp_path / "out.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "VERIFIED" in result.output
    data["scope_confirmed"] = False
    input_path.write_text(json.dumps(data), encoding="utf-8")
    unconfirmed = evaluate_file(input_path, tmp_path / "out.json", vault_root=root)
    assert unconfirmed.verdict == "inconclusive"


def test_vault_metadata_digest_or_kind_mismatch(tmp_path: Path) -> None:
    root, _source, _vault, _artifact, input_path, data = create_case(tmp_path)
    evidence = data["evidence"][0]
    evidence["sha256"] = hashlib.sha256(b"wrong").hexdigest()
    input_path.write_text(json.dumps(data), encoding="utf-8")
    result = evaluate_file(input_path, tmp_path / "out.json", vault_root=root)
    assert result.verdict == "inconclusive"
    assert result.artifact_checks["EV-1"] == "metadata_mismatch"
    evidence["sha256"] = _artifact.sha256
    evidence["kind"] = "configuration"
    input_path.write_text(json.dumps(data), encoding="utf-8")
    result = evaluate_file(input_path, tmp_path / "out.json", vault_root=root)
    assert result.verdict == "inconclusive"
    assert result.artifact_checks["EV-1"] == "metadata_mismatch"


def test_missing_vault_and_unresolved_artifact_id(tmp_path: Path) -> None:
    root, _source, _vault, _artifact, input_path, data = create_case(tmp_path)
    result = evaluate_file(input_path, tmp_path / "out.json")
    assert result.verdict == "inconclusive"
    assert result.artifact_checks["EV-1"] == "vault_not_configured"
    result = evaluate_file(input_path, tmp_path / "out.json", vault_root=root / "wrong")
    assert result.verdict == "inconclusive"
    assert result.artifact_checks["EV-1"] == "vault_missing"
    data["evidence"][0]["vault_artifact_id"] = "does-not-exist"
    input_path.write_text(json.dumps(data), encoding="utf-8")
    result = evaluate_file(input_path, tmp_path / "out.json", vault_root=root)
    assert result.verdict == "inconclusive"
    assert result.artifact_checks["EV-1"] == "vault_reference_invalid"


def test_tampered_blob_downgrades_assessment(tmp_path: Path) -> None:
    root, _source, _vault, artifact, input_path, _data = create_case(tmp_path)
    blob = root / "objects" / "sha256" / artifact.sha256[:2] / artifact.sha256
    blob.write_bytes(b"tampered after ingestion")
    result = evaluate_file(input_path, tmp_path / "out.json", vault_root=root)
    assert result.verdict == "inconclusive"
    assert result.artifact_checks["EV-1"] == "hash_mismatch"


def test_vault_observed_failure_is_failed_not_pass(tmp_path: Path) -> None:
    root, _source, _vault, _artifact, input_path, _data = create_case(
        tmp_path, outcome="fail"
    )
    result = evaluate_file(input_path, tmp_path / "out.json", vault_root=root)
    assert result.verdict == "failed"


def test_mixed_local_and_vault_evidence(tmp_path: Path) -> None:
    root, _source, _vault, _artifact, input_path, data = create_case(tmp_path)
    workspace = input_path.parent
    local = workspace / "second.txt"
    local.write_text("synthetic local secondary observation", encoding="utf-8")
    data["evidence"].append(
        {
            "id": "EV-2", "kind": "test-result",
            "relative_path": "second.txt",
            "sha256": hashlib.sha256(local.read_bytes()).hexdigest(),
        }
    )
    data["observations"][0]["evidence_ids"].append("EV-2")
    input_path.write_text(json.dumps(data), encoding="utf-8")
    result = evaluate_file(input_path, tmp_path / "out.json", vault_root=root)
    assert result.verdict == "verified"
    assert result.artifact_checks == {"EV-1": "matched", "EV-2": "matched"}


def test_reference_requires_exactly_one_location() -> None:
    base = {
        "id": "EV-1", "kind": "test-result",
        "sha256": "a" * 64,
    }
    with pytest.raises(ValidationError):
        ArtifactReference.model_validate(base)
    with pytest.raises(ValidationError):
        ArtifactReference.model_validate(
            {**base, "relative_path": "test.txt", "vault_artifact_id": "uuid-1"}
        )
