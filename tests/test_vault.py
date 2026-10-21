"""Known-ground-truth tests for the development-only Evidence Vault."""

import hashlib
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from grcctl.cli import app
from grcctl.vault import LocalEvidenceVault, VaultError

runner = CliRunner()


def _source(tmp_path: Path, name: str = "synthetic.txt") -> Path:
    path = tmp_path / name
    path.write_bytes(b"synthetic GRC assessment output only")
    return path


def _blob_path(root: Path, digest: str) -> Path:
    return root / "objects" / "sha256" / digest[:2] / digest


def test_persistent_ingestion_and_integrity(tmp_path: Path) -> None:
    root = tmp_path / "private-vault"
    source = _source(tmp_path)
    vault = LocalEvidenceVault(root)
    record = vault.ingest(source, kind="test-result")
    assert record.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert record.kind == "test-result"
    assert vault.verify(record.artifact_id).valid
    assert LocalEvidenceVault(root).get(record.artifact_id) == record
    assert LocalEvidenceVault(root).list_artifacts()[0] == record
    assert _blob_path(root, record.sha256).read_bytes() == source.read_bytes()
    assert record.origin_claim == "operator-provided (unverified)"


def test_identical_bytes_preserved_once_but_each_ingest_recorded(
    tmp_path: Path,
) -> None:
    root = tmp_path / "vault"
    vault = LocalEvidenceVault(root)
    first = vault.ingest(_source(tmp_path))
    second = vault.ingest(_source(tmp_path, "other.txt"))
    assert first.artifact_id != second.artifact_id
    assert first.sha256 == second.sha256
    assert len(vault.list_artifacts()) == 2
    assert len(list((root / "objects" / "sha256").rglob(first.sha256))) == 1


def test_tampering_detected_and_original_blob_not_overwritten(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    source = _source(tmp_path)
    vault = LocalEvidenceVault(root)
    record = vault.ingest(source)
    blob = _blob_path(root, record.sha256)
    blob.write_bytes(b"tampered")
    result = vault.verify(record.artifact_id)
    assert result.status == "hash_mismatch"
    assert not result.valid
    with pytest.raises(VaultError, match="invalid"):
        vault.ingest(source)
    assert blob.read_bytes() == b"tampered"


def test_missing_object_and_unknown_reference(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    vault = LocalEvidenceVault(root)
    record = vault.ingest(_source(tmp_path))
    _blob_path(root, record.sha256).unlink()
    assert vault.verify(record.artifact_id).status == "missing"
    with pytest.raises(VaultError, match="Unknown"):
        vault.verify("not-a-real-artifact-id")


def test_rejects_symlinked_source_and_symlinked_blob(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    source = _source(tmp_path)
    link = tmp_path / "link.txt"
    link.symlink_to(source)
    vault = LocalEvidenceVault(root)
    with pytest.raises(VaultError, match="symbolic-link"):
        vault.ingest(link)
    record = vault.ingest(source)
    blob = _blob_path(root, record.sha256)
    blob.unlink()
    blob.symlink_to(source)
    assert vault.verify(record.artifact_id).status == "unsafe_store"
    with pytest.raises(VaultError, match="invalid"):
        vault.ingest(source)


def test_rejects_oversized_and_invalid_kind(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    vault = LocalEvidenceVault(root)
    source = _source(tmp_path)
    with pytest.raises(VaultError, match="size limit"):
        vault.ingest(source, max_bytes=5)
    assert list((root / "staging").iterdir()) == []
    assert vault.list_artifacts() == []
    with pytest.raises(VaultError, match="kind"):
        vault.ingest(source, kind="../../bad")


def test_local_directory_requires_private_permissions(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("Unix mode semantics")
    root = tmp_path / "vault"
    root.mkdir(mode=0o700)
    root.chmod(0o755)
    with pytest.raises(VaultError, match="private"):
        LocalEvidenceVault(root)


def test_cli_ingest_list_verify_and_corruption_exit(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    source = _source(tmp_path)
    command = runner.invoke(
        app,
        ["vault", "ingest", str(source), "--root", str(root), "--kind", "test-result"],
    )
    assert command.exit_code == 0, command.output
    assert "STORED" in command.output
    assert "Ingested (host clock):" in command.output
    artifact_id = LocalEvidenceVault(root).list_artifacts()[0].artifact_id
    listing = runner.invoke(app, ["vault", "list", "--root", str(root)])
    assert listing.exit_code == 0, listing.output
    assert "test-result" in listing.output
    verified = runner.invoke(app, ["vault", "verify", artifact_id, "--root", str(root)])
    assert verified.exit_code == 0, verified.output
    assert "MATCHED" in verified.output
    digest = LocalEvidenceVault(root).get(artifact_id).sha256
    _blob_path(root, digest).write_text("bad", encoding="utf-8")
    rejected = runner.invoke(app, ["vault", "verify", artifact_id, "--root", str(root)])
    assert rejected.exit_code == 1
    assert "HASH_MISMATCH" in rejected.output
