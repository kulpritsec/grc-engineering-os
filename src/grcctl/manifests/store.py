"""Local replay consumption and additive Vault links; operator-mutable metadata."""

import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from ..assurance.journal import verify_journal
from ..vault import LocalEvidenceVault, VaultError
from .codec import ManifestError, parse_contract, read_bounded
from .models import ManifestCheck, SignedManifest, VerificationContext
from .verifier import verify_manifest


def consume(db: sqlite3.Connection, check: ManifestCheck) -> ManifestCheck:
    """Caller owns transaction; consumption and its other writes are atomic."""
    if not check.authenticated or check.manifest_id is None:
        return check
    db.execute(
        "CREATE TABLE IF NOT EXISTS consumed_manifests "
        "(manifest_id TEXT PRIMARY KEY, verified_at TEXT NOT NULL)"
    )
    try:
        db.execute(
            "INSERT INTO consumed_manifests VALUES (?, ?)",
            (check.manifest_id, check.verified_at),
        )
    except sqlite3.IntegrityError:
        return check.model_copy(
            update={
                "authenticated": False,
                "replay": "duplicate",
                "problems": [*check.problems, "Manifest was already consumed locally."],
            }
        )
    return check.model_copy(update={"replay": "consumed_locally"})


def consume_file(registry: Path, check: ManifestCheck) -> ManifestCheck:
    """Optional caller-owned seen state; does not protect against registry rollback."""
    if not check.authenticated:
        return check
    try:
        if any(path.is_symlink() for path in (registry, *registry.parents)):
            raise ManifestError("Symbolic-link replay registry refused.")
        if not registry.exists():
            fd = os.open(registry, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        if not registry.is_file():
            raise ManifestError("Replay registry is not a regular file.")
        if os.name == "posix" and registry.stat().st_mode & 0o077:
            raise ManifestError("Replay registry must be private (0600).")
        with closing(sqlite3.connect(registry, timeout=10)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            return consume(db, check)
    except (OSError, sqlite3.Error) as exc:
        raise ManifestError(f"Replay registry unavailable: {exc}") from exc


def _preserve(vault: LocalEvidenceVault, raw: bytes, kind: str) -> str:
    """Preserve the same checked snapshot, never reread a caller's source file."""
    name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=vault.staging, delete=False) as handle:
            name = handle.name
            os.chmod(name, 0o600)
            handle.write(raw)
        return vault.ingest(Path(name), kind=kind).artifact_id
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)


def link_manifest(
    root: Path,
    raw: bytes,
    trust: bytes,
    *,
    context: VerificationContext,
    verified_at: str,
    publication_id: str | None = None,
) -> ManifestCheck:
    """Verify current retained evidence then append separate authentication metadata.

    Existing assessments/journal/verdicts remain unchanged. A preservation orphan
    can remain on failure, but replay consumption and link rows roll back together.
    """
    try:
        if not (root / "vault.db").is_file():
            raise ManifestError("Linkage requires an existing Vault.")
        manifest = parse_contract(raw, SignedManifest)
        payload = manifest.payload
        vault = LocalEvidenceVault(root)
        paths: dict[str, Path] = {}
        for item in payload.artifacts:
            record = vault.get(item.artifact_id)
            if (record.sha256, record.kind, record.size_bytes) != (
                item.sha256,
                item.kind,
                item.size_bytes,
            ):
                raise ManifestError("Signed artifact differs from Vault metadata.")
            paths[item.artifact_id] = vault.artifact_path(item.artifact_id)
        check = verify_manifest(
            raw, trust, paths, context=context, verified_at=verified_at
        )
        if not check.authenticated:
            raise ManifestError(
                "Manifest authentication refused: " + "; ".join(check.problems)
            )
        stored_manifest = _preserve(vault, raw, "signed-manifest")
        stored_trust = _preserve(vault, trust, "trust-policy-snapshot")
        with vault._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if publication_id is not None:
                if payload.assessment is None:
                    raise ManifestError(
                        "Publication linkage requires signed assessment context."
                    )
                if not verify_journal(db).valid:
                    raise ManifestError("Publication journal is inconsistent.")
                pub = db.execute(
                    "SELECT * FROM assessment_publications WHERE publication_id = ?",
                    (publication_id,),
                ).fetchone()
                if pub is None or (
                    pub["assessment_id"],
                    pub["procedure_id"],
                    pub["scope"],
                    pub["report_sha256"],
                ) != (
                    payload.assessment.assessment_id,
                    payload.assessment.procedure_id,
                    payload.scope,
                    payload.assessment.report_sha256,
                ):
                    raise ManifestError(
                        "Publication context does not match signed assessment."
                    )
                report_record = vault.get(pub["report_artifact_id"])
                if (
                    report_record.sha256 != pub["report_sha256"]
                    or not vault.verify(report_record.artifact_id).valid
                ):
                    raise ManifestError("Publication report is unavailable or altered.")
                links = db.execute(
                    "SELECT artifact_id, kind, sha256 FROM assessment_evidence_links "
                    "WHERE publication_id = ?",
                    (publication_id,),
                ).fetchall()
                if {(r["artifact_id"], r["kind"], r["sha256"]) for r in links} != {
                    (a.artifact_id, a.kind, a.sha256) for a in payload.artifacts
                }:
                    raise ManifestError(
                        "Publication evidence differs from signed artifact set."
                    )
            check = consume(db, check)
            if not check.authenticated:
                raise ManifestError("Manifest was already consumed locally.")
            check = check.model_copy(
                update={
                    "retained_manifest_id": stored_manifest,
                    "retained_trust_id": stored_trust,
                }
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS manifest_verifications ("
                "manifest_id TEXT PRIMARY KEY, manifest_artifact_id TEXT NOT NULL, "
                "trust_artifact_id TEXT NOT NULL, publication_id TEXT, check_json TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS manifest_artifact_links ("
                "manifest_id TEXT NOT NULL, artifact_id TEXT NOT NULL, "
                "PRIMARY KEY(manifest_id, artifact_id))"
            )
            db.execute(
                "INSERT INTO manifest_verifications VALUES (?, ?, ?, ?, ?)",
                (
                    payload.manifest_id,
                    stored_manifest,
                    stored_trust,
                    publication_id,
                    check.model_dump_json(),
                ),
            )
            db.executemany(
                "INSERT INTO manifest_artifact_links VALUES (?, ?)",
                [(payload.manifest_id, a.artifact_id) for a in payload.artifacts],
            )
        return check
    except (OSError, sqlite3.Error, VaultError) as exc:
        raise ManifestError(f"Manifest linkage failed: {exc}") from exc


def read_inputs(manifest_path: Path, trust_path: Path) -> tuple[bytes, bytes]:
    return read_bounded(manifest_path), read_bounded(trust_path)
