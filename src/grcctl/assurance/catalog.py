"""Local, application-append-only assessment and evidence relationship catalog.

The metadata database is still operator-mutable SQLite, not a signed audit
ledger or authenticated release decision. This adapter is for synthetic labs.
"""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from ..evidence import verify_evidence_file
from ..vault import LocalEvidenceVault, VaultError
from .engine import evaluate_assessment
from .journal import JournalCheck, append_publication, create_journal, verify_journal
from .models import AssessmentInput, AssessmentReport


class CatalogError(ValueError):
    """Assessment publication cannot be substantiated."""


@dataclass(frozen=True)
class AssessmentPublication:
    publication_id: str
    assessment_id: str
    procedure_id: str
    scope: str
    verdict: str
    evaluated_at: str
    published_at: str
    report_artifact_id: str
    report_sha256: str


@dataclass(frozen=True)
class EvidenceLink:
    publication_id: str
    evidence_id: str
    artifact_id: str
    kind: str
    sha256: str


class LocalAssuranceCatalog:
    """Persist reviewable CVP-to-Vault links without creating a separate store."""

    def __init__(self, root: Path) -> None:
        self.vault = LocalEvidenceVault(root)
        with self.vault._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS assessment_publications (
                    publication_id TEXT PRIMARY KEY,
                    assessment_id TEXT NOT NULL,
                    procedure_id TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    report_artifact_id TEXT NOT NULL,
                    report_sha256 TEXT NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS assessment_evidence_links (
                    publication_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    PRIMARY KEY (publication_id, evidence_id),
                    FOREIGN KEY(publication_id)
                        REFERENCES assessment_publications(publication_id)
                )
                """
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_publications_procedure "
                "ON assessment_publications(procedure_id)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_links_artifact "
                "ON assessment_evidence_links(artifact_id)"
            )
            create_journal(db)

    def publish(self, report_path: Path) -> AssessmentPublication:
        """Reassess stored evidence before recording an immutable-in-API run."""
        if report_path.is_symlink():
            raise CatalogError("Symbolic-link assessment reports are refused.")
        try:
            raw = report_path.read_bytes()
            report = AssessmentReport.model_validate_json(raw)
        except (OSError, ValueError, ValidationError) as exc:
            raise CatalogError(f"Cannot read assessment report: {exc}") from exc

        result = verify_evidence_file(report_path)
        if not result.valid:
            raise CatalogError("Assessment report schema/hash is not valid.")
        if not report.evidence:
            raise CatalogError("Publishing requires retained evidence references.")
        if any(item.vault_artifact_id is None for item in report.evidence):
            raise CatalogError("All published evidence must reference Vault UUIDs.")
        if set(report.artifact_checks) != {item.id for item in report.evidence}:
            raise CatalogError("Report's artifact check set is inconsistent.")

        trial = AssessmentInput(
            assessment_id=report.assessment_id,
            procedure=report.procedure,
            observations=report.observations,
            evidence=report.evidence,
            scope_confirmed=report.scope_confirmed,
            coverage_complete=report.coverage_complete,
        )
        current = evaluate_assessment(trial, report_path.parent, self.vault.root)
        if current.verdict != report.verdict:
            raise CatalogError("Stored assessment verdict differs from reevaluation.")
        if current.artifact_checks != report.artifact_checks:
            raise CatalogError("Current evidence checks differ from the report.")
        if set(current.artifact_checks.values()) != {"matched"}:
            raise CatalogError("One or more referenced Vault artifacts are invalid.")

        try:
            stored = self.vault.ingest(report_path, kind="assessment-report")
        except (VaultError, OSError) as exc:
            raise CatalogError(f"Report could not be preserved: {exc}") from exc
        if stored.sha256 != hashlib.sha256(raw).hexdigest():
            raise CatalogError("Assessment source changed during publication.")

        publication = AssessmentPublication(
            publication_id=str(uuid4()),
            assessment_id=report.assessment_id,
            procedure_id=report.procedure.id,
            scope=report.procedure.scope,
            verdict=report.verdict,
            evaluated_at=report.evaluated_at.isoformat(),
            published_at=datetime.now(UTC).isoformat(),
            report_artifact_id=stored.artifact_id,
            report_sha256=stored.sha256,
        )
        with self.vault._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not verify_journal(db).valid:
                raise CatalogError(
                    "Existing publication journal is inconsistent; "
                    "refusing to extend it."
                )
            db.execute(
                """
                INSERT INTO assessment_publications (
                    publication_id, assessment_id, procedure_id, scope, verdict,
                    evaluated_at, published_at, report_artifact_id, report_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    publication.publication_id,
                    publication.assessment_id,
                    publication.procedure_id,
                    publication.scope,
                    publication.verdict,
                    publication.evaluated_at,
                    publication.published_at,
                    publication.report_artifact_id,
                    publication.report_sha256,
                ),
            )
            links: list[dict[str, str]] = []
            for evidence in report.evidence:
                if evidence.vault_artifact_id is None:
                    raise CatalogError("Published evidence must have a Vault ID.")
                links.append(
                    {
                        "evidence_id": evidence.id,
                        "artifact_id": evidence.vault_artifact_id,
                        "kind": evidence.kind,
                        "sha256": evidence.sha256,
                    }
                )
                db.execute(
                    """
                    INSERT INTO assessment_evidence_links (
                        publication_id, evidence_id, artifact_id, kind, sha256
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        publication.publication_id,
                        evidence.id,
                        evidence.vault_artifact_id,
                        evidence.kind,
                        evidence.sha256,
                    ),
                )
            append_publication(
                db,
                publication_id=publication.publication_id,
                report_sha256=publication.report_sha256,
                links=links,
            )
        return publication

    def journal_status(self) -> JournalCheck:
        """Detect inconsistencies in local publication/relationship metadata."""
        with self.vault._connect() as db:
            return verify_journal(db)

    def history(
        self, procedure_id: str, limit: int = 100
    ) -> list[AssessmentPublication]:
        """Return past evaluation publications in reverse publication order."""
        if not 1 <= limit <= 1000:
            raise CatalogError("History limit must be between 1 and 1000.")
        with self.vault._connect() as db:
            records = db.execute(
                """
                SELECT * FROM assessment_publications
                WHERE procedure_id = ?
                ORDER BY published_at DESC, publication_id DESC LIMIT ?
                """,
                (procedure_id, limit),
            ).fetchall()
        return [AssessmentPublication(**dict(record)) for record in records]

    def evidence_usage(self, artifact_id: str) -> list[EvidenceLink]:
        """Which published assessments used this *particular* ingestion ID?"""
        with self.vault._connect() as db:
            records = db.execute(
                """
                SELECT * FROM assessment_evidence_links
                WHERE artifact_id = ?
                ORDER BY publication_id
                """,
                (artifact_id,),
            ).fetchall()
        return [EvidenceLink(**dict(record)) for record in records]

    def publication_integrity(self, publication_id: str) -> dict[str, str]:
        """Recheck persisted report and linked evidence against their digests."""
        with self.vault._connect() as db:
            report = db.execute(
                "SELECT * FROM assessment_publications WHERE publication_id = ?",
                (publication_id,),
            ).fetchone()
            links = db.execute(
                "SELECT * FROM assessment_evidence_links WHERE publication_id = ?",
                (publication_id,),
            ).fetchall()
        if report is None:
            raise CatalogError("Unknown publication ID.")
        result: dict[str, str] = {}
        references = [("report", report["report_artifact_id"], report["report_sha256"])]
        references.extend(
            (link["evidence_id"], link["artifact_id"], link["sha256"]) for link in links
        )
        for name, artifact_id, digest in references:
            try:
                record = self.vault.get(artifact_id)
                if record.sha256 != digest:
                    result[name] = "metadata_mismatch"
                else:
                    result[name] = self.vault.verify(artifact_id).status
            except (VaultError, OSError):
                result[name] = "vault_reference_invalid"
        return result
