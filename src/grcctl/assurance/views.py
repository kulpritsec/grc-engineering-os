"""Read-only operator views over published assessments.

Built on the read-only relationship projection: no schema initialization,
writes, CVP re-evaluation or source-evidence content. Only stored assessment
reports are returned, and only after a single verified read of their bytes.
"""

import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from pydantic import ValidationError

from ..relationships import (
    ProjectionError,
    RelationshipProjection,
    project_relationships,
)
from ..vault import LocalEvidenceVault, VaultError
from .models import AssessmentReport

VIEW_VERIFY_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024

VIEW_LIMITATIONS = [
    (
        "Stored verdicts are claims recorded at publication and are not "
        "re-evaluated here; evidence freshness and CVP conditions may have changed."
    ),
    "Byte integrity is local consistency only, not source authenticity.",
    "Source evidence content is never served; only verified stored reports are.",
    "Unauthenticated local development view; bind to loopback only.",
]


class VaultUnavailableError(ValueError):
    """No existing Vault database at the configured root."""


class StoreUnsupportedError(ValueError):
    """The Vault exists but cannot be safely read as a projection."""


def _identity(node_id: str) -> str:
    return unquote(node_id.split(":", 1)[1])


def _project(root: Path, limit: int) -> RelationshipProjection:
    # Check before opening so a misconfigured root is never created.
    if not root.is_dir() or not (root / "vault.db").is_file():
        raise VaultUnavailableError("No Vault database at the configured root.")
    try:
        return project_relationships(
            root, limit=limit, max_verify_bytes=VIEW_VERIFY_BYTES
        )
    except (ProjectionError, VaultError, sqlite3.Error, OSError) as exc:
        raise StoreUnsupportedError(f"Vault cannot be read safely: {exc}") from exc


def _integrity(node: Any, reference_status: str) -> str:
    if node is None:
        return "missing_record"
    if reference_status != "matched_metadata":
        return reference_status
    attributes = node.attributes
    return str(
        attributes.get("current_byte_integrity") or attributes.get("record_status")
    )


def _summaries(projection: RelationshipProjection) -> list[dict[str, Any]]:
    nodes = {node.id: node for node in projection.nodes}
    outgoing: dict[str, list[Any]] = {}
    for edge in projection.edges:
        outgoing.setdefault(edge.source, []).append(edge)

    summaries = []
    for node in projection.nodes:
        if node.kind != "publication" or node.attributes.get("placeholder"):
            continue
        attributes = node.attributes
        summary: dict[str, Any] = {
            "publication_id": _identity(node.id),
            "assessment_id": attributes.get("stored_assessment_id"),
            "procedure_id": None,
            "scope": None,
            "stored_verdict": attributes.get("stored_verdict"),
            "evaluated_at": attributes.get("stored_evaluated_at"),
            "published_at": attributes.get("stored_published_at"),
            "current_assurance": "not_evaluated",
            "report_artifact_id": None,
            "report_integrity": "missing_record",
            "evidence": [],
        }
        for edge in sorted(outgoing.get(node.id, []), key=lambda item: item.id):
            target = nodes.get(edge.target)
            reference = edge.attributes.get("reference_status", "matched_metadata")
            if edge.relation == "declares_procedure" and target is not None:
                summary["procedure_id"] = target.attributes.get("declared_procedure_id")
                summary["scope"] = target.attributes.get("declared_scope")
            elif edge.relation == "preserved_report":
                summary["report_artifact_id"] = _identity(edge.target)
                summary["report_integrity"] = _integrity(target, reference)
            elif edge.relation == "uses_evidence":
                summary["evidence"].append(
                    {
                        "evidence_id": edge.attributes.get("evidence_id"),
                        "artifact_id": _identity(edge.target),
                        "kind": edge.attributes.get("expected_kind"),
                        "integrity": _integrity(target, reference),
                    }
                )
        summary["evidence"].sort(key=lambda item: str(item["evidence_id"]))
        summaries.append(summary)

    summaries.sort(key=lambda item: str(item["publication_id"]))
    summaries.sort(key=lambda item: str(item["published_at"]), reverse=True)
    return summaries


def list_publications(root: Path, *, limit: int = 200) -> dict[str, Any]:
    projection = _project(root, limit)
    return {
        "observed_at": projection.observed_at,
        "complete": projection.complete,
        "consistent": projection.consistent,
        "journal": projection.journal,
        "publications": _summaries(projection),
        "diagnostics": projection.diagnostics,
        "limitations": VIEW_LIMITATIONS,
    }


def _report(root: Path, summary: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    if summary["report_integrity"] != "matched":
        return str(summary["report_integrity"]), None
    try:
        vault = LocalEvidenceVault(root, readonly=True)
        record = vault.get(str(summary["report_artifact_id"]))
    except (VaultError, sqlite3.Error, OSError):
        return "missing_record", None
    if record.kind != "assessment-report":
        return "not_an_assessment_report", None
    status, data = vault.read_verified(record, max_bytes=MAX_REPORT_BYTES)
    if data is None:
        return status, None
    try:
        report = AssessmentReport.model_validate_json(data)
    except ValidationError:
        return "invalid_report", None
    return "matched", report.model_dump(
        mode="json",
        include={
            "schema_version",
            "assessment_id",
            "evaluated_at",
            "procedure",
            "observations",
            "artifact_checks",
            "freshness_checks",
            "scope_confirmed",
            "coverage_complete",
            "verdict",
            "reasons",
            "limitations",
        },
    )


def publication_detail(
    root: Path, publication_id: str, *, limit: int = 200
) -> dict[str, Any] | None:
    projection = _project(root, limit)
    summary = next(
        (
            item
            for item in _summaries(projection)
            if item["publication_id"] == publication_id
        ),
        None,
    )
    if summary is None:
        return None
    status, report = _report(root, summary)
    return {
        "observed_at": projection.observed_at,
        "publication": summary,
        "report_status": status,
        "report": report,
        "stored_verdict_matches_report": (
            None if report is None else report["verdict"] == summary["stored_verdict"]
        ),
        "journal": projection.journal,
        "diagnostics": projection.diagnostics,
        "limitations": VIEW_LIMITATIONS,
    }
