"""Deterministic CVP evaluation. Hash checks are not origin attestations."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from ..doctor import hash_payload
from ..vault import LocalEvidenceVault, VaultError
from .models import (
    ArtifactReference,
    AssessmentInput,
    AssessmentReport,
    AssuranceVerdict,
    FreshnessStatus,
)


class AssessmentInputError(ValueError):
    """Invalid assessment input or unsafe workspace location."""


def _artifact_status(root: Path, relative_path: str, expected_hash: str) -> str:
    """Read only regular files confined to the assessment input directory."""
    requested = Path(relative_path)
    if requested.is_absolute():
        return "unsafe_path"
    candidate = (root / requested).resolve()
    if not candidate.is_relative_to(root.resolve()):
        return "unsafe_path"
    if not candidate.is_file():
        return "missing"
    actual_hash = hashlib.sha256(candidate.read_bytes()).hexdigest()
    return "matched" if actual_hash == expected_hash else "hash_mismatch"


def _evidence_status(
    evidence: ArtifactReference, workspace: Path, vault_root: Path | None
) -> tuple[str, str | None]:
    """Validate local bytes or resolve a specific vault record by UUID.

    Returns the byte status and, for vault records, the stored ingestion time.
    """
    if evidence.relative_path is not None:
        status = _artifact_status(workspace, evidence.relative_path, evidence.sha256)
        return status, None

    if vault_root is None:
        return "vault_not_configured", None

    # Lookup must not silently initialize a new store at a misspelled location.
    if not vault_root.is_dir() or not (vault_root / "vault.db").is_file():
        return "vault_missing", None

    try:
        vault = LocalEvidenceVault(vault_root)
        artifact_id = evidence.vault_artifact_id
        if artifact_id is None:
            return "invalid_source", None
        record = vault.get(artifact_id)
        if record.sha256 != evidence.sha256 or record.kind != evidence.kind:
            return "metadata_mismatch", None
        return vault.verify(record.artifact_id).status, record.ingested_at
    except (VaultError, OSError):
        return "vault_reference_invalid", None


def _parse_ingested_at(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _freshness_status(
    evidence: ArtifactReference,
    byte_status: str,
    ingested_at: str | None,
    max_age_seconds: int | None,
    at: datetime,
) -> FreshnessStatus:
    """Bound evidence age by the earliest known collection or ingestion time.

    Collection cannot follow ingestion, so an old ingestion proves staleness
    regardless of a later declared collection time. Neither time is trusted.
    """
    if byte_status != "matched":
        return "not_checked"
    if max_age_seconds is None:
        return "no_policy"
    ingested = None
    if ingested_at is not None:
        ingested = _parse_ingested_at(ingested_at)
        if ingested is None:
            return "invalid_ingestion_time"
    collected = evidence.collected_at
    known = [value for value in (collected, ingested) if value is not None]
    if any(value > at for value in known):
        return "future_timestamp"
    if collected is not None and ingested is not None and collected > ingested:
        return "collected_after_ingestion"
    if known and at - min(known) > timedelta(seconds=max_age_seconds):
        return "stale"
    if collected is None:
        return "unknown_collection_time"
    return "fresh"


def evaluate_assessment(
    assessment: AssessmentInput,
    workspace: Path,
    vault_root: Path | None = None,
    *,
    at: datetime | None = None,
) -> AssessmentReport:
    """Verify a bounded assertion, never an organization's overall compliance."""
    if at is None:
        at = datetime.now(UTC)
    elif at.tzinfo is None:
        raise AssessmentInputError("Evaluation time must include a timezone.")
    reasons: list[str] = []
    ids = [artifact.id for artifact in assessment.evidence]
    checks = [observation.check_id for observation in assessment.observations]
    if len(ids) != len(set(ids)) or len(checks) != len(set(checks)):
        raise AssessmentInputError(
            "Evidence IDs and observation check IDs must be unique."
        )
    if len(set(assessment.procedure.required_check_ids)) != len(
        assessment.procedure.required_check_ids
    ):
        raise AssessmentInputError("Required check IDs must be unique.")
    max_age = assessment.procedure.max_evidence_age_seconds
    artifact_status: dict[str, str] = {}
    freshness: dict[str, str] = {}
    for evidence in assessment.evidence:
        status, ingested_at = _evidence_status(evidence, workspace, vault_root)
        artifact_status[evidence.id] = status
        freshness[evidence.id] = _freshness_status(
            evidence, status, ingested_at, max_age, at
        )
    evidence_by_id = {artifact.id: artifact for artifact in assessment.evidence}
    observations = {obs.check_id: obs for obs in assessment.observations}

    if not assessment.scope_confirmed:
        reasons.append("Assessment scope was not confirmed by the caller.")
    if not assessment.coverage_complete:
        reasons.append("Assessment coverage is incomplete or unconfirmed.")
    if max_age is None:
        reasons.append(
            "Procedure declares no evidence freshness policy; "
            "freshness was not evaluated."
        )
    for eid, status in artifact_status.items():
        if status != "matched":
            reasons.append(f"Evidence {eid}: {status}.")
        elif freshness[eid] not in {"fresh", "no_policy"}:
            reasons.append(f"Evidence {eid}: {freshness[eid]}.")
    verified_obs = []
    for observation in assessment.observations:
        referenced = observation.evidence_ids
        trusted = bool(referenced) and all(
            artifact_status.get(ref) == "matched" and freshness.get(ref) == "fresh"
            for ref in referenced
        )
        verified_obs.append((observation, trusted))
        if not trusted:
            reasons.append(
                f"Observation {observation.check_id} lacks matching, fresh evidence."
            )

    missing_checks = set(assessment.procedure.required_check_ids) - set(observations)
    for check_id in sorted(missing_checks):
        reasons.append(f"Required check {check_id} is missing.")
    present_kinds = {
        evidence_by_id[ref].kind
        for obs, trusted in verified_obs
        if trusted
        for ref in obs.evidence_ids
    }
    for kind in sorted(
        set(assessment.procedure.required_evidence_kinds) - present_kinds
    ):
        reasons.append(f"Required evidence kind {kind} is missing.")

    verdict: AssuranceVerdict
    if not assessment.observations:
        verdict = "not_tested"
        reasons.append("No checks have been executed.")
    elif assessment.scope_confirmed and any(
        obs.outcome == "fail" and trusted for obs, trusted in verified_obs
    ):
        verdict = "failed"
        reasons.append("An evidenced, scoped control check failed.")
    elif reasons or any(obs.outcome != "pass" for obs in assessment.observations):
        verdict = "inconclusive"
        if not reasons:
            reasons.append("At least one observation is unknown.")
    else:
        verdict = "verified"
        reasons.append(
            "All required checks passed with matching, fresh local evidence."
        )

    report = AssessmentReport(
        assessment_id=assessment.assessment_id,
        evaluated_at=at,
        procedure=assessment.procedure,
        observations=assessment.observations,
        evidence=assessment.evidence,
        artifact_checks=artifact_status,
        freshness_checks=freshness,
        scope_confirmed=assessment.scope_confirmed,
        coverage_complete=assessment.coverage_complete,
        verdict=verdict,
        reasons=reasons,
        limitations=[
            (
                "Evidence hashes verify local byte consistency only, "
                "not source authenticity."
            ),
            "Caller-supplied scope confirmation is not an authorization mechanism.",
            (
                "Evidence age uses caller-declared collection and host ingestion "
                "times; these are not trusted time sources."
            ),
            (
                "Verification applies only to the named assertion, checks "
                "and time of evaluation."
            ),
        ],
    )
    report.evidence_hash = hash_payload(
        report.model_dump(mode="json", exclude={"evidence_hash"})
    )
    return report


def evaluate_file(
    input_path: Path, output_path: Path, vault_root: Path | None = None
) -> AssessmentReport:
    """Read a local JSON specification and preserve the resulting bounded assessment."""
    try:
        raw = json.loads(input_path.read_text(encoding="utf-8"))
        assessment = AssessmentInput.model_validate(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise AssessmentInputError(f"Invalid assessment input: {exc}") from exc
    report = evaluate_assessment(assessment, input_path.parent, vault_root)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    output_path.chmod(0o600)
    return report
