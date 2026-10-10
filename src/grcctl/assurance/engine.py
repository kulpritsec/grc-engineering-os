"""Deterministic CVP evaluation. Hash checks are not origin attestations."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from ..doctor import hash_payload
from .models import AssessmentInput, AssessmentReport, AssuranceVerdict


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


def evaluate_assessment(
    assessment: AssessmentInput, workspace: Path
) -> AssessmentReport:
    """Verify a bounded assertion, never an organization's overall compliance."""
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
    artifact_status = {
        evidence.id: _artifact_status(
            workspace, evidence.relative_path, evidence.sha256
        )
        for evidence in assessment.evidence
    }
    evidence_by_id = {artifact.id: artifact for artifact in assessment.evidence}
    observations = {obs.check_id: obs for obs in assessment.observations}

    if not assessment.scope_confirmed:
        reasons.append("Assessment scope was not confirmed by the caller.")
    if not assessment.coverage_complete:
        reasons.append("Assessment coverage is incomplete or unconfirmed.")
    for eid, status in artifact_status.items():
        if status != "matched":
            reasons.append(f"Evidence {eid}: {status}.")
    verified_obs = []
    for observation in assessment.observations:
        referenced = observation.evidence_ids
        trusted = bool(referenced) and all(
            artifact_status.get(ref) == "matched" for ref in referenced
        )
        verified_obs.append((observation, trusted))
        if not trusted:
            reasons.append(
                f"Observation {observation.check_id} lacks matching evidence."
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
    elif (
        assessment.scope_confirmed
        and any(obs.outcome == "fail" and trusted for obs, trusted in verified_obs)
    ):
        verdict = "failed"
        reasons.append("An evidenced, scoped control check failed.")
    elif reasons or any(obs.outcome != "pass" for obs in assessment.observations):
        verdict = "inconclusive"
        if not reasons:
            reasons.append("At least one observation is unknown.")
    else:
        verdict = "verified"
        reasons.append("All required checks passed with matching local evidence.")

    report = AssessmentReport(
        assessment_id=assessment.assessment_id,
        evaluated_at=datetime.now(UTC),
        procedure=assessment.procedure,
        observations=assessment.observations,
        evidence=assessment.evidence,
        artifact_checks=artifact_status,
        scope_confirmed=assessment.scope_confirmed,
        coverage_complete=assessment.coverage_complete,
        verdict=verdict,
        reasons=reasons,
        limitations=[
            "Evidence hashes verify local byte consistency only, "
            "not source authenticity.",
            "Caller-supplied scope confirmation is not an authorization mechanism.",
            "Verification applies only to the named assertion, checks "
            "and time of evaluation.",
        ],
    )
    report.evidence_hash = hash_payload(
        report.model_dump(mode="json", exclude={"evidence_hash"})
    )
    return report


def evaluate_file(input_path: Path, output_path: Path) -> AssessmentReport:
    """Read a local JSON specification and preserve the resulting bounded assessment."""
    try:
        raw = json.loads(input_path.read_text(encoding="utf-8"))
        assessment = AssessmentInput.model_validate(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise AssessmentInputError(f"Invalid assessment input: {exc}") from exc
    report = evaluate_assessment(assessment, input_path.parent)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    output_path.chmod(0o600)
    return report
