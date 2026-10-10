"""Minimal contract for a scoped Control Verification Procedure (CVP)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

ObservationOutcome = Literal["pass", "fail", "unknown"]
AssuranceVerdict = Literal["verified", "failed", "inconclusive", "not_tested"]


class ControlVerificationProcedure(BaseModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    assertion: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    required_check_ids: list[str] = Field(min_length=1)
    required_evidence_kinds: list[str] = Field(min_length=1)


class ArtifactReference(BaseModel):
    id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    relative_path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Observation(BaseModel):
    check_id: str = Field(min_length=1)
    outcome: ObservationOutcome
    evidence_ids: list[str] = Field(default_factory=list)
    detail: str = ""


class AssessmentInput(BaseModel):
    assessment_id: str = Field(min_length=1)
    procedure: ControlVerificationProcedure
    observations: list[Observation]
    evidence: list[ArtifactReference]
    scope_confirmed: bool = False
    coverage_complete: bool = False


class AssessmentReport(BaseModel):
    schema_version: str = "0.1.0"
    assessment_type: Literal["cvp-evaluation"] = "cvp-evaluation"
    assessment_id: str
    evaluated_at: datetime
    procedure: ControlVerificationProcedure
    observations: list[Observation]
    evidence: list[ArtifactReference]
    artifact_checks: dict[str, str]
    scope_confirmed: bool
    coverage_complete: bool
    verdict: AssuranceVerdict
    reasons: list[str]
    limitations: list[str] = Field(default_factory=list)
    evidence_hash: str = ""
