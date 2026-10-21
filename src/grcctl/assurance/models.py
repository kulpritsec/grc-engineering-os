"""Minimal contract for a scoped Control Verification Procedure (CVP)."""

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    Field,
    StrictInt,
    field_validator,
    model_validator,
)

ObservationOutcome = Literal["pass", "fail", "unknown"]
AssuranceVerdict = Literal["verified", "failed", "inconclusive", "not_tested"]
FreshnessStatus = Literal[
    "fresh",
    "stale",
    "no_policy",
    "not_checked",
    "unknown_collection_time",
    "future_timestamp",
    "collected_after_ingestion",
    "invalid_ingestion_time",
]

# Ten years of 365 days; longer windows are not a meaningful freshness policy.
MAX_EVIDENCE_AGE_SECONDS = 315_360_000


class ControlVerificationProcedure(BaseModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    assertion: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    required_check_ids: list[str] = Field(min_length=1)
    required_evidence_kinds: list[str] = Field(min_length=1)
    # Required for a verified or failed verdict; None means not evaluated.
    max_evidence_age_seconds: (
        Annotated[StrictInt, Field(gt=0, le=MAX_EVIDENCE_AGE_SECONDS)] | None
    ) = None


class ArtifactReference(BaseModel):
    """One evidence identity bound to either a local file or a vault record."""

    id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    relative_path: str | None = Field(default=None, min_length=1)
    vault_artifact_id: str | None = Field(default=None, min_length=1)
    # Caller-declared collection time; a claim, not a trusted timestamp.
    collected_at: AwareDatetime | None = None

    @field_validator("collected_at", mode="before")
    @classmethod
    def timestamp_text(cls, value: object) -> object:
        if value is not None and not isinstance(value, str | datetime):
            raise ValueError("collected_at must be an ISO 8601 timestamp string.")
        return value

    @field_validator("collected_at")
    @classmethod
    def normalize_utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def exactly_one_source(self) -> "ArtifactReference":
        if (self.relative_path is None) == (self.vault_artifact_id is None):
            raise ValueError(
                "Provide exactly one of relative_path or vault_artifact_id."
            )
        return self


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
    schema_version: str = "0.2.0"
    assessment_type: Literal["cvp-evaluation"] = "cvp-evaluation"
    assessment_id: str
    evaluated_at: datetime
    procedure: ControlVerificationProcedure
    observations: list[Observation]
    evidence: list[ArtifactReference]
    artifact_checks: dict[str, str]
    # Absent from schema 0.1.0 reports, which never evaluated freshness.
    freshness_checks: dict[str, str] = Field(default_factory=dict)
    scope_confirmed: bool
    coverage_complete: bool
    verdict: AssuranceVerdict
    reasons: list[str]
    limitations: list[str] = Field(default_factory=list)
    evidence_hash: str = ""
