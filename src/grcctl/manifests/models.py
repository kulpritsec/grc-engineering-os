"""Strict, bounded contracts for the local Ed25519 evidence profile v1."""

import re
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Token = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[ -~]+$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identity = Annotated[
    str,
    Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
]
Timestamp = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")]
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_BYTES = 256 * 1024 * 1024


def utc_time(value: str) -> datetime:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ValueError("Time must use YYYY-MM-DDTHH:MM:SSZ UTC syntax.")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ManifestArtifact(Contract):
    artifact_id: Identity
    kind: Annotated[str, Field(pattern=r"^[a-z][a-z0-9.-]{0,63}$")]
    sha256: Digest
    size_bytes: Annotated[int, Field(ge=0, le=MAX_ARTIFACT_BYTES)]


class AssessmentContext(Contract):
    assessment_id: Token
    procedure_id: Token
    report_sha256: Digest


class ManifestPayload(Contract):
    schema_version: Literal["1"]
    algorithm: Literal["Ed25519"]
    purpose: Literal["evidence-collection"]
    manifest_id: Identity
    execution_id: Token
    collector_id: Token
    collector_version: Token
    key_id: Token
    scope: Token
    collected_at: Timestamp
    artifacts: Annotated[list[ManifestArtifact], Field(min_length=1, max_length=64)]
    assessment: AssessmentContext | None

    @model_validator(mode="after")
    def valid_collection(self) -> "ManifestPayload":
        utc_time(self.collected_at)
        ids = [item.artifact_id for item in self.artifacts]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate artifact ingestion identity.")
        if sum(item.size_bytes for item in self.artifacts) > MAX_BUNDLE_BYTES:
            raise ValueError("Bundle exceeds total byte budget.")
        return self


class SignedManifest(Contract):
    payload: ManifestPayload
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


class TrustAnchor(Contract):
    collector_id: Token
    key_id: Token
    public_key: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    purpose: Literal["evidence-collection"]
    scopes: Annotated[list[Token], Field(min_length=1, max_length=64)]
    valid_from: Timestamp
    valid_until: Timestamp
    revoked: bool

    @model_validator(mode="after")
    def valid_interval(self) -> "TrustAnchor":
        if utc_time(self.valid_from) >= utc_time(self.valid_until):
            raise ValueError("Invalid key validity interval.")
        if len(set(self.scopes)) != len(self.scopes):
            raise ValueError("Duplicate authorized scope.")
        return self


class TrustPolicy(Contract):
    schema_version: Literal["1"]
    updated_at: Timestamp
    expires_at: Timestamp
    max_collection_age_seconds: Annotated[int, Field(ge=1, le=31536000)]
    anchors: Annotated[list[TrustAnchor], Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def valid_policy(self) -> "TrustPolicy":
        if utc_time(self.updated_at) >= utc_time(self.expires_at):
            raise ValueError("Invalid trust-policy validity interval.")
        ids = [(item.collector_id, item.key_id) for item in self.anchors]
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate collector/key binding.")
        return self


class VerificationContext(Contract):
    execution_id: Token
    scope: Token
    assessment: AssessmentContext | None


class ManifestCheck(Contract):
    authenticated: bool = False
    manifest_id: str | None = None
    manifest_sha256: str | None = None
    retained_manifest_id: str | None = None
    retained_trust_id: str | None = None
    structure: str = "not_checked"
    signature: str = "not_checked"
    identity_policy: str = "not_checked"
    artifacts: dict[str, str] = Field(default_factory=dict)
    context: str = "not_checked"
    replay: str = "unavailable"
    verified_at: str
    trust_policy_sha256: str | None = None
    trust_updated_at: str | None = None
    problems: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Signing authenticates a statement within supplied trust policy, not observation truth.",
            "Collection and verification times rely on caller/host clocks, not trusted timestamps.",
            "Offline revocation is only as current as the separately supplied trust policy.",
            "Stateless verification cannot detect replay or local history rollback.",
            "No production key custody, enrollment, FIPS or compliance certification.",
        ]
    )
