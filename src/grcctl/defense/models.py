"""Normalized, bounded observations for the Agentic Defense development MVP."""

from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Literal

from pydantic import AwareDatetime, BaseModel, Field, field_validator

Source = Literal["artex", "suricata", "wazuh"]
EventKind = Literal["execution", "approval", "network", "alert", "endpoint"]


class DefenseEvent(BaseModel):
    """An observation, not an attested fact or control verdict."""

    id: str = Field(min_length=1)
    source: Source
    kind: EventKind
    observed_at: AwareDatetime
    source_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_line: int = Field(ge=1)
    source_record_id: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = Field(default=None, ge=1, le=65535)
    requested_ports: list[int] = Field(default_factory=list)
    description: str = ""
    rule_id: str | None = None

    @field_validator("src_ip", "dest_ip")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        if value is not None:
            return str(ip_address(value))
        return None

    @field_validator("requested_ports")
    @classmethod
    def validate_ports(cls, values: list[int]) -> list[int]:
        if any(not 1 <= port <= 65535 for port in values):
            raise ValueError("requested_ports must be valid TCP/UDP port numbers")
        return sorted(set(values))

    @field_validator("observed_at")
    @classmethod
    def normalize_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)


class SourceDigest(BaseModel):
    source: Source
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    records: int = Field(ge=0)


class Correlation(BaseModel):
    action_event_id: str
    candidate_event_ids: list[str]
    candidate_alert_ids: list[str]
    attribution: Literal["candidate", "not_observed"]
    conclusion: Literal["inconclusive"] = "inconclusive"
    reason: str


class DefenseReport(BaseModel):
    schema_version: Literal["0.1.0"] = "0.1.0"
    assessment_type: Literal["defense-correlation"] = "defense-correlation"
    generated_at: AwareDatetime
    window_seconds: int = Field(ge=1, le=3600)
    source_digests: list[SourceDigest]
    event_counts: dict[str, int]
    correlations: list[Correlation]
    limitations: list[str] = Field(default_factory=list)
    evidence_hash: str = ""
