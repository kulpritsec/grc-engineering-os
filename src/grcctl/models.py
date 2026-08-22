from datetime import datetime

from pydantic import BaseModel, Field


class PlatformInfo(BaseModel):
    operating_system: str
    version: str
    architecture: str
    kernel: str


class ToolStatus(BaseModel):
    name: str
    available: bool
    version: str | None = None
    path: str | None = None


class ResourceInfo(BaseModel):
    logical_cpus: int
    memory_total_bytes: int
    disk_total_bytes: int
    disk_available_bytes: int


class DoctorEvidence(BaseModel):
    schema_version: str = "0.1.0"
    assessment_type: str = "system-baseline"
    collected_at: datetime
    platform: PlatformInfo
    resources: ResourceInfo
    tools: list[ToolStatus]
    podman_rootless: bool
    ready: bool
    provenance: dict[str, str]
    evidence_hash: str = Field(default="")


class EvidenceVerification(BaseModel):
    evidence_path: str
    schema_valid: bool
    integrity_valid: bool
    valid: bool
    stored_hash: str | None = None
    calculated_hash: str | None = None
    error: str | None = None
