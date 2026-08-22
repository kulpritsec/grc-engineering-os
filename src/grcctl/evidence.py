import hmac
import json
from pathlib import Path

from pydantic import ValidationError

from .doctor import hash_payload
from .models import DoctorEvidence, EvidenceVerification


def verify_evidence_file(path: Path) -> EvidenceVerification:
    if not path.is_file():
        return EvidenceVerification(
            evidence_path=str(path),
            schema_valid=False,
            integrity_valid=False,
            valid=False,
            error="Evidence file does not exist.",
        )

    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return EvidenceVerification(
            evidence_path=str(path),
            schema_valid=False,
            integrity_valid=False,
            valid=False,
            error=f"Unable to read evidence: {exc}",
        )

    if not isinstance(loaded, dict):
        return EvidenceVerification(
            evidence_path=str(path),
            schema_valid=False,
            integrity_valid=False,
            valid=False,
            error="Evidence must be a JSON object.",
        )

    stored_hash = loaded.get("evidence_hash")

    if not isinstance(stored_hash, str):
        return EvidenceVerification(
            evidence_path=str(path),
            schema_valid=False,
            integrity_valid=False,
            valid=False,
            error="Evidence hash is missing or invalid.",
        )

    payload = dict(loaded)
    payload.pop("evidence_hash", None)
    calculated_hash = hash_payload(payload)

    schema_valid = True
    error = None

    try:
        if loaded.get("assessment_type") == "system-baseline":
            DoctorEvidence.model_validate(loaded)
        else:
            schema_valid = False
            error = "Unsupported evidence assessment type."
    except ValidationError as exc:
        schema_valid = False
        error = f"Evidence schema validation failed: {exc}"

    integrity_valid = hmac.compare_digest(
        stored_hash,
        calculated_hash,
    )

    return EvidenceVerification(
        evidence_path=str(path),
        schema_valid=schema_valid,
        integrity_valid=integrity_valid,
        valid=schema_valid and integrity_valid,
        stored_hash=stored_hash,
        calculated_hash=calculated_hash,
        error=error,
    )
