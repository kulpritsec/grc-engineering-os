"""Offline verification with external anchors; no producer or database imports."""

import hashlib
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .codec import ManifestError, parse_contract, read_bounded, signing_bytes
from .models import (
    ManifestCheck,
    SignedManifest,
    TrustPolicy,
    VerificationContext,
    utc_time,
)


def verify_manifest(
    raw: bytes,
    trust: bytes | None,
    artifact_paths: Mapping[str, Path],
    *,
    context: VerificationContext,
    verified_at: str,
) -> ManifestCheck:
    """Authenticate only when every independent check matches supplied policy."""
    values = ManifestCheck(verified_at=verified_at).model_dump()
    problems: list[str] = []
    try:
        now = utc_time(verified_at)
        context = VerificationContext.model_validate(context.model_dump(mode="json"))
        manifest = parse_contract(raw, SignedManifest)
    except (ManifestError, ValueError) as exc:
        return ManifestCheck(
            verified_at=verified_at, structure="invalid", problems=[str(exc)]
        )
    payload = manifest.payload
    values.update(
        structure="valid",
        manifest_id=payload.manifest_id,
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
    )
    values["context"] = (
        "matched"
        if (payload.execution_id, payload.scope, payload.assessment)
        == (context.execution_id, context.scope, context.assessment)
        else "mismatch"
    )
    if values["context"] != "matched":
        problems.append("Expected execution/scope/assessment context differs.")
    try:
        if trust is None:
            raise ManifestError("External trust policy is required.")
        policy = parse_contract(trust, TrustPolicy)
        values.update(
            trust_policy_sha256=hashlib.sha256(trust).hexdigest(),
            trust_updated_at=policy.updated_at,
        )
        anchor = next(
            (
                item
                for item in policy.anchors
                if (item.collector_id, item.key_id)
                == (payload.collector_id, payload.key_id)
            ),
            None,
        )
        if anchor is None:
            raise ManifestError("Collector/key has no external trust anchor.")
        collected = utc_time(payload.collected_at)
        authorized = (
            utc_time(policy.updated_at) <= now < utc_time(policy.expires_at)
            and not anchor.revoked
            and anchor.purpose == payload.purpose
            and payload.scope in anchor.scopes
            and utc_time(anchor.valid_from) <= collected <= now
            and utc_time(anchor.valid_from) <= now < utc_time(anchor.valid_until)
            and (now - collected).total_seconds() <= policy.max_collection_age_seconds
        )
        values["identity_policy"] = "authorized" if authorized else "rejected"
        if not authorized:
            problems.append(
                "Key/scope/revocation/collection age/trust-policy time rejected."
            )
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(anchor.public_key)).verify(
                bytes.fromhex(manifest.signature), signing_bytes(payload)
            )
            values["signature"] = "valid"
        except InvalidSignature:
            values["signature"] = "invalid"
            problems.append("Signature does not match the external anchor.")
        except UnsupportedAlgorithm:
            values["signature"] = "unsupported"
            problems.append("Ed25519 is unavailable in this cryptographic backend.")
    except (ManifestError, ValueError) as exc:
        values["identity_policy"] = "untrusted"
        problems.append(str(exc))

    checks: dict[str, str] = {}
    for artifact in payload.artifacts:
        path = artifact_paths.get(artifact.artifact_id)
        if path is None:
            checks[artifact.artifact_id] = "missing"
        else:
            try:
                # Per-artifact read limit also bounds growth. Total declarations are
                # capped by schema; read at most declared bytes plus one per object.
                content = read_bounded(path, artifact.size_bytes)
                checks[artifact.artifact_id] = (
                    "matched"
                    if len(content) == artifact.size_bytes
                    and hashlib.sha256(content).hexdigest() == artifact.sha256
                    else "mismatch"
                )
            except ManifestError:
                checks[artifact.artifact_id] = "unavailable_or_unsafe"
        if checks[artifact.artifact_id] != "matched":
            problems.append(
                f"Artifact {artifact.artifact_id}: {checks[artifact.artifact_id]}."
            )
    values["artifacts"] = checks
    values["problems"] = problems
    values["authenticated"] = not problems
    return ManifestCheck.model_validate(values)
