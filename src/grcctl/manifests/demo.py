"""Reproducible local workflow using synthetic bytes and an ephemeral key."""

import hashlib
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..vault import LocalEvidenceVault
from .codec import ManifestError
from .models import (
    ManifestArtifact,
    ManifestPayload,
    TrustAnchor,
    TrustPolicy,
    VerificationContext,
    utc_time,
)
from .producer import sign_manifest


def create_demo(output: Path, at: str) -> None:
    now = utc_time(at)
    if output.exists():
        raise ManifestError("Demo output must be a new directory.")
    output.mkdir(parents=True, mode=0o700)
    vault = LocalEvidenceVault(output / "vault")
    source = output / "synthetic.txt"
    content = b"synthetic collection observation\n"
    source.write_bytes(content)
    source.chmod(0o600)
    artifact = vault.ingest(source, kind="test-result")
    bundle = output / "bundle"
    bundle.mkdir(mode=0o700)
    (bundle / artifact.artifact_id).write_bytes(content)
    (bundle / artifact.artifact_id).chmod(0o600)
    key = Ed25519PrivateKey.generate()
    payload = ManifestPayload(
        schema_version="1",
        algorithm="Ed25519",
        purpose="evidence-collection",
        manifest_id=str(uuid4()),
        execution_id="synthetic-execution-1",
        collector_id="synthetic-collector",
        collector_version="demo-1",
        key_id="synthetic-key",
        scope="isolated-demo",
        collected_at=at,
        artifacts=[
            ManifestArtifact(
                artifact_id=artifact.artifact_id,
                kind=artifact.kind,
                sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content),
            )
        ],
        assessment=None,
    )
    policy = TrustPolicy(
        schema_version="1",
        updated_at=at,
        expires_at=(now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        max_collection_age_seconds=3600,
        anchors=[
            TrustAnchor(
                collector_id=payload.collector_id,
                key_id=payload.key_id,
                public_key=key.public_key().public_bytes_raw().hex(),
                purpose="evidence-collection",
                scopes=[payload.scope],
                valid_from=at,
                valid_until=(now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                revoked=False,
            )
        ],
    )
    context = VerificationContext(
        execution_id=payload.execution_id, scope=payload.scope, assessment=None
    )
    for name, model in (
        ("manifest.json", sign_manifest(payload, key)),
        ("trust.json", policy),
        ("context.json", context),
    ):
        path = output / name
        path.write_text(model.model_dump_json(indent=2) + "\n", encoding="utf-8")
        path.chmod(0o600)
    source.unlink()
    # No private key is serialized. The generated trust file is a demo fixture,
    # not independent real-world identity enrollment.
