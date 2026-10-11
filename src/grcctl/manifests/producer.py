"""Synthetic local signer. Production key lifecycle is deliberately absent."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .codec import signing_bytes
from .models import ManifestPayload, SignedManifest


def sign_manifest(payload: ManifestPayload, key: Ed25519PrivateKey) -> SignedManifest:
    # The verifier never imports this module or needs access to this key.
    payload = ManifestPayload.model_validate(payload.model_dump(mode="json"))
    return SignedManifest(
        payload=payload, signature=key.sign(signing_bytes(payload)).hex()
    )
