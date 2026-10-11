"""Ground-truth and adversarial criteria for collection statement authentication.

Golden payload/signature was frozen using PyNaCl/libsodium, without importing
the project's producer/codec. RFC 8032 section 7.1 key is PUBLIC TEST DATA.
"""

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from typer.testing import CliRunner

from grcctl.cli import app
from grcctl.manifests.codec import (
    DOMAIN,
    MAX_JSON_BYTES,
    ManifestError,
    canonical_payload,
    parse_contract,
    read_bounded,
)
from grcctl.manifests.models import ManifestPayload, SignedManifest, VerificationContext
from grcctl.manifests.producer import sign_manifest
from grcctl.manifests.store import consume_file
from grcctl.manifests.verifier import verify_manifest

FIXTURES = Path(__file__).parent / "fixtures" / "manifests"
# Public test-only seed from https://www.rfc-editor.org/rfc/rfc8032#section-7.1
TEST_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
AT = "2026-10-10T12:01:00Z"
ARTIFACT_ID = "11111111-1111-4111-8111-111111111111"
CONTEXT = VerificationContext(
    execution_id="synthetic-execution", scope="sandbox", assessment=None
)


def encoded(value):
    return json.dumps(value).encode()


def signed(payload):
    return (
        sign_manifest(
            ManifestPayload.model_validate(payload),
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(TEST_SEED)),
        )
        .model_dump_json()
        .encode()
    )


@pytest.fixture
def bundle(tmp_path):
    source = tmp_path / ARTIFACT_ID
    source.write_bytes(b"synthetic\n")
    return {
        "raw": (FIXTURES / "signed.json").read_bytes(),
        "trust": (FIXTURES / "trust.json").read_bytes(),
        "artifact_paths": {ARTIFACT_ID: source},
        "context": CONTEXT,
        "verified_at": AT,
    }


def test_rfc8032_independent_empty_message_vector():
    public = bytes.fromhex(
        json.loads((FIXTURES / "trust.json").read_bytes())["anchors"][0]["public_key"]
    )
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    Ed25519PublicKey.from_public_bytes(public).verify(signature, b"")
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(public).verify(signature, b"changed")


def test_golden_bytes_producer_and_independent_verifier(bundle):
    envelope = parse_contract(bundle["raw"], SignedManifest)
    assert (
        canonical_payload(envelope.payload) == (FIXTURES / "canonical.bin").read_bytes()
    )
    assert signed(envelope.payload.model_dump()) == envelope.model_dump_json().encode()
    result = verify_manifest(**bundle)
    assert result.authenticated
    assert (result.signature, result.identity_policy, result.context) == (
        "valid",
        "authorized",
        "matched",
    )
    assert result.replay == "unavailable"
    assert result.trust_policy_sha256 == hashlib.sha256(bundle["trust"]).hexdigest()


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "2"),
        ("algorithm", "RSA"),
        ("purpose", "assessment"),
        ("manifest_id", "33333333-3333-4333-8333-333333333333"),
        ("execution_id", "replayed-execution"),
        ("collector_id", "other"),
        ("collector_version", "fixture-2"),
        ("key_id", "other-key"),
        ("scope", "elsewhere"),
        ("collected_at", "2026-10-10T12:00:01Z"),
        (
            "assessment",
            {"assessment_id": "A", "procedure_id": "P", "report_sha256": "0" * 64},
        ),
    ],
)
def test_every_top_level_signed_field_tamper_rejected(bundle, field, value):
    data = json.loads(bundle["raw"])
    data["payload"][field] = value
    bundle["raw"] = encoded(data)
    assert not verify_manifest(**bundle).authenticated


@pytest.mark.parametrize(
    "field,value",
    [
        ("artifact_id", "44444444-4444-4444-8444-444444444444"),
        ("kind", "other-kind"),
        ("sha256", "0" * 64),
        ("size_bytes", 9),
    ],
)
def test_every_artifact_field_tamper_rejected(bundle, field, value):
    data = json.loads(bundle["raw"])
    data["payload"]["artifacts"][0][field] = value
    bundle["raw"] = encoded(data)
    assert not verify_manifest(**bundle).authenticated


@pytest.mark.parametrize(
    "change",
    [
        "revoked",
        "unknown_collector",
        "unknown_key",
        "wrong_key",
        "scope",
        "expired_key",
        "future_key",
        "expired_policy",
        "future_policy",
        "stale_collection",
    ],
)
def test_external_identity_policy_failures(bundle, change):
    trust = json.loads(bundle["trust"])
    anchor = trust["anchors"][0]
    if change == "revoked":
        anchor["revoked"] = True
    elif change == "unknown_collector":
        anchor["collector_id"] = "other"
    elif change == "unknown_key":
        anchor["key_id"] = "other"
    elif change == "wrong_key":
        anchor["public_key"] = (
            Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        )
    elif change == "scope":
        anchor["scopes"] = ["other"]
    elif change == "expired_key":
        anchor["valid_until"] = AT
    elif change == "future_key":
        anchor["valid_from"] = "2026-10-10T13:00:00Z"
    elif change == "expired_policy":
        trust["expires_at"] = AT
    elif change == "future_policy":
        trust["updated_at"] = "2026-10-10T13:00:00Z"
    elif change == "stale_collection":
        trust["max_collection_age_seconds"] = 59
    bundle["trust"] = encoded(trust)
    assert not verify_manifest(**bundle).authenticated


def test_missing_trust_and_future_collection_do_not_authenticate(bundle):
    bundle["trust"] = None
    assert verify_manifest(**bundle).identity_policy == "untrusted"
    bundle["trust"] = (FIXTURES / "trust.json").read_bytes()
    payload = json.loads(bundle["raw"])["payload"]
    payload["collected_at"] = "2026-10-10T13:00:00Z"
    bundle["raw"] = signed(payload)
    assert not verify_manifest(**bundle).authenticated


@pytest.mark.parametrize("mutation", ["absent", "changed", "grown", "directory"])
def test_artifact_failures(bundle, mutation):
    path = bundle["artifact_paths"][ARTIFACT_ID]
    if mutation == "absent":
        bundle["artifact_paths"] = {}
    elif mutation == "changed":
        path.write_bytes(b"different\n")
    elif mutation == "grown":
        path.write_bytes(b"synthetic\nextra")
    else:
        path.unlink()
        path.mkdir()
    result = verify_manifest(**bundle)
    assert result.signature == "valid"
    assert not result.authenticated


def test_bad_signature_and_domain_substitution(bundle):
    data = json.loads(bundle["raw"])
    data["signature"] = "0" * 128
    bundle["raw"] = encoded(data)
    assert verify_manifest(**bundle).signature == "invalid"
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(TEST_SEED))
    payload = ManifestPayload.model_validate(data["payload"])
    data["signature"] = key.sign(canonical_payload(payload)).hex()
    bundle["raw"] = encoded(data)
    assert verify_manifest(**bundle).signature == "invalid"
    assert DOMAIN.endswith(b"\x00")


@pytest.mark.parametrize(
    "raw",
    [
        b'{"payload": {}, "payload": {}}',
        b'{"signature":NaN}',
        b'{"signature":1.2}',
        b'{"signature":Infinity}',
        b"[]",
        b"null",
        b"\xff",
        b"{" * 2000,
        b" " * (MAX_JSON_BYTES + 1),
    ],
    ids=[
        "duplicate-key",
        "nan",
        "float",
        "infinity",
        "array",
        "null",
        "utf8",
        "depth",
        "oversize",
    ],
)
def test_invalid_or_unbounded_json(bundle, raw):
    bundle["raw"] = raw
    assert verify_manifest(**bundle).structure == "invalid"


@pytest.mark.parametrize(
    "mutation",
    [
        "extra",
        "nested_extra",
        "duplicate_id",
        "negative_size",
        "bool_size",
        "huge_size",
        "non_utc",
        "invalid_date",
        "unicode",
        "missing_version",
        "missing_assessment",
    ],
)
def test_strict_schema_rejects_ambiguous_contract(bundle, mutation):
    data = json.loads(bundle["raw"])
    payload = data["payload"]
    artifact = payload["artifacts"][0]
    if mutation == "extra":
        data["public_key"] = "untrusted"
    elif mutation == "nested_extra":
        artifact["path"] = "../../secret"
    elif mutation == "duplicate_id":
        payload["artifacts"].append(artifact.copy())
    elif mutation == "negative_size":
        artifact["size_bytes"] = -1
    elif mutation == "bool_size":
        artifact["size_bytes"] = True
    elif mutation == "huge_size":
        artifact["size_bytes"] = 64 * 1024 * 1024 + 1
    elif mutation == "non_utc":
        payload["collected_at"] = "2026-10-10T12:00:00+00:00"
    elif mutation == "invalid_date":
        payload["collected_at"] = "2026-02-30T12:00:00Z"
    elif mutation == "unicode":
        payload["scope"] = "sandbox\ud800"
    elif mutation == "missing_version":
        del payload["schema_version"]
    else:
        del payload["assessment"]
    bundle["raw"] = encoded(data)
    assert verify_manifest(**bundle).structure == "invalid"


def test_layout_and_artifact_order_are_canonical(bundle):
    data = json.loads(bundle["raw"])
    bundle["raw"] = json.dumps(data, indent=4, sort_keys=True).encode()
    assert verify_manifest(**bundle).authenticated
    payload = data["payload"]
    second = payload["artifacts"][0].copy()
    second["artifact_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    payload["artifacts"].append(second)
    first_bytes = canonical_payload(ManifestPayload.model_validate(payload))
    payload["artifacts"].reverse()
    assert canonical_payload(ManifestPayload.model_validate(payload)) == first_bytes


def test_context_and_verification_time_are_explicit(bundle):
    bundle["context"] = CONTEXT.model_copy(update={"execution_id": "other"})
    assert verify_manifest(**bundle).context == "mismatch"
    bundle["context"] = CONTEXT
    bundle["verified_at"] = "2026-10-10T12:01:00+00:00"
    assert verify_manifest(**bundle).structure == "invalid"


def test_replay_consumption_and_distinct_collection(bundle, tmp_path):
    registry = tmp_path / "seen.db"
    first = consume_file(registry, verify_manifest(**bundle))
    assert first.authenticated and first.replay == "consumed_locally"
    duplicate = consume_file(registry, verify_manifest(**bundle))
    assert not duplicate.authenticated and duplicate.replay == "duplicate"
    payload = json.loads(bundle["raw"])["payload"]
    payload["manifest_id"] = "33333333-3333-4333-8333-333333333333"
    payload["execution_id"] = "new-execution"
    bundle["context"] = CONTEXT.model_copy(update={"execution_id": "new-execution"})
    bundle["raw"] = signed(payload)
    assert consume_file(registry, verify_manifest(**bundle)).authenticated


def test_failed_checks_do_not_consume_and_corrupt_registry_fails(bundle, tmp_path):
    registry = tmp_path / "seen.db"
    bundle["trust"] = None
    assert not consume_file(registry, verify_manifest(**bundle)).authenticated
    assert not registry.exists()
    bundle["trust"] = (FIXTURES / "trust.json").read_bytes()
    registry.write_bytes(b"not sqlite")
    registry.chmod(0o600)
    with pytest.raises(ManifestError, match="unavailable"):
        consume_file(registry, verify_manifest(**bundle))


def test_symlink_and_unreadable_inputs_rejected(bundle, monkeypatch):
    original = Path.is_symlink
    artifact = bundle["artifact_paths"][ARTIFACT_ID]
    monkeypatch.setattr(Path, "is_symlink", lambda p: p == artifact or original(p))
    assert not verify_manifest(**bundle).authenticated
    with pytest.raises(ManifestError, match="Symbolic"):
        read_bounded(artifact)


def test_cli_demo_verify_replay_tamper_and_link(tmp_path):
    runner = CliRunner()
    output = tmp_path / "demo"
    demo = runner.invoke(app, ["manifest", "demo", str(output), "--at", AT])
    assert demo.exit_code == 0, demo.output
    args = [
        "manifest",
        "verify",
        str(output / "manifest.json"),
        "--trust",
        str(output / "trust.json"),
        "--context",
        str(output / "context.json"),
        "--at",
        AT,
        "--bundle",
        str(output / "bundle"),
    ]
    assert runner.invoke(app, args).exit_code == 0
    assert not list(output.rglob("*private*"))
    stateful = [*args, "--seen-registry", str(output / "seen.db")]
    assert runner.invoke(app, stateful).exit_code == 0
    assert runner.invoke(app, stateful).exit_code == 1
    link = [
        "manifest",
        "link",
        str(output / "manifest.json"),
        "--trust",
        str(output / "trust.json"),
        "--context",
        str(output / "context.json"),
        "--at",
        AT,
        "--vault-root",
        str(output / "vault"),
    ]
    assert runner.invoke(app, link).exit_code == 0
    assert runner.invoke(app, link).exit_code == 2
    next((output / "bundle").iterdir()).write_bytes(b"altered")
    assert runner.invoke(app, args).exit_code == 1
    (output / "trust.json").unlink()
    assert runner.invoke(app, args).exit_code == 2
    assert (
        runner.invoke(app, ["manifest", "demo", str(output), "--at", AT]).exit_code == 2
    )
