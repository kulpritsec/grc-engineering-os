"""Additive migration, publication binding and rollback fixtures."""

import json
import sqlite3
from contextlib import closing

import pytest
from test_assurance_catalog import fixture_run
from test_manifests import AT, FIXTURES, signed

from grcctl.assurance.catalog import LocalAssuranceCatalog
from grcctl.manifests.codec import ManifestError
from grcctl.manifests.models import AssessmentContext, VerificationContext
from grcctl.manifests.store import link_manifest
from grcctl.manifests.verifier import verify_manifest


@pytest.fixture
def publication(tmp_path):
    # A negative CVP must remain negative after statement authentication.
    root, artifact, report = fixture_run(tmp_path, outcome="fail")
    catalog = LocalAssuranceCatalog(root)
    pub = catalog.publish(report)
    payload = json.loads((FIXTURES / "payload.json").read_bytes())
    payload["artifacts"] = [
        {
            "artifact_id": artifact.artifact_id,
            "kind": artifact.kind,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
        }
    ]
    payload["assessment"] = {
        "assessment_id": pub.assessment_id,
        "procedure_id": pub.procedure_id,
        "report_sha256": pub.report_sha256,
    }
    context = VerificationContext(
        execution_id=payload["execution_id"],
        scope=payload["scope"],
        assessment=AssessmentContext.model_validate(payload["assessment"]),
    )
    return catalog, pub, artifact, payload, context


def link_args(fixture):
    catalog, pub, _artifact, payload, context = fixture
    return {
        "root": catalog.vault.root,
        "raw": signed(payload),
        "trust": (FIXTURES / "trust.json").read_bytes(),
        "context": context,
        "verified_at": AT,
        "publication_id": pub.publication_id,
    }


def test_additive_link_preserves_unsigned_history_and_negative_verdict(publication):
    catalog, pub, artifact, _payload, context = publication
    before = catalog.history(pub.procedure_id)
    check = link_manifest(**link_args(publication))
    assert check.authenticated and check.replay == "consumed_locally"
    assert catalog.history(pub.procedure_id) == before
    assert catalog.history(pub.procedure_id)[0].verdict == "failed"
    assert catalog.journal_status().valid
    assert catalog.journal_status().events_checked == 1
    with catalog.vault._connect() as db:
        row = db.execute("SELECT * FROM manifest_verifications").fetchone()
        assert row["publication_id"] == pub.publication_id
        assert (
            db.execute("SELECT artifact_id FROM manifest_artifact_links").fetchone()[0]
            == artifact.artifact_id
        )
        raw = catalog.vault.artifact_path(row["manifest_artifact_id"]).read_bytes()
        trust = catalog.vault.artifact_path(row["trust_artifact_id"]).read_bytes()
    # Stored snapshots, rather than current producer files, can be exported and verified.
    result = verify_manifest(
        raw,
        trust,
        {artifact.artifact_id: catalog.vault.artifact_path(artifact.artifact_id)},
        context=context,
        verified_at=AT,
    )
    assert result.authenticated
    with pytest.raises(ManifestError, match="already consumed"):
        link_manifest(**link_args(publication))
    assert catalog.journal_status().events_checked == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "assessment_id",
        "procedure_id",
        "digest",
        "scope",
        "artifact_set",
        "absent_assessment",
        "unknown_publication",
    ],
)
def test_publication_binding_rejects_substitution(publication, mutation):
    args = link_args(publication)
    payload = json.loads(args["raw"])["payload"]
    if mutation == "assessment_id":
        payload["assessment"]["assessment_id"] = "other"
    elif mutation == "procedure_id":
        payload["assessment"]["procedure_id"] = "other"
    elif mutation == "digest":
        payload["assessment"]["report_sha256"] = "0" * 64
    elif mutation == "scope":
        payload["scope"] = "other"
        policy = json.loads(args["trust"])
        policy["anchors"][0]["scopes"] = ["other"]
        args["trust"] = json.dumps(policy).encode()
    elif mutation == "artifact_set":
        catalog = publication[0]
        source = catalog.vault.root.parent / "extra.txt"
        source.write_bytes(b"synthetic extra")
        extra = catalog.vault.ingest(source, kind="test-result")
        payload["artifacts"].append(
            {
                "artifact_id": extra.artifact_id,
                "kind": extra.kind,
                "sha256": extra.sha256,
                "size_bytes": extra.size_bytes,
            }
        )
    elif mutation == "absent_assessment":
        payload["assessment"] = None
    else:
        args["publication_id"] = "unknown"
    args["raw"] = signed(payload)
    args["context"] = VerificationContext.model_validate(
        {
            "execution_id": payload["execution_id"],
            "scope": payload["scope"],
            "assessment": payload["assessment"],
        }
    )
    with pytest.raises(ManifestError):
        link_manifest(**args)
    with publication[0].vault._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM publication_journal").fetchone()[0] == 1
        assert not db.execute(
            "SELECT name FROM sqlite_master WHERE name = 'manifest_verifications'"
        ).fetchall()


@pytest.mark.parametrize("target", ["report", "evidence", "journal", "metadata"])
def test_corrupt_retained_state_never_gets_authenticated_link(publication, target):
    catalog, pub, artifact, _payload, _context = publication
    if target == "report":
        catalog.vault.artifact_path(pub.report_artifact_id).write_bytes(
            b"tampered report"
        )
    elif target == "evidence":
        catalog.vault.artifact_path(artifact.artifact_id).write_bytes(
            b"tampered evidence"
        )
    elif target == "journal":
        with catalog.vault._connect() as db:
            db.execute("UPDATE publication_journal SET event_hash = ?", ("0" * 64,))
    else:
        with catalog.vault._connect() as db:
            db.execute(
                "UPDATE artifacts SET kind = 'other' WHERE artifact_id = ?",
                (artifact.artifact_id,),
            )
    with pytest.raises(ManifestError):
        link_manifest(**link_args(publication))


def test_link_insert_failure_rolls_back_consumption_and_rows(publication):
    catalog = publication[0]
    with catalog.vault._connect() as db:
        db.execute(
            "CREATE TABLE manifest_verifications (manifest_id TEXT PRIMARY KEY, manifest_artifact_id TEXT, trust_artifact_id TEXT, publication_id TEXT, check_json TEXT)"
        )
        db.execute(
            "CREATE TABLE manifest_artifact_links (manifest_id TEXT, artifact_id TEXT)"
        )
        db.execute(
            "CREATE TRIGGER fail_link BEFORE INSERT ON manifest_artifact_links BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END"
        )
    with pytest.raises(ManifestError, match="linkage failed"):
        link_manifest(**link_args(publication))
    with catalog.vault._connect() as db:
        assert (
            db.execute("SELECT COUNT(*) FROM manifest_verifications").fetchone()[0] == 0
        )
        assert (
            db.execute("SELECT COUNT(*) FROM manifest_artifact_links").fetchone()[0]
            == 0
        )
        assert not db.execute(
            "SELECT name FROM sqlite_master WHERE name = 'consumed_manifests'"
        ).fetchall()
        db.execute("DROP TRIGGER fail_link")
    assert link_manifest(**link_args(publication)).authenticated


def test_absent_and_malformed_vault_fail_explicitly(publication, tmp_path):
    args = link_args(publication)
    args["root"] = tmp_path / "absent"
    with pytest.raises(ManifestError, match="existing Vault"):
        link_manifest(**args)
    root = tmp_path / "corrupt"
    root.mkdir(mode=0o700)
    database = root / "vault.db"
    database.write_bytes(b"not sqlite")
    database.chmod(0o600)
    args["root"] = root
    with pytest.raises(ManifestError, match="linkage failed"):
        link_manifest(**args)


def test_rejected_trust_does_not_preserve_or_consume(publication):
    args = link_args(publication)
    policy = json.loads(args["trust"])
    policy["anchors"][0]["revoked"] = True
    args["trust"] = json.dumps(policy).encode()
    count = len(publication[0].vault.list_artifacts())
    with pytest.raises(ManifestError, match="authentication refused"):
        link_manifest(**args)
    assert len(publication[0].vault.list_artifacts()) == count
    # Independent connection verifies no state was committed.
    with closing(sqlite3.connect(publication[0].vault.db_path)) as db:
        assert not db.execute(
            "SELECT name FROM sqlite_master WHERE name = 'consumed_manifests'"
        ).fetchall()
