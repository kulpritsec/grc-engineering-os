"""Read-only, historical-claim and corruption criteria fixed in issue 24."""

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
import test_manifest_store
from test_manifest_store import link_args
from typer.testing import CliRunner

from grcctl.cli import app
from grcctl.manifests.store import link_manifest
from grcctl.relationships import (
    ProjectionError,
    export_relationships,
    node_id,
    project_relationships,
)
from grcctl.vault import LocalEvidenceVault, VaultError

publication = test_manifest_store.publication


def source_snapshot(root):
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file()
    }


def node(graph, kind, identity):
    return next(n for n in graph.nodes if n.id == node_id(kind, identity))


def assert_connected(graph):
    ids = {n.id for n in graph.nodes}
    assert len(ids) == len(graph.nodes)
    assert len({e.id for e in graph.edges}) == len(graph.edges)
    assert all(e.source in ids and e.target in ids for e in graph.edges)
    assert [n.id for n in graph.nodes] == sorted(ids)
    assert [e.id for e in graph.edges] == sorted(e.id for e in graph.edges)


def test_empty_and_legacy_vault_no_schema_creation(tmp_path):
    vault = LocalEvidenceVault(tmp_path / "vault")
    before = source_snapshot(vault.root)
    empty = project_relationships(vault.root)
    assert empty.complete and empty.consistent
    assert empty.nodes == [] and empty.edges == []
    assert empty.journal == {"status": "not_present"}
    assert source_snapshot(vault.root) == before
    source = tmp_path / "synthetic.txt"
    source.write_bytes(b"synthetic")
    saved = vault.ingest(source)
    before = source_snapshot(vault.root)
    graph = project_relationships(vault.root)
    assert len(graph.nodes) == 1
    assert (
        node(graph, "artifact", saved.artifact_id).attributes["current_byte_integrity"]
        == "matched"
    )
    assert graph.source_tables["manifest_verifications"] == "not_present"
    assert source_snapshot(vault.root) == before


def test_published_and_linked_records_remain_read_only_claims(publication):
    catalog, pub, artifact, _payload, _context = publication
    check = link_manifest(**link_args(publication))
    before = source_snapshot(catalog.vault.root)
    graph = project_relationships(catalog.vault.root)
    assert graph.complete and graph.consistent, graph.diagnostics
    assert graph.journal["status"] == "consistent"
    assert (
        node(graph, "publication", pub.publication_id).attributes["stored_verdict"]
        == "failed"
    )
    assert (
        node(graph, "publication", pub.publication_id).attributes["current_assurance"]
        == "not_evaluated"
    )
    record = node(graph, "manifest_record", check.manifest_id)
    assert record.attributes["recorded_authenticated_claim"] is True
    assert record.attributes["current_authentication"] == "not_checked"
    assert record.attributes["snapshot_custody"] == "operator_mutable_unsigned"
    assert (
        node(graph, "artifact", artifact.artifact_id).attributes[
            "current_authentication"
        ]
        == "not_checked"
    )
    relations = {e.relation for e in graph.edges}
    assert relations == {
        "declares_procedure",
        "uses_evidence",
        "preserved_report",
        "preserved_manifest",
        "preserved_trust_snapshot",
        "recorded_for_publication",
        "records_artifact_link",
    }
    assert_connected(graph)
    again = project_relationships(catalog.vault.root)
    assert graph.model_dump(exclude={"observed_at"}) == again.model_dump(
        exclude={"observed_at"}
    )
    assert source_snapshot(catalog.vault.root) == before


def test_same_bytes_distinct_ingestion_and_repeated_publications(publication):
    catalog, pub, artifact, _payload, _context = publication
    other = catalog.vault.ingest(
        catalog.vault.artifact_path(artifact.artifact_id), kind=artifact.kind
    )
    report_path = catalog.vault.artifact_path(pub.report_artifact_id)
    next_pub = catalog.publish(report_path)
    graph = project_relationships(catalog.vault.root)
    assert graph.complete and graph.consistent
    assert artifact.sha256 == other.sha256
    assert (
        node(graph, "artifact", artifact.artifact_id).id
        != node(graph, "artifact", other.artifact_id).id
    )
    assert (
        node(graph, "publication", pub.publication_id).id
        != node(graph, "publication", next_pub.publication_id).id
    )
    uses = [e for e in graph.edges if e.relation == "uses_evidence"]
    assert len(uses) == 2 and {e.target for e in uses} == {
        node_id("artifact", artifact.artifact_id)
    }
    assert_connected(graph)


@pytest.mark.parametrize("mutation", ["modify", "remove", "size", "invalid_digest"])
def test_corrupt_bytes_or_metadata_are_visible_not_passing(publication, mutation):
    catalog, _pub, artifact, _payload, _context = publication
    path = catalog.vault.artifact_path(artifact.artifact_id)
    if mutation == "modify":
        path.write_bytes(b"x" * artifact.size_bytes)
    elif mutation == "remove":
        path.unlink()
    else:
        column, value = (
            ("size_bytes", -1) if mutation == "size" else ("sha256", "../../escape")
        )
        with catalog.vault._connect() as db:
            db.execute(
                f"UPDATE artifacts SET {column} = ? WHERE artifact_id = ?",
                (value, artifact.artifact_id),
            )
    before = source_snapshot(catalog.vault.root)
    graph = project_relationships(catalog.vault.root)
    assert not graph.consistent
    status = node(graph, "artifact", artifact.artifact_id).attributes[
        "current_byte_integrity"
    ]
    assert (
        status
        == {
            "modify": "hash_mismatch",
            "remove": "missing",
            "size": "invalid_metadata",
            "invalid_digest": "invalid_metadata",
        }[mutation]
    )
    assert source_snapshot(catalog.vault.root) == before
    assert_connected(graph)


def test_missing_records_get_explicit_placeholders(publication):
    catalog, pub, artifact, _payload, _context = publication
    with catalog.vault._connect() as db:
        db.execute(
            "DELETE FROM artifacts WHERE artifact_id = ?", (artifact.artifact_id,)
        )
        db.execute(
            "UPDATE assessment_evidence_links SET publication_id = 'orphan' WHERE publication_id = ?",
            (pub.publication_id,),
        )
    graph = project_relationships(catalog.vault.root)
    assert not graph.consistent
    assert (
        node(graph, "artifact", artifact.artifact_id).attributes["record_status"]
        == "missing_record"
    )
    assert node(graph, "publication", "orphan").attributes["placeholder"] is True
    assert graph.journal["status"] == "inconsistent"
    assert_connected(graph)


def test_metadata_contradictions_visible_without_verdict_rewrite(publication):
    catalog, pub, artifact, _payload, _context = publication
    with catalog.vault._connect() as db:
        db.execute(
            "UPDATE assessment_evidence_links SET kind = 'other' WHERE artifact_id = ?",
            (artifact.artifact_id,),
        )
        db.execute(
            "UPDATE assessment_publications SET report_sha256 = ? WHERE publication_id = ?",
            ("0" * 64, pub.publication_id),
        )
    graph = project_relationships(catalog.vault.root)
    assert not graph.consistent
    assert all(
        e.attributes["reference_status"] == "unresolved_or_mismatched_metadata"
        for e in graph.edges
        if e.relation in ("uses_evidence", "preserved_report")
    )
    assert (
        node(graph, "publication", pub.publication_id).attributes["stored_verdict"]
        == "failed"
    )


def test_fabricated_snapshot_never_becomes_current_authentication(publication):
    catalog, _pub, _artifact, _payload, _context = publication
    check = link_manifest(**link_args(publication))
    with catalog.vault._connect() as db:
        raw = json.loads(
            db.execute("SELECT check_json FROM manifest_verifications").fetchone()[0]
        )
        raw["signature"] = "invalid"
        raw["authenticated"] = True
        db.execute(
            "UPDATE manifest_verifications SET check_json = ?", (json.dumps(raw),)
        )
    graph = project_relationships(catalog.vault.root)
    attributes = node(graph, "manifest_record", check.manifest_id).attributes
    assert attributes["recorded_authenticated_claim"] is True
    assert attributes["current_authentication"] == "not_checked"
    assert attributes["snapshot_custody"] == "operator_mutable_unsigned"
    assert attributes["snapshot_schema"] == "invalid_or_inconsistent"
    assert not graph.consistent


@pytest.mark.parametrize(
    "mutation", ["malformed", "identity", "missing_table", "orphan_link"]
)
def test_partial_and_invalid_manifest_metadata(publication, mutation):
    catalog, _pub, _artifact, _payload, _context = publication
    check = link_manifest(**link_args(publication))
    with catalog.vault._connect() as db:
        if mutation == "malformed":
            db.execute("UPDATE manifest_verifications SET check_json = 'not json'")
        elif mutation == "identity":
            db.execute(
                "UPDATE manifest_verifications SET trust_artifact_id = manifest_artifact_id"
            )
        elif mutation == "missing_table":
            db.execute("DROP TABLE manifest_artifact_links")
        else:
            db.execute("UPDATE manifest_artifact_links SET manifest_id = 'unknown'")
    graph = project_relationships(catalog.vault.root)
    assert not graph.consistent
    if mutation in ("malformed", "identity"):
        assert (
            node(graph, "manifest_record", check.manifest_id).attributes[
                "snapshot_schema"
            ]
            == "invalid_or_inconsistent"
        )
    if mutation == "missing_table":
        assert not graph.complete
    assert_connected(graph)


def test_row_limits_and_byte_budget_disclose_incomplete_projection(publication):
    catalog = publication[0]
    limited = project_relationships(catalog.vault.root, limit=1)
    assert not limited.complete and not limited.consistent
    assert limited.journal["status"] == "consistent"
    assert limited.source_tables["artifacts"] == "truncated"
    assert_connected(limited)
    pub = publication[1]
    catalog.publish(catalog.vault.artifact_path(pub.report_artifact_id))
    assert (
        project_relationships(catalog.vault.root, limit=1).journal["status"]
        == "not_checked_incomplete"
    )
    no_bytes = project_relationships(catalog.vault.root, max_verify_bytes=0)
    assert not no_bytes.complete
    assert all(
        n.attributes["current_byte_integrity"] == "not_checked_budget"
        for n in no_bytes.nodes
        if n.kind == "artifact"
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limit": 0},
        {"limit": 1001},
        {"max_verify_bytes": -1},
        {"max_verify_bytes": 2**31},
    ],
)
def test_invalid_bounds_fail_without_creating_vault(tmp_path, kwargs):
    root = tmp_path / "missing"
    with pytest.raises(ProjectionError, match="Limit must"):
        project_relationships(root, **kwargs)
    assert not root.exists()


def test_absent_corrupt_unsupported_sources_and_readonly_sql(tmp_path):
    root = tmp_path / "missing"
    with pytest.raises(ProjectionError, match="existing Vault"):
        project_relationships(root)
    assert not root.exists()
    vault = LocalEvidenceVault(tmp_path / "vault")
    reader = LocalEvidenceVault(vault.root, readonly=True)
    with pytest.raises(VaultError, match="read-only"):
        reader.ingest(tmp_path / "anything")
    with reader._connect() as db, pytest.raises(sqlite3.OperationalError):
        db.execute("CREATE TABLE forbidden (id TEXT)")
    with closing(sqlite3.connect(vault.db_path)) as db, db:
        db.execute("DROP TABLE artifacts")
    with pytest.raises(ProjectionError, match="artifacts table"):
        project_relationships(vault.root)
    vault.db_path.write_bytes(b"not sqlite")
    with pytest.raises(ProjectionError):
        project_relationships(vault.root)


def test_wal_or_hot_journal_is_refused_without_ignoring_data(tmp_path):
    vault = LocalEvidenceVault(tmp_path / "vault")
    with closing(sqlite3.connect(vault.db_path)) as db:
        assert db.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"
    before = source_snapshot(vault.root)
    with pytest.raises(ProjectionError, match="quiescent"):
        project_relationships(vault.root)
    assert source_snapshot(vault.root) == before


def test_binary_source_values_and_oversized_rows_fail_explicitly(publication):
    catalog, _pub, artifact, _payload, _context = publication
    with catalog.vault._connect() as db:
        db.execute(
            "UPDATE artifacts SET origin_claim = ? WHERE artifact_id = ?",
            (b"\xff", artifact.artifact_id),
        )
    with pytest.raises(ProjectionError, match="non-scalar"):
        project_relationships(catalog.vault.root)
    with catalog.vault._connect() as db:
        db.execute(
            "UPDATE artifacts SET origin_claim = ? WHERE artifact_id = ?",
            ("x" * (64 * 1024 + 1), artifact.artifact_id),
        )
    with pytest.raises(ProjectionError):
        project_relationships(catalog.vault.root)


def test_output_safety_and_cli_status(publication, tmp_path):
    catalog = publication[0]
    before = source_snapshot(catalog.vault.root)
    output = tmp_path / "relationships.json"
    graph = export_relationships(catalog.vault.root, output=output)
    assert json.loads(output.read_text())["nodes"] == [
        n.model_dump() for n in graph.nodes
    ]
    assert source_snapshot(catalog.vault.root) == before
    with pytest.raises(ProjectionError, match="new file"):
        export_relationships(catalog.vault.root, output=output)
    with pytest.raises(ProjectionError, match="outside"):
        export_relationships(catalog.vault.root, output=catalog.vault.db_path)
    assert source_snapshot(catalog.vault.root) == before
    runner = CliRunner()
    args = ["assurance", "relationships", "--vault-root", str(catalog.vault.root)]
    success = runner.invoke(app, args)
    assert success.exit_code == 0, success.output
    assert json.loads(success.output)["consistent"] is True
    assert runner.invoke(app, [*args, "--limit", "1"]).exit_code == 1
    assert runner.invoke(app, [*args, "--limit", "0"]).exit_code == 2
    assert (
        runner.invoke(app, [*args, "--output", str(tmp_path / "cli.json")]).exit_code
        == 0
    )


def test_journal_without_publication_tables_is_incomplete(publication):
    catalog = publication[0]
    with catalog.vault._connect() as db:
        db.execute("DROP TABLE assessment_evidence_links")
        db.execute("DROP TABLE assessment_publications")
    graph = project_relationships(catalog.vault.root)
    assert graph.journal["status"] == "not_checked_incomplete"
    assert not graph.complete and not graph.consistent


def test_source_and_output_symlink_guardrails(publication, tmp_path, monkeypatch):
    catalog = publication[0]
    original = Path.is_symlink
    monkeypatch.setattr(
        Path, "is_symlink", lambda p: p == catalog.vault.db_path or original(p)
    )
    with pytest.raises(ProjectionError, match="Symbolic-link"):
        project_relationships(catalog.vault.root)
    outside = tmp_path / "linked"
    monkeypatch.setattr(Path, "is_symlink", lambda p: p == outside or original(p))
    with pytest.raises(ProjectionError, match="symlinks"):
        export_relationships(catalog.vault.root, output=outside)
