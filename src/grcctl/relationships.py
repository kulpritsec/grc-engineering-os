"""Read-only local relationship projection, not an ontology or assurance engine."""

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from pydantic import BaseModel, Field

from .assurance.journal import verify_journal
from .manifests.codec import parse_contract
from .manifests.models import ManifestArtifact, ManifestCheck, utc_time
from .vault import LocalEvidenceVault, VaultArtifact, VaultError

# Identifiers and ordering expressions are static, never taken from CLI input.
TABLE_ORDER = {
    "artifacts": "artifact_id",
    "assessment_publications": "publication_id",
    "assessment_evidence_links": "publication_id, evidence_id",
    "publication_journal": "sequence",
    "manifest_verifications": "manifest_id",
    "manifest_artifact_links": "manifest_id, artifact_id",
}


class ProjectionError(ValueError):
    """The source cannot be safely represented as a read-only projection."""


class RelationshipNode(BaseModel):
    id: str
    kind: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class RelationshipEdge(BaseModel):
    id: str
    source: str
    target: str
    relation: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class RelationshipProjection(BaseModel):
    schema_version: str = "0.1.0"
    projection_type: str = "local-evidence-relationships"
    observed_at: str
    complete: bool
    consistent: bool
    source_tables: dict[str, str]
    journal: dict[str, Any]
    nodes: list[RelationshipNode]
    edges: list[RelationshipEdge]
    diagnostics: list[str]
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Stored verdicts, origin claims and authentication snapshots are operator-mutable claims.",
            "Byte consistency and journal consistency do not establish source authenticity or control effectiveness.",
            "Current manifest authentication, revocation and evidence freshness were not evaluated.",
            "Procedure claims are grouped by declared identifier and scope, not registered canonical controls or assets.",
            "Metadata is a SQLite read snapshot; object bytes are checked afterward and may change concurrently.",
            "This is a local projection, not KAEO/GRCML/RDF standards conformance or regulatory assurance.",
        ]
    )


def node_id(kind: str, identity: str) -> str:
    return kind + ":" + quote(identity, safe="")


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def project_relationships(
    root: Path, *, limit: int = 200, max_verify_bytes: int = 256 * 1024 * 1024
) -> RelationshipProjection:
    """Project persisted relationships without schema initialization or writes."""
    if not 1 <= limit <= 1000 or not 0 <= max_verify_bytes <= 1024 * 1024 * 1024:
        raise ProjectionError("Limit must be 1–1000; byte budget must be 0–1073741824.")
    try:
        vault = LocalEvidenceVault(root, readonly=True)
        with vault._connect() as db:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 64 * 1024)
            # Bound work even for a hostile/corrupt local schema with expensive views.
            steps = 0

            def progress() -> int:
                nonlocal steps
                steps += 1000
                return int(steps > 5_000_000)

            db.set_progress_handler(progress, 1000)
            db.execute("BEGIN")
            existing = {
                r["name"]
                for r in db.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            if "artifacts" not in existing:
                raise ProjectionError("Source has no Vault artifacts table.")
            rows: dict[str, list[dict[str, Any]]] = {}
            states: dict[str, str] = {}
            diagnostics: list[str] = []
            for table, order in TABLE_ORDER.items():
                if table not in existing:
                    states[table] = "not_present"
                    rows[table] = []
                    continue
                values = [
                    dict(r)
                    for r in db.execute(
                        f'SELECT * FROM "{table}" ORDER BY {order} LIMIT ?',
                        (limit + 1,),
                    )
                ]
                if any(
                    not isinstance(value, (str, int, type(None)))
                    for row in values
                    for value in row.values()
                ):
                    raise ProjectionError(
                        f"{table}: unsupported non-scalar source value."
                    )
                truncated = len(values) > limit
                states[table] = "truncated" if truncated else "loaded"
                rows[table] = values[:limit]
                if truncated:
                    diagnostics.append(
                        f"{table}: row limit reached; source is incompletely projected."
                    )
            for left, right in (
                ("assessment_publications", "assessment_evidence_links"),
                ("manifest_verifications", "manifest_artifact_links"),
            ):
                if (left in existing) != (right in existing):
                    diagnostics.append(f"Partial source schema: {left} / {right}.")
            journal: dict[str, Any] = {"status": "not_present"}
            journal_tables = (
                "publication_journal",
                "assessment_publications",
                "assessment_evidence_links",
            )
            if "publication_journal" in existing:
                if not all(states[t] == "loaded" for t in journal_tables):
                    journal = {"status": "not_checked_incomplete"}
                    diagnostics.append(
                        "Journal check skipped because its source tables are incomplete."
                    )
                else:
                    check = verify_journal(db)
                    journal = {
                        "status": "consistent" if check.valid else "inconsistent",
                        "events_checked": check.events_checked,
                        "problems": check.problems,
                    }
                    diagnostics.extend(check.problems)

            # Resolve referenced-but-unloaded IDs within this same metadata snapshot.
            nodes: dict[str, RelationshipNode] = {}
            edges: dict[str, RelationshipEdge] = {}
            artifact_rows = {r["artifact_id"]: r for r in rows["artifacts"]}

            def add_node(kind: str, identity: str, attributes: dict[str, Any]) -> str:
                key = node_id(kind, identity)
                nodes[key] = RelationshipNode(id=key, kind=kind, attributes=attributes)
                return key

            def endpoint(kind: str, identity: str) -> str:
                key = node_id(kind, identity)
                if key not in nodes:
                    table, column = {
                        "artifact": ("artifacts", "artifact_id"),
                        "publication": ("assessment_publications", "publication_id"),
                        "manifest_record": ("manifest_verifications", "manifest_id"),
                    }[kind]
                    present = (
                        table in existing
                        and db.execute(
                            f'SELECT 1 FROM "{table}" WHERE {column} = ? LIMIT 1',
                            (identity,),
                        ).fetchone()
                        is not None
                    )
                    status = "outside_limit" if present else "missing_record"
                    add_node(
                        kind, identity, {"record_status": status, "placeholder": True}
                    )
                    diagnostics.append(f"{key}: referenced record {status}.")
                return key

            def edge(
                source: str,
                target: str,
                relation: str,
                attributes: dict[str, Any] | None = None,
            ) -> None:
                attributes = attributes or {}
                key = "edge:" + _digest([source, target, relation, attributes])
                edges[key] = RelationshipEdge(
                    id=key,
                    source=source,
                    target=target,
                    relation=relation,
                    attributes=attributes,
                )

            remaining = max_verify_bytes
            budget_incomplete = False
            for row in rows["artifacts"]:
                attributes = {
                    "stored_kind": row["kind"],
                    "stored_sha256": row["sha256"],
                    "stored_size_bytes": row["size_bytes"],
                    "stored_ingested_at": row["ingested_at"],
                    "stored_origin_claim": row["origin_claim"],
                    "current_authentication": "not_checked",
                    "record_status": "present",
                }
                try:
                    ManifestArtifact.model_validate(
                        {
                            k: row[k]
                            for k in ("artifact_id", "kind", "sha256", "size_bytes")
                        }
                    )
                    record = VaultArtifact(**row)
                    status = vault.verify_record(
                        record, max_bytes=min(record.size_bytes, remaining)
                    ).status
                    remaining = max(0, remaining - record.size_bytes)
                except (ValueError, TypeError):
                    status = "invalid_metadata"
                attributes["current_byte_integrity"] = status
                if status != "matched":
                    diagnostics.append(f"artifact:{row['artifact_id']}: {status}.")
                budget_incomplete |= status == "not_checked_budget"
                add_node("artifact", row["artifact_id"], attributes)
            for row in rows["assessment_publications"]:
                key = add_node(
                    "publication",
                    row["publication_id"],
                    {
                        "record_status": "present",
                        "stored_assessment_id": row["assessment_id"],
                        "stored_verdict": row["verdict"],
                        "stored_evaluated_at": row["evaluated_at"],
                        "stored_published_at": row["published_at"],
                        "current_assurance": "not_evaluated",
                    },
                )
                procedure = add_node(
                    "procedure_claim",
                    _digest([row["procedure_id"], row["scope"]]),
                    {
                        "declared_procedure_id": row["procedure_id"],
                        "declared_scope": row["scope"],
                        "registry_status": "unregistered_claim",
                    },
                )
                edge(key, procedure, "declares_procedure")
                report = endpoint("artifact", row["report_artifact_id"])
                metadata = artifact_rows.get(row["report_artifact_id"])
                status = (
                    "matched_metadata"
                    if metadata
                    and metadata["sha256"] == row["report_sha256"]
                    and metadata["kind"] == "assessment-report"
                    else "unresolved_or_mismatched_metadata"
                )
                if status != "matched_metadata":
                    diagnostics.append(f"{key}: report reference {status}.")
                edge(
                    key,
                    report,
                    "preserved_report",
                    {
                        "expected_sha256": row["report_sha256"],
                        "reference_status": status,
                    },
                )
            for row in rows["manifest_verifications"]:
                attributes = {
                    "record_status": "present",
                    "current_authentication": "not_checked",
                    "snapshot_custody": "operator_mutable_unsigned",
                }
                try:
                    snapshot = parse_contract(
                        row["check_json"].encode("utf-8"), ManifestCheck
                    )
                    utc_time(snapshot.verified_at)
                    attributes.update(
                        recorded_authenticated_claim=snapshot.authenticated,
                        recorded_verified_at=snapshot.verified_at,
                    )
                    if snapshot.authenticated and (
                        snapshot.structure != "valid"
                        or snapshot.signature != "valid"
                        or snapshot.identity_policy != "authorized"
                        or snapshot.context != "matched"
                        or not snapshot.artifacts
                        or any(v != "matched" for v in snapshot.artifacts.values())
                        or snapshot.replay != "consumed_locally"
                        or snapshot.problems
                    ):
                        raise ValueError(
                            "Historical authentication claim is internally contradictory."
                        )
                    if (
                        snapshot.manifest_id,
                        snapshot.retained_manifest_id,
                        snapshot.retained_trust_id,
                    ) != (
                        row["manifest_id"],
                        row["manifest_artifact_id"],
                        row["trust_artifact_id"],
                    ):
                        raise ValueError("Snapshot identity differs from record.")
                    for column, expected, kind in (
                        (
                            "manifest_artifact_id",
                            snapshot.manifest_sha256,
                            "signed-manifest",
                        ),
                        (
                            "trust_artifact_id",
                            snapshot.trust_policy_sha256,
                            "trust-policy-snapshot",
                        ),
                    ):
                        retained = artifact_rows.get(row[column])
                        if retained is not None and (
                            retained["sha256"] != expected or retained["kind"] != kind
                        ):
                            raise ValueError(
                                "Snapshot digest/type differs from retained metadata."
                            )
                    attributes["snapshot_schema"] = "valid"
                except (ValueError, AttributeError):
                    attributes["snapshot_schema"] = "invalid_or_inconsistent"
                    diagnostics.append(
                        f"manifest_record:{row['manifest_id']}: invalid or inconsistent stored snapshot."
                    )
                add_node("manifest_record", row["manifest_id"], attributes)
            for row in rows["assessment_evidence_links"]:
                source = endpoint("publication", row["publication_id"])
                target = endpoint("artifact", row["artifact_id"])
                metadata = artifact_rows.get(row["artifact_id"])
                status = (
                    "matched_metadata"
                    if metadata
                    and (metadata["sha256"], metadata["kind"])
                    == (row["sha256"], row["kind"])
                    else "unresolved_or_mismatched_metadata"
                )
                if status != "matched_metadata":
                    diagnostics.append(
                        f"{source}: evidence {row['evidence_id']} reference {status}."
                    )
                edge(
                    source,
                    target,
                    "uses_evidence",
                    {
                        "evidence_id": row["evidence_id"],
                        "expected_kind": row["kind"],
                        "expected_sha256": row["sha256"],
                        "reference_status": status,
                    },
                )
            for row in rows["manifest_verifications"]:
                source = endpoint("manifest_record", row["manifest_id"])
                for column, relation in (
                    ("manifest_artifact_id", "preserved_manifest"),
                    ("trust_artifact_id", "preserved_trust_snapshot"),
                ):
                    edge(source, endpoint("artifact", row[column]), relation)
                if row["publication_id"] is not None:
                    edge(
                        source,
                        endpoint("publication", row["publication_id"]),
                        "recorded_for_publication",
                    )
            for row in rows["manifest_artifact_links"]:
                edge(
                    endpoint("manifest_record", row["manifest_id"]),
                    endpoint("artifact", row["artifact_id"]),
                    "records_artifact_link",
                )
        partial = any(d.startswith("Partial source schema") for d in diagnostics)
        return RelationshipProjection(
            observed_at=datetime.now(UTC).isoformat(),
            complete=not budget_incomplete
            and not partial
            and journal["status"] != "not_checked_incomplete"
            and all(v != "truncated" for v in states.values()),
            consistent=not diagnostics,
            source_tables=states,
            journal=journal,
            nodes=sorted(nodes.values(), key=lambda n: n.id),
            edges=sorted(edges.values(), key=lambda e: e.id),
            diagnostics=sorted(set(diagnostics)),
        )
    except (OSError, sqlite3.Error, VaultError, KeyError, TypeError) as exc:
        raise ProjectionError(f"Cannot project source: {exc}") from exc


def export_relationships(
    root: Path,
    *,
    limit: int = 200,
    max_verify_bytes: int = 256 * 1024 * 1024,
    output: Path | None = None,
) -> RelationshipProjection:
    """Optional new export file; never overwrite a source or existing file."""
    if output is not None:
        if output.resolve().is_relative_to(root.resolve()) or any(
            p.is_symlink() for p in (output, *output.parents)
        ):
            raise ProjectionError(
                "Export output must be outside the Vault and free of symlinks."
            )
        if output.exists():
            raise ProjectionError("Export output must be a new file.")
    projection = project_relationships(
        root, limit=limit, max_verify_bytes=max_verify_bytes
    )
    if output is not None:
        try:
            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as writer:
                writer.write(projection.model_dump_json(indent=2) + "\n")
        except OSError as exc:
            raise ProjectionError(f"Cannot write new export: {exc}") from exc
    return projection
