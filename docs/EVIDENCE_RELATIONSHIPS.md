# Read only evidence relationship projection

The local CLI projects existing Vault ingestions, publications and manifest records into a bounded JSON graph. This is the first relationship layer for later KAEO/GRCML views; it does not implement an ontology, infer canonical controls/assets or issue assurance conclusions. Tracks [issue 24](https://github.com/kulpritsec/grc-engineering-os/issues/24).

## Operator commands

For an existing synthetic Vault:

```powershell
uv sync --locked
uv run grcctl assurance relationships --vault-root evidence/vault
uv run grcctl assurance relationships --vault-root evidence/vault --output evidence/relationships.json
```

The output path must be a new file outside the source Vault, with an existing parent directory and no symlink path. Existing files are never overwritten. Exit 0 means this bounded local projection is complete and has no reported inconsistencies; exit 1 still emits the graph but indicates incompleteness or inconsistencies. Input, unsupported storage/schema and export errors exit 2.

Create a synthetic manifest demo, record its linkage, then inspect it:

```powershell
uv run grcctl manifest demo evidence/relationship-demo --at 2026-10-10T12:00:00Z
uv run grcctl manifest link evidence/relationship-demo/manifest.json --trust evidence/relationship-demo/trust.json --context evidence/relationship-demo/context.json --at 2026-10-10T12:01:00Z --vault-root evidence/relationship-demo/vault
uv run grcctl assurance relationships --vault-root evidence/relationship-demo/vault
```

The demo has no assessment publication. To inspect those edges too, use the synthetic [CVP Vault workflow](CVP_VAULT_LINKS.md), [publication workflow](ASSURANCE_HISTORY.md) and optional signed publication linkage from [Signed Evidence Manifests](SIGNED_EVIDENCE_MANIFESTS.md).

## Projection contract

Version `0.1.0` exports `nodes`, `edges`, `source_tables`, `journal`, `diagnostics`, `complete`, `consistent`, a host `observed_at` timestamp and limitations. Nodes and edges sort by stable ID; repeated projections of unchanged source data differ only in observation time. Node IDs use a kind prefix and percent-encoded source identity. Edge IDs hash source, target, relation and attributes; these hashes identify graph elements, not signed attestations.

| Node kind | Source and interpretation |
| --- | --- |
| artifact | Specific Vault ingestion UUID, stored digest/kind/size/time/origin claim and current byte check |
| publication | Distinct publication UUID, stored assessment identity/verdict/times; current assurance is not evaluated |
| procedure_claim | Hash of declared procedure ID and scope, with both values retained; no registered/versioned control identity is inferred |
| manifest_record | Manifest verification record, its historical authentication claim/time and unsigned mutable snapshot status; current authentication is not checked |

Relations are `declares_procedure`, `preserved_report`, `uses_evidence`, `preserved_manifest`, `preserved_trust_snapshot`, `recorded_for_publication` and `records_artifact_link`. Evidence references retain their report-local evidence IDs and expected digest/kind. Duplicate bytes retain distinct ingestion nodes; repeated assessment publications remain distinct. No source artifact content, signing key, policy body or source filename is exported.

References outside the loaded row limit create placeholder nodes labeled `outside_limit`; genuinely absent records create `missing_record` placeholders. Every emitted edge has both endpoints. Reference contradictions, partial schemas, missing/tampered objects and damaged journals appear as diagnostics, never as silently passing relationships.

`complete` means all present source tables fit the row limit, required paired tables are available and byte checks were not skipped for budget. It does not mean all planned platform modules exist. `consistent` means no inconsistency/incompleteness diagnostics were emitted; it is not a security verdict. Absent optional tables are labeled `not_present` so older or artifact-only Vaults remain usable without migrations. Historical publication metadata without a journal does not acquire a fabricated journal result.

## Trust semantics

Stored verdicts and authentication snapshots remain operator-mutable claims. A saved `authenticated: true` is exported as `recorded_authenticated_claim`, alongside `current_authentication: not_checked`. Structurally valid saved snapshots are not independent custody evidence. Internally contradictory flags, mismatched identities and mismatched retained digest/kind are diagnosed, while a self-consistent fabricated historical record still requires external verification.

Current artifact SHA-256/size checks and the existing journal verifier are reused. The journal concerns local publication/link metadata, not current artifact bytes or collector authenticity. The projection does not rerun CVPs, authenticate manifest signatures against a current trust policy, evaluate revocation/freshness or turn a stored failed verdict into a verified conclusion. Use the independent manifest verifier for current statement authentication.

## Storage and resource boundaries

The Vault reader uses SQLite `mode=ro`, query-only transactions and no schema initialization. Metadata is read in one transaction. Objects are checked against those rows without opening a second database snapshot. No source directories, tables, journal events, verification records or replay consumption are created. Reads can update filesystem access times; tests establish unchanged contents and file inventory, not forensic immutability.

This reader deliberately rejects WAL and existing journal/sidecar stores instead of silently dropping their state. SQLite documents that read-only WAL access can require existing or newly created sidecar files; see [SQLite WAL](https://www.sqlite.org/wal.html). Mode flags are detected using the documented [database header](https://www.sqlite.org/fileformat.html). Use a quiescent rollback-journal development store. There is no automatic checkpoint, recovery or conversion.

`--limit` defaults to 200 rows per present source table, maximum 1000. Truncated sources are explicit; journal verification is skipped when its publication/journal/link tables are truncated or missing, while unrelated artifact truncation does not invalidate a complete metadata-only journal check. `--max-verify-bytes` defaults to 256 MiB, maximum 1 GiB, and can be zero to skip positive-size byte reads. Per-artifact metadata follows the existing 64 MiB profile. Records with unsupported scalar values or values beyond the SQLite 64 KiB length limit fail explicitly; SQLite work is additionally bounded by a progress handler. No unbounded graph traversal occurs.

Metadata snapshot isolation does not freeze object bytes or prevent concurrent host writers. Symlink checks, POSIX privacy validation and bounded reads are guardrails; Windows ACLs and race-free hostile filesystem access are not established. This is single-user local development, with no HTTP evidence access, graph database, cloud changes or new persistent schema.

## Validation

```powershell
uv run pytest -q tests/test_relationships.py
uv run ruff format --check .
uv run ruff check .
uv run --no-sync --with-requirements requirements/platform-dev.txt mypy src
uv run --no-sync --with-requirements requirements/platform-dev.txt pytest --cov=grcctl --cov-report=term-missing --cov-fail-under=70
uv build
```

Acceptance cases include legacy/empty Vaults, distinct ingestion identities for shared bytes, repeated publications, historical authentication labels, byte and metadata corruption, dangling relationships, partial/malformed storage, deterministic ordering, row/byte bounds, WAL refusal, SQL write rejection, safe export and unchanged source hashes/file inventory. AI-assisted implementation remains subject to independent human review; passing checks do not constitute security certification.

Local Windows validation: all 25 new projection cases pass. Full suite: 151 passed, 2 existing Windows failures, 1 skip, four warnings, 89.63% coverage. The failures remain the POSIX 0600 assertion and missing Windows symlink privileges; the existing Unix privacy test skips. Warnings remain one Starlette/AnyIO deprecation and three unclosed SQLite connections. Locked sync, formatter, Ruff, mypy and package build pass. No dependency changes were introduced; the locked runtime audit reports no known vulnerabilities, excluding optional API/dev extras. A scoped scan of new source, tests and documentation found no AWS/GitHub tokens or serialized private-key blocks. Linux CI remains separate evidence for the draft PR.
