# Local CVP Publication History — G2 prototype

**Status:** Local development prototype only. The publisher uses a SQLite database controlled by the local operator. Publication is append-only through the supported CLI, **not an immutable, independently authenticated audit ledger**.

## Purpose

A single preserved Evidence Vault artifact can support multiple assessment runs over time. Each report has its own publication UUID, assessment identity, CVP/control procedure ID, reported verdict, evaluation/publish times, and a persisted report artifact. Every relationship contains the **specific Vault ingestion UUID** (not just a content hash) and its expected type/digest.

This provides the first persistence and search layer that can later project into KAEO and GRCML, without deploying a graph database or cloud infrastructure.

## How to use

From `feature/assurance-history-catalog`, use the synthetic steps in
[CVP Vault Links](CVP_VAULT_LINKS.md) to create `evidence/demo-cvp-evaluation.json`.

```bash
uv sync --locked
uv run grcctl assurance publish evidence/demo-cvp-evaluation.json \
    --vault-root evidence/vault

uv run grcctl assurance history CVP-SYNTH-ACCESS \
    --vault-root evidence/vault

uv run grcctl assurance evidence-usage <VAULT-INGESTION-UUID> \
    --vault-root evidence/vault
```

Publication:
1. Rejects reports with invalid schema or canonical hash.
2. Requires every referenced evidence artifact to be a persistent Vault UUID, rather than a volatile file path.
3. Re-runs the deterministic CVP evaluator against the **current stored artifacts**, requires matching verdict and matching artifact checks.
4. Rejects missing, modified or inconsistent evidence. A genuine negative observation with intact evidence remains a **failed** conclusion and is retained.
5. Stores a distinct ingestion of the report into the Vault and inserts a record for each evidence relationship into SQLite.

The source evidence can be shared across multiple runs, and a second publication never overwrites the first via the supported API. A lookup by procedure ID returns a history; a lookup by evidence ingestion ID returns uses across publications.

## Assurance limitations

The report and metadata are still under control of the same local user. Recomputed hashes, altered SQLite rows or filesystem compromise can defeat the prototype. The publishing step is **not a regulator-approved validation, nor an external attestation**. It does not authenticate who collected an observation or independently validate whether the underlying event occurred.

We intentionally do **not** expose Vault or history data through the unauthenticated HTTP starter. Authenticated collectors, secure time, digital signatures, independent verification, retention locks, disaster recovery, and tenant separation are G2+ work.

## Next iteration

Add a **locally verifiable hash-chained publication event journal** with integrity tests, clearly distinguishing it from signed provenance. Later introduce independently administered signatures and WORM-protected storage; then expose read-only graph APIs under authentication.

## Regressions

```bash
uv run pytest -q tests/test_assurance_catalog.py
uv run ruff format --check .
uv run ruff check .
uv run mypy src
```

Test deliberately includes altered report verdicts where the self-reported hash has been recomputed, corrupted evidence objects, duplicate publication events, missing references, and persistence after source file deletion.
