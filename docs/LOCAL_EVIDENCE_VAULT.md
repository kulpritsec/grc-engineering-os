# Local Evidence Vault — development foundation

**Status:** implemented local CLI-only storage with SQLite metadata and a SHA-256-addressed directory of source bytes. **Not production assurance storage.** This is a bounded adapter for the larger Kulprit Evidence Platform; it has no login, tenant isolation, digital signatures, WORM retention, encryption at rest, or trusted timestamps.

## Why this first?

The unified GRC OS must be able to keep a test artifact after its source file changes or disappears, retrieve metadata later, and detect when stored bytes no longer match the recorded digest. This makes that behavior testable without deploying AWS/Azure, installing a database server, or granting agents credentials.

The target enterprise interface will later support PostgreSQL metadata and S3-compatible locked object storage. SQLite and private local folders are an **interim implementation**, not a claim that the selected production database design has changed.

## Local quick start

```bash
uv sync --locked
printf "synthetic configuration evidence\n" > synthetic-observation.txt

uv run grcctl vault ingest synthetic-observation.txt --kind test-result
uv run grcctl vault list
uv run grcctl vault verify <ARTIFACT-UUID>
uv run pytest -q tests/test_vault.py
```

The default `evidence/vault` directory is excluded from Git. A different private storage directory can be chosen with `--root PATH`. Do not place real secrets, real customer PII or unapproved system evidence in this development vault.

## Storage contract

- Source is a **regular local file**; symbolic-link sources are denied and size is capped at 64 MiB.
- Bytes are streamed into a private staging file, hashed, then atomically hard-linked to `objects/sha256/xx/<digest>`; repeated content retains a single blob.
- Every ingest creates a **distinct UUID and timestamped metadata entry** in `vault.db`, including kind, filename and explicitly unverified operator-origin claim.
- `verify` detects missing content, digest/size mismatches, and symbolic-link object replacement.
- Existing corrupt blobs are not silently overwritten.
- Default store and metadata permissions must be owner-only; SQLite connections are short lived. Files created by the CLI are owner-readable only.
- A stored hash establishes local byte consistency, not collector authenticity, evidence relevance, chain of custody or unalterable retention.
- Metadata can still be altered by a sufficiently privileged local operator; there is **no independent attestation**. The filesystem owner can replace blobs, tamper with the SQLite database or purge evidence. The vault must not be marketed as audit-grade.
- The HTTP API remains **read-only structural preflight** and does not accept uploads or expose vault data.

## Model boundaries

Stored artifacts are **source evidence**, not control conclusions. Assessment observations and GRCML/KAEO/OSCAL links are a separate graph/metadata layer. Do not let `vault ingest` return `verified` as an assessment conclusion. `vault verify` only reports `matched`, `missing`, `hash_mismatch` or `unsafe_store`.

Next: define the storage adapter interface, add explicit CVP artifact links, design authenticated ingestion, signed manifests, retention, disaster-recovery tests, and a real audit-trail service. Those capabilities require distinct acceptance tests and security review.

## Known limitations and deferred hardening

- Single-process local development target; not audited for hostile concurrent filesystem writers, power-loss recovery or denial of service.
- Directory privacy and symlink rejection are useful guardrails, not a sandbox or comprehensive race-free OS security boundary.
- SQLite preserves ingest metadata only; there is no provenance-signing authority.
- No legal hold, retention lock, backup guarantee, tenant policy or data residency control.
- Data is **not encrypted at rest by this module**. Use only synthetic evidence until an enterprise storage trust model is implemented.
