# Local signed evidence manifests

Status: development-only implementation for synthetic evidence. The project product owner approved the G2 development trust contract in the October 10, 2026 Codex session. Independent fixture/security review and final acceptance remain outstanding. Tracks [issue 21](https://github.com/kulpritsec/grc-engineering-os/issues/21), on top of draft PR 20.

## Trust decision

This implements the development portion of ADR-004 from ARCHITECTURE.md: portable Ed25519 collection statements, separately administered collector trust anchors, explicit verification time/context, and additive local authentication metadata. Production enrollment, key custody, rotation, hardware/KMS selection, independent witnesses and protected storage remain undecided.

The signing authority asserts that the listed bytes and collection metadata belong to a named execution. The verifier authenticates that statement only against a collector/key binding in its independently selected trust file. Possession of a trusted private key does not prove that an observation is truthful, collection was authorized, or a control is effective. A collector identity here is a configured key binding, not externally certified enrollment. Existing CVP outcomes keep their original semantics.

The producer is `manifests/producer.py`; the standalone verifier never imports it or the Vault. A verifier needs only the envelope, artifact bytes, external trust policy, expected context and verification time. Artifact locations come from the verifier's caller; the manifest cannot direct arbitrary file reads. The portable CLI expects artifact filenames equal to their signed ingestion UUIDs.

## Version 1 representation

The envelope has exactly `payload` and a lowercase hexadecimal 64-byte `signature`. The payload explicitly supplies version `1`, algorithm `Ed25519`, purpose `evidence-collection`, manifest UUID, execution/collector/version/key identities, scope, claimed UTC collection time, artifacts and `assessment`. The latter is either null or the complete assessment ID, procedure ID and report SHA-256 context. Each artifact supplies its ingestion UUID, kind, SHA-256 and byte count.

Canonical signing bytes are the literal ASCII domain `kulprit-grc/evidence-manifest/v1`, one NUL byte, and the canonical payload JSON. JSON keys sort lexicographically; artifacts sort by their ingestion UUID; separators are comma/colon with no whitespace. `ensure_ascii=True` encoding is UTF-8. Token strings accept only printable ASCII, 1–256 characters. Digests and UUIDs use lowercase canonical forms. Times use exactly `YYYY-MM-DDTHH:MM:SSZ` with calendar validation. No Unicode normalization or general RFC 8785 claim is made.

Unknown or duplicate keys, absent required fields, unsupported versions/algorithms, duplicate ingestion IDs, floats, nonfinite values, coercions and malformed dates are rejected. JSON inputs are capped at 256 KiB, lists at 64 artifacts, each artifact at 64 MiB, and total declared bytes at 256 MiB. Reads are bounded by the signed size and reject symbolic-link paths and nonregular inputs. Artifact ordering and ordinary JSON layout may differ without changing canonical signing bytes; the verification result also records the original envelope SHA-256.

Fixed bytes and signature in `tests/fixtures/manifests` were generated with independent PyNaCl/libsodium, without the project codec/producer. A separate known-answer check uses the published [RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1) test vector. The runtime uses PyCA's [Ed25519 signature verification API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/). Publicly published test seeds are clearly identified as synthetic test data and must never become real collector keys.

## External trust policy

The policy explicitly supplies version, update/expiration time, maximum collection age and collector/key anchors. Each anchor provides a raw public key, fixed signing purpose, exact authorized scopes, validity interval and revoked flag. Keys from an envelope are never trusted; extra embedded-key fields fail validation.

Acceptance requires `updated_at <= verification_time < expires_at`, an unrevoked key valid at verification time, a collection time no earlier than key validity and no later than verification time, and collection age within the policy limit. Revoked keys are rejected even for claimed historic collections. All time checks depend on explicitly supplied time and claimed collection time; there is no trusted timestamp service. The result records the exact trust-file hash and policy update time. An expired or unreadable policy cannot authenticate a statement. Offline checks cannot learn revocations omitted by the operator's policy.

## Operator demonstration

Use a new directory under ignored `evidence/`. The demo creates synthetic bytes, an in-memory random signing key, a demo trust policy and an expected context. It deletes the original source and never saves the private key. A trust file generated by the producer is only a fixture; real enrollment requires separately reviewed trust provisioning.

```powershell
uv sync --locked
uv run grcctl manifest demo evidence/manifest-demo --at 2026-10-10T12:00:00Z
uv run grcctl manifest verify evidence/manifest-demo/manifest.json --trust evidence/manifest-demo/trust.json --context evidence/manifest-demo/context.json --at 2026-10-10T12:01:00Z --bundle evidence/manifest-demo/bundle
uv run grcctl manifest link evidence/manifest-demo/manifest.json --trust evidence/manifest-demo/trust.json --context evidence/manifest-demo/context.json --at 2026-10-10T12:01:00Z --vault-root evidence/manifest-demo/vault
```

Portable verification prints separate structure, signature, identity-policy, artifact, context and replay results. `authenticated: true` means those checks passed under the supplied policy. It is never a CVP or compliance conclusion. Verification exits 0 on authentication, 1 on a completed negative check, and 2 on input/registry errors. Linkage errors exit 2 without claiming a committed authentication record.

## Replay and linkage

Expected execution, scope and optional assessment context must match. Stateless verification reports replay protection `unavailable`; callers needing consumption checks can add `--seen-registry PATH`. The registry rejects a previously consumed manifest UUID in an immediate SQLite transaction. It does not detect a trusted signer reissuing a new manifest UUID or protect against registry deletion, coordinated rewrite or rollback. Distinct authorized collections may preserve the same artifact bytes.

Vault linkage always consumes locally. It checks signed UUID/kind/digest/size against existing Vault records, verifies retained bytes, and preserves snapshots of both manifest and trust policy as new artifacts. Output includes their retained UUIDs. `manifest_verifications` holds verification snapshots and an optional publication ID; `manifest_artifact_links` records signed ingestion UUIDs. It does not rewrite the existing artifact, assessment or journal tables. These new tables are local mutable metadata, not independently signed endorsements by the verifier.

For an existing assessment publication, add `--publication-id UUID` and supply matching signed assessment context. Linkage also checks the journal, preserved report bytes, procedure/scope/report digest and exact evidence artifact set. Authentication neither changes the verdict nor retroactively signs a prior journal. A negative CVP remains negative. Consumption, verification record and artifact links commit together. A failed transaction may leave preserved snapshot ingestions without links, just as existing publication preservation can leave orphans; it cannot leave a successful link or consume the manifest. Recovery does not delete retained evidence automatically.

Existing Vaults gain only new tables when linkage succeeds. Older publications and unsigned CLI workflows continue to work. To roll back application code, retain the additional rows/blobs; old code ignores them. No backfill, retrospective signatures or trust inheritance occurs. Consumers must reverify preserved manifest/artifact snapshots against current independent trust and context rather than treating a historical check JSON as current authentication.

## Validation and remaining boundaries

```powershell
uv run pytest -q tests/test_manifests.py tests/test_manifest_store.py
uv run ruff format --check .
uv run ruff check .
uv run --no-sync --with-requirements requirements/platform-dev.txt mypy src
uv run --no-sync --with-requirements requirements/platform-dev.txt pytest --cov=grcctl --cov-report=term-missing --cov-fail-under=70
uv build
```

Tests cover fixed vectors, all signed field mutations, wrong anchors, revoked/expired/future keys and policy, stale/future collection, byte/size tampering, schema ambiguity, replay/context substitution, publication association, corrupt databases and transaction failure. The existing Linux-only mode and symlink tests still have disclosed Windows limitations; Windows ACL privacy is not established.

Host administrators can compromise signing keys, trust policy, local clocks, registries and storage. Path checks are guardrails, not a race-free hostile filesystem boundary. Metadata remains unsigned and operator-mutable. No production private keys, HTTP uploads, cloud resources, retention locks, independent witnesses or regulatory assurance claims are introduced. The original API dependencies remain outside uv.lock in platform-dev requirements; consolidating them is a separate follow-up.

## Local validation results

October 10, 2026, Windows with Python 3.13.14 and locked cryptography 50.0.2: all 74 new manifest/storage cases pass. Full suite: 126 passed, 2 failed, 1 skipped, four warnings, 88.58% coverage. The two existing failures are the POSIX 0600 assertion and Windows symlink privilege requirement; the existing Unix privacy case skips. Warnings include one Starlette/AnyIO deprecation and three existing unclosed SQLite connection warnings. Formatting (50 files), Ruff, mypy (24 source files), locked sync and package build pass. Runtime lock export scanned with pip-audit reports no known vulnerabilities; optional API/dev dependencies were outside that audit. A scoped source pattern scan found no AWS tokens, GitHub tokens or serialized private-key blocks. The public RFC test seed is intentionally present in tests.

The draft PR's Linux CI and human independent validation provide separate acceptance evidence. Local test results do not certify Windows ACL privacy or production evidence trust.
