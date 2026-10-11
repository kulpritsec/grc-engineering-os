# G2 evidence trust baseline and proposed sprint

Date: October 10, 2026. Status: development contract approved by the project product owner in the Codex session; implementation and independent acceptance remain under review.

The platform has a working local assurance and preservation foundation. Its next useful increment is a portable signed manifest verified against separately configured collector trust anchors. Existing byte checks and assessment verdicts must retain their current meaning. Signing authenticates a statement within an approved trust policy; it does not prove that an observation happened or that a control is effective.

## A Current state

Reviewed development head: `c8b578086fbb5a4fc47c5d821f689e47452bc032`, branch `feature/assurance-publication-journal`. The five foundational PRs are open, draft, and unmerged:

| PR | Base | Implemented increment |
| --- | --- | --- |
| [16](https://github.com/kulpritsec/grc-engineering-os/pull/16) | docs/alpha-2 | CVP contracts, deterministic evaluator, local FastAPI preflight |
| [17](https://github.com/kulpritsec/grc-engineering-os/pull/17) | feature/unified-platform-foundation | SQLite metadata, bounded SHA-256 object storage, ingestion UUIDs |
| [18](https://github.com/kulpritsec/grc-engineering-os/pull/18) | feature/local-evidence-vault | CVP references to retained Vault records |
| [19](https://github.com/kulpritsec/grc-engineering-os/pull/19) | feature/cvp-vault-artifact-links | Reevaluated publication, history, evidence relationships |
| [20](https://github.com/kulpritsec/grc-engineering-os/pull/20) | feature/assurance-history-catalog | Transactional publication/link hash chain |

[GitHub CI run 22](https://github.com/kulpritsec/grc-engineering-os/actions/runs/38086534789) reports completed/success for this head. The connector exposes the workflow conclusion, not its detailed test log; the handoff's Linux test count was not independently recovered from that log.

Local checks on Windows, Python 3.13.14:

| Gate | Actual result |
| --- | --- |
| uv sync --locked | Passed |
| Ruff formatting | Passed, 38 files |
| Ruff lint | Passed |
| mypy with platform-dev requirements | Passed, 16 source files |
| pytest with platform-dev requirements and coverage | 52 passed, 2 failed, 1 skipped; 85.60% coverage |
| uv build | Passed, source archive and wheel |

Failures: `test_insecure_plan_produces_expected_findings` assumes POSIX 0600 modes; `test_rejects_symlinked_source_and_symlinked_blob` cannot create Windows symlinks (WinError 1314). The Unix privacy test skips on Windows. Four warnings: one Starlette/AnyIO deprecation and three unclosed SQLite connection ResourceWarnings. These results do not establish Windows ACL security or a fully passing local suite. Tests and runtime code were left unchanged.

Doctor, Terraform plan rules, schema/hash verification, Vault ingestion/verification, four CVP outcomes, persistent publications and journal checking are implemented. API preflight checks structure without executing assessments or reading evidence. Collector authentication, signatures, trusted time, retention, tenant isolation, production API security, orchestration and the specialist modules remain incomplete or planned.

## B Architecture assessment

- Reuse `VaultArtifact`, `ArtifactReference`, `LocalEvidenceVault.verify`, catalog publication checks and journal transactions. Keep manifest verification a separate subsystem with no producer or SQLite dependency for portable verification. Do not duplicate the evaluator or storage engine.
- Documentation has drifted: ARCHITECTURE.md still says no Vault; README and API landing copy contain similar outdated statements; CVP_VAULT_LINKS.md still says relationship persistence is future work. Reconcile these in the implementation documentation change.
- `catalog.py` uses the Vault's private `_connect`; establish a public transaction/storage adapter before replacing SQLite. Declared foreign keys are not enabled by `_connect`, and artifact links lack database foreign keys. Migration tests must precede schema changes.
- Report ingestion occurs before the publication transaction, so refusal or rollback can leave an unreferenced retained report. Treat this as preservation without publication, never a committed assessment. Define recovery and cleanup separately.
- The CVP checks bytes and caller-supplied outcomes, scope and coverage. It does not interpret source evidence to substantiate an observation. Required evidence kinds are aggregated across observations rather than bound to each required check. A failing extra observation can determine `failed`; decide whether that is intended before changing semantics.
- There is no evidence freshness policy or authenticated procedure registry. A stale artifact can currently support `verified`; a caller can change the assertion itself. Report schemas allow default versions and ignore unknown fields. Signed contracts need explicit versions, strict validation and rejection of unsupported fields.
- Publication reevaluates verdict/checks, but not equality of reasons, limitations or trusted evaluation time. A self-rehashed report can change those fields. Signed metadata must not silently become an approved conclusion.
- Platform dependencies are pinned separately from uv.lock, with transitive dependencies resolved at execution. Integrate these into a reviewed locked extra/group before claiming repeatable dependency closure.

## C Security assessment

| Threat | Existing protection and remaining boundary |
| --- | --- |
| Artifact alteration | SHA-256 and size checks detect mismatch against current metadata; operator can replace both metadata and bytes |
| Fabricated collection | Origin, scope and outcomes are caller claims; no authenticated collector or authorization record |
| Storage compromise | POSIX privacy checks and some symlink rejection; Windows ACLs, hostile ancestor replacement, concurrent writers and filesystem races are not comprehensively enforced |
| Resource exhaustion | Ingestion is bounded; legacy file evaluation uses unbounded read_bytes, report/JSON inputs and verification streams lack equivalent global budgets |
| Publication rewrite or rollback | Local chain catches inconsistent edits; rewriting all hashes, coordinated truncation or complete deletion can evade checks |
| Misleading journal result | Journal checks report digest and links, not every publication field or artifact byte; empty/new stores can report consistent without prior-history knowledge |
| Signing key compromise | No current signing; future trusted-key possession authenticates a statement, not truth or authorized execution |

SQLite errors are not uniformly translated to domain failures. CLI assurance evaluation also returns normally for negative verdicts; consumers must not infer control success from process success. Independent witnesses, durable anti-replay state, trusted timestamps and protected key custody remain separate future controls.

## D Proposed first sprint

Budget: 26 engineering hours. The product owner approved this development contract; [issue 21](https://github.com/kulpritsec/grc-engineering-os/issues/21) tracks implementation and acceptance. The original review was completed before implementation.

| Work | Hours | Deliverable |
| --- | --- | --- |
| Trust model and approved ADR | 4 | Collector identity, authority boundaries, canonical bytes and fixture contract |
| Strict manifest model and vectors | 5 | Versioned portable representation and fixed independent fixtures |
| Separate verifier and synthetic producer | 5 | Offline signature, identity, artifact and policy checks |
| Adversarial validation | 6 | Negative, tamper, replay and failure cases |
| Additive Vault linkage and regression checks | 4 | Preserved manifest references without changing CVP verdict rules |
| Documentation and CI review | 2 | Reproduction commands, limitations and draft PR after approval |

Proposed review contract:

1. Use the approved development-only Ed25519 signing profile with synthetic keys and a maintained cryptographic library. This carries no FIPS validation claim. Do not implement production custody, enrollment, KMS or hardware decisions in this sprint.
2. Bind collector ID and key ID to a separately supplied verifier trust file containing the public key, allowed purpose/scope, validity interval and explicit revocation state. Never trust a public key embedded in the manifest. A collector ID is authenticated only through that configured binding; it is not proof of real-world identity enrollment.
3. Sign a versioned payload containing manifest UUID, collection/execution ID, collector ID/version, key ID/algorithm, scope, claimed collection time, artifact ingestion UUIDs/kinds/SHA-256/sizes, and optional assessment ID/procedure ID/report digest. Do not equate a collection timestamp with trusted time or a manifest UUID with replay protection.
4. Define deterministic UTF-8 JSON bytes for a restricted schema: sorted keys, compact separators, no floats, no NaN, duplicate-key rejection, explicit UTC timestamp syntax, bounded strings/lists and deterministic artifact ordering. Sign a domain-separated prefix plus canonical payload bytes. Reject unsupported versions/algorithms and unknown fields. Freeze byte-level test vectors before implementation; do not reuse the legacy hash serializer without specifying its semantics.
5. Verify a bundle using only manifest, preserved artifact bytes, externally configured trust policy, caller-supplied expected context and verification time. Verify key authorization, signature and every artifact digest/size. Return separate structure, signature, identity-policy, artifact and context results. Missing trust is an explicit failure/unknown, never authenticated.
6. Collection freshness and key validity use explicit verification time; signed historical times cannot bypass revocation. Default revoked keys to rejection. No offline claim of real-time revocation; trust-policy freshness must be visible.
7. Require expected execution/scope/context for acceptance. A portable offline verifier cannot detect repeat use by itself. An optional caller-managed seen-manifest registry can reject duplicate consumption; its local rollback limitations must be explicit. Duplicate source bytes with distinct authorized collection identities remain valid.
8. Retain manifests as new Vault artifacts and add separate verification/link metadata. Preserve legacy unsigned workflows; unsigned evidence must never acquire authenticated status by inheritance. Initially record authentication alongside assessments without upgrading their verdicts. Any later requirement that CVPs mandate authenticated evidence needs a separately approved policy change.

Human decision owner: project product owner. Approval must cover the signing profile, identity binding, canonical payload, revocation/freshness policy and additive integration boundary. Verification fixtures must be reviewed independently; the implementing agent cannot certify its own evidence trust.

## E Acceptance criteria

| Category | Required observable behavior |
| --- | --- |
| Positive | Fixed externally checked signature vector and synthetic bundle pass with correct independent trust anchor; verification works after producer and source files are removed |
| Negative | Wrong key, unknown collector/key, missing anchor, unauthorized scope/purpose, expired/not-yet-valid/revoked key and missing artifact cannot authenticate evidence |
| Tamper | Every signed field mutation, signature bit flip, artifact modification, size mismatch and ingestion-UUID substitution fail the corresponding check |
| Canonicalization | Stable golden bytes across producer/verifier; alternate permitted JSON layout has defined behavior; duplicate keys, unknown fields, unsupported versions/algorithms, invalid timestamps and excessive input are rejected |
| Replay | Wrong expected execution, scope or assessment digest fails context checks; duplicate consumption fails when configured seen-state is enabled; stateless verification explicitly reports replay detection unavailable |
| Failure modes | Unreadable trust/bundle, malformed SQLite and interrupted linkage yield explicit errors, no authenticated record and no false publication success |
| Regression | Existing unsigned CLI interfaces and all four CVP outcomes retain semantics; signatures cannot turn missing, failed or contradictory observations into verified controls |
| Migration | Existing Vault/publications remain readable; new linkage failure does not manufacture journal events or retrospectively sign history |
| Quality and review | Required gates pass in supported Linux CI, local platform failures remain disclosed, fixtures and trust ADR receive human review before acceptance |

## Reproduce the baseline

```powershell
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run --no-sync --with-requirements requirements/platform-dev.txt mypy src
uv run --no-sync --with-requirements requirements/platform-dev.txt pytest --cov=grcctl --cov-report=term-missing --cov-fail-under=70
uv build
```

This assessment is an AI-assisted engineering review, not an independent security certification. The product owner approved the development manifest contract after this baseline review in the October 10, 2026 Codex session. Production decisions and independent security acceptance remain subject to human approval.
