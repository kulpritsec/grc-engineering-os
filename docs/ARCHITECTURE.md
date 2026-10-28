# Kulprit GRC Engineering OS — unified platform architecture (G0 draft)

**Status:** G0 working architecture; this is not production readiness or regulatory certification.  
**Decision:** start as a **single modular monolith** with a common assurance core and external, isolated workers.  
**Product lead:** human-led, approximately 20 hours/week; coding agents may prepare changes but do not self-approve architecture or releases.

## Guiding principles

1. One consistent **Control Verification Procedure (CVP)** for all assessment modules.
2. Separate **declared requirement**, **implemented configuration**, **observed behavior**, **assessment conclusion**, and **authorized decision**.
3. Treat source evidence as immutable/versioned; never edit original artifacts to reflect a later conclusion.
4. Explicit scope, time, provenance, known coverage limits and unknown outcomes; do not treat absence of findings as proof of effective security.
5. Prefer existing standards and tools: GRCML for GRC visualization, proposed KAEO for audit evidence semantics, W3C PROV-O for provenance, NIST OSCAL for assessment exchange, CycloneDX CBOM for crypto assets.
6. Tools submit observations, not compliance certificates. Deterministic rules or qualified reviewers issue bounded claim evaluations.
7. Keep active scan/emulation workers outside the evidence authority and policy database; no production targets without an authorization mechanism.
8. Local-first single-tenant deployment; tenant boundaries, signing, WORM and SaaS scale are explicit later gates, not assumed current features.

## Logical components

```text
Unified UI (future React) → Platform API (future FastAPI)
                                  │
                 ┌────────────────┼────────────────┐
                 │ Assurance Core │ Control Registry│
                 │ CVP Evaluator  │ GRCML / KAEO    │
                 └────────────────┼────────────────┘
                                  │
                  Evidence Vault / Graph / Intelligence
                                  │
                       Audit Runner (future)
                                  │
                  Authorized isolated workers (future)
              Scout | TraceSentinel | Crypto | Adversary
```

**Current implementation** (this branch): `grcctl` baseline/Terraform assessments, a Terraform plan to CVP bridge with per-rule pass/fail/unknown results, hash verification, CVP evaluation, local Evidence Vault, publication history/journal, separate signed collection-manifest verification and an unauthenticated FastAPI structural preflight starter. There is no unified operator web app, orchestration service, ontology reasoner, cloud agent, active network scanning or continuous scheduler yet. See [Signed Evidence Manifests](SIGNED_EVIDENCE_MANIFESTS.md) for the development trust decision and production boundaries.

## Canonical entities (target data model, not all implemented)

- `Requirement` (source, version, applicability, effective dates)
- `ControlObjective`, `Control` (owning role, declared/implemented state)
- `Asset`, `Identity`, `DataAsset`, `Flow` (stable IDs and scope)
- `CVP` (assertion, required checks, evidence kinds, negative control, test authorization)
- `Execution` (runner identity, timestamps, environment, authorization, collector version)
- `Observation` (method, outcome, value, scope, provenance and uncertainty)
- `EvidenceArtifact` (content digest, source, custody events, storage reference, retention)
- `Assessment` (verdict and rationale, coverage/freshness, references to inputs)
- `Finding`, `Risk`, `Exception`, `HumanDecision`
- `AuditEvent` (append-only actor, action, decision and transaction log)

Identifiers and versions are first class. Prefer relations to copying objects; introduce unique constraints, foreign keys and migration tests when persistent storage is implemented.

## Evidence trust boundaries

**Current alpha:** the CVP evaluator reads local file paths within the input workspace or resolves retained Vault ingestion UUIDs, checks SHA-256, declared test coverage and [evidence freshness](EVIDENCE_FRESHNESS.md) against a required procedure age policy, and determines a limited claim verdict. Freshness uses caller-declared collection and host ingestion times, not trusted time. Optional signed manifests separately authenticate collection statements against explicitly supplied external trust policy; CVP verdicts do not require or inherit that status. **Caller-declared scope is not independently authorized, observation truth is not attested, and a file hash is not a digital signature.** A locally supported `verified` verdict must never be displayed as FIPS certification or organization-wide regulatory compliance.

**Target maturity:** collector identities, signed manifests, trusted time sources, immutable/WORM-enabled storage, independent verification API, legal holds, per-object access policy, explicit evidence aging and revocation of stale assessments.

## Module boundaries and dependencies

| Module | Role | Depends on |
|---|---|---|
| Assurance core | CVP, claims, scope, observation/result semantics | canonical models |
| Evidence Vault | source artifact ingestion, digest, custody, retention, access | identity and storage |
| KAEO graph | evidence/claim/provenance relationships | canonical IDs and records |
| GRCML Studio | multiple visual projections over shared model | graph, controls, scope |
| Audit Runner | authorized jobs, schedules, retries, coverage, worker orchestration | CVP, identity, scoped workers |
| Scout | discovery and bounded technical observations | worker API |
| TraceSentinel | synthetic tracer, lineage, activity events, evidence | worker API, graph |
| Crypto Assurance | CBOM, encryption paths and module-use evaluation | worker API, graph |
| Evidence Dynamics | history, benchmarking, temporal quality, signal analytics | verified time series |
| RiskAI | independent quantitative risk scenarios and results | scoped findings, uncertainty |

A specialized module does not own the final regulatory determination.

## First build gates

**G0 architecture:** document key ADRs, risk boundaries, schema versioning and modular design.  
**G1 executable CVP:** local file-backed verified/failed/inconclusive/not-tested fixtures; original file digests and output artifact verification. **In progress on this branch.**  
**G2 trusted evidence foundation:** restricted artifact upload, authenticated collector, signing, protected storage and verification, migration tests.  
**G3 integrated vertical slice:** existing Terraform scanner mapped to CVP, simple API/UI, GRCML/KAEO projection, one explainable report.  
**G4 controlled labs:** TraceSentinel/crypto local fault injection, AWS/Azure with approved budgets and teardown.  
**G5 pilot:** authentication, secure workers, auditor separation, performance, backup/restore, repeatable upgrades, independent security review.

Do not skip the evidence-trust gate before marketing an audit-grade product.

## ADRs to resolve next

- ADR-001: modular monolith; Python/Pydantic core; worker boundary.
- ADR-002: canonical identifier namespaces and schema versioning.
- ADR-003: PostgreSQL and S3-compatible storage; whether/when RDF graph projection is materialized.
- ADR-004: evidence custody, digital signatures, independent verification and time semantics.
- ADR-005: human approvals, authorization scopes, identity/tenant isolation.
- ADR-006: GRCML/KAEO metamodel alignment, including manuscript node-count inconsistencies.
- ADR-007: agentic development roles, budgets, review ownership and code provenance.
- ADR-008: CVP assertion-verification semantics, including positive/negative fixtures and non-declarative scope authorization.

Related designs on existing branches: `docs/tracesentinel-validation-labs.md` and `docs/k-caef-evaluation-framework.md`. These are not merged into this branch.
