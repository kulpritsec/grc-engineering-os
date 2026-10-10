# K-CAEF v1.0 — Kulprit Cryptographic Assurance Evaluation Framework

**Status:** Proposed methodology (not a certification, validated standard, or executed test report).  
**Product:** Kulprit Crypto Assurance, GRC Engineering OS  
**Related designs:** `docs/crypto-assurance-cbom.md`, `tests/specifications/crypto-assurance-cases.json`.

## Purpose and unit of assessment

Assess specific cryptographic **assertions** for a declared system, data class, geographic/environmental boundary, cryptographic operation and time window. A system may be secure for one flow and not another, and may support a FIPS-validated operation without having FIPS-validated protection for unrelated operations.

Use the GRC Engineering triad:
1. **Declared:** policy/architecture says what must happen, including applicability and intended E2EE endpoints.
2. **Implemented:** discovered software/hardware modules, algorithms, certificates, crypto protocols, keys *metadata*, configurations, modes, and actual data flow edges.
3. **Effective:** authorized operational tests and telemetry confirm the intended behavior over specified time windows, with reproducible evidence.

Every assessment records: `assessment_id`, `asset_or_flow_id`, `data_classification`, `scope`, `assertion`, `requirement_source/version`, `applicability`, `method`, `observation_ids`, `collector_and_version`, `observed_at`, `valid_until`, `limitations`, `status`, `reviewer`, `signoff`. A missing required observation yields **inconclusive** or **not tested**, not verified.

## Normative sources and interoperability

Use the currently applicable customer/regulator-approved versions, with explicit version pins:
- **NIST FIPS 140-3 / CMVP:** module-specific validation and certificate + security policy, exact deployed version/build, operational environment, approved service and operational mode; see https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules
- **NIST SP 800-52 Rev. 2:** TLS implementation selection and configuration; https://csrc.nist.gov/pubs/sp/800/52/r2/final
- **NIST SP 800-57 Part 1 Rev. 5:** cryptographic key lifecycle; https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- **NIST SP 800-131A Rev. 2:** algorithm/key-length transition decisions; https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
- **NIST SP 800-53 Rev. 5:** selected SC-8, SC-12, SC-13, SC-17, SC-28, as applicable.
- **PCI DSS v4.x** Req. 3 and 4, if in scope; customer-specific relevant ISO 27001:2022 controls.
- **CycloneDX v1.7 CBOM:** serialization and field semantics; https://cyclonedx.org/docs/1.7/json/
- **PQC:** NIST FIPS 203, 204, 205 inventory/migration planning where relevant. FIPS approval of algorithms is not a module validation.

## Seven assessment domains (proposed default weights; configurable per assessment scope)

| Domain | Weight | What constitutes evidence |
|---|---:|---|
| D1 Inventory / CBOM completeness | 10 | Discovered endpoints, crypto libraries/modules, algorithms, certificates, cryptographic dependencies; schema validity; scanner coverage |
| D2 Algorithm, strength & protocol | 15 | TLS/SSH settings and observed negotiated parameters; accepted algorithm suites; PKI path validation; applicable algorithm-transition rules |
| D3 FIPS validated-module use | 20 | Official CMVP cert with status plus deployed exact module/version, covered crypto service, operating environment and approved-mode operation **when FIPS requirement applies** |
| D4 Key and certificate lifecycle | 15 | KMS/HSM metadata, lifecycle, access privileges, rotation/expiry, custody and revocation testing without exporting secrets |
| D5 Data-path encryption protection | 20 | Complete declared path and observed coverage, encryption termination and reencryption, at-rest vs in-transit vs application-layer and true-E2EE distinction |
| D6 Operational control effectiveness | 15 | Controlled positive and negative tests, drift detection, denial/alert outcome, monitored crypto operations, recovery/resilience where applicable |
| D7 Evidence provenance and crypto agility | 5 | Reproducible, time-bounded observations and signed provenance as available; versioned CBOM and migration/deprecation dependencies |

Weights sum to 100 **only where all seven apply**. For out-of-scope domains (e.g., no FIPS requirement), remove their weights and rescale the remainder; publish applicable-domain coverage and the omitted-domain rationale. Do not imply a non-FIPS assessment established FIPS conformance.

### Domain scores vs assurance outcomes

Use two orthogonal axes:
- **Implementation capability/maturity level (0–4):** 0 absent/observed failing; 1 declared; 2 implemented/configured; 3 independently validated at defined point in time; 4 continuously monitored with reliable verification and drift response.
- **Assertion result:** `verified | failed | inconclusive | not_tested | exception | not_applicable`. Missing data is not equivalent to observed failure; it is also not success.

Proposed descriptive index `readiness = sum(applicable weights × maturity/4) / sum(applicable weights) × 100`. **Never publish readiness as a compliance or FIPS pass.** Also report: tested assertion coverage, telemetry coverage, evidence recency, high-severity failures, remaining exceptions, and verification confidence.

## Mandatory assertion gates (cannot average away)

1. **Required FIPS 140-3 operation:** Applicable module/service requirement must have current official CMVP and vendor security-policy references with demonstrated deployed-module/version, permitted operational environment, approved service/mode use and proper cert status. Revoked, mismatched or disallowed is `failed`; unknown specifics is `inconclusive`. Historical validation requires explicit separately approved policy treatment; do not silently treat historical FIPS 140-2 as active FIPS 140-3.
2. **True E2EE claim:** Define legitimate cryptographic endpoints and key holders; require evidence intermediate infrastructure **cannot decrypt** relevant payload. If a proxy, service, managed processor or other intermediary can decrypt, status is `hop_by_hop_encrypted` not true E2EE. Unless the requirement specifically demands E2EE, this may still satisfy a transport-encryption control.
3. **Protection-required segment:** Observed plaintext on a segment whose applicable requirement mandates encryption is `failed`. Lack of visibility is `inconclusive`.
4. **Key-control critical failures:** Demonstrated unauthorized test identity key access, compromised key, or other scope-specific critical failure blocks overall assertion verification.
5. **Missing critical evidence or out-of-scope testing:** Never report a passing mandatory assertion.

## Claim-specific verification procedures

- `CVP-CRYPTO-001`: Certificate chain, expiration, revocation applicability, hostname binding and endpoint scope.
- `CVP-CRYPTO-002`: End-to-end/transport/storage path test: enumerate trust boundaries, record each handshake and application termination, verify final intended endpoints and intermediate decrypt rights.
- `CVP-CRYPTO-003`: FIPS service validation chain: customer control requirement -> crypto operation -> workload/process/module -> CMVP cert/version/OE/approved mode/service -> artifact + reviewer.
- `CVP-CRYPTO-004`: KMS key lifecycle and allow/deny test on **synthetic** key and records.
- `CVP-CRYPTO-005`: CycloneDX CBOM schema validity, asset/reference completeness, stale inventory and drift.
- `CVP-CRYPTO-006`: Algorithm deprecation and crypto-agility/PQ preparation.

Each assessment should produce a GRCML graph from requirement to control to implementation, actor/owner, test, observation and evidence; a path diagram annotating encrypted, plaintext and unknown segments; separate FIPS and E2EE verdicts; and signed/hashed evidence status with all limitations.

## How we validate **the Kulprit tool itself** (distinct from auditing customer cryptography)

Use known-ground-truth local, AWS, and Azure fixtures cataloged in `tests/specifications/crypto-assurance-cases.json`:
- Positive and negative TLS; proxy terminates/re-encrypts; cleartext backend; mTLS missing peer auth; certificate expiry/SAN mismatch/rotation.
- CMVP-certificate valid but wrong module version; module valid but approved-mode not shown; vendor claim only; historical/revoked certificate; missing data.
- KMS allowed/denied synthetic key, encrypted at-rest without E2EE, deliberately incomplete scanner visibility.
- Managed-service opacity, async data-flow transformation, IAM and logging gaps.

### Proposed tool quality gates (engineering targets, to calibrate against benchmark)

- **Zero false VERIFIED claims** for intentionally non-E2EE paths and unproven FIPS module/service use in the curated negative corpus.
- 100% of mandatory-claim evaluations link exact observation/CMVP source or return `inconclusive/not_tested`.
- 100% of generated CBOM samples validate against target CycloneDX 1.7 official schema.
- High recall for seeded inventory assets with explicit coverage and observed false-negative rate, segmented by collector/tool and access level; numerical recall targets only after lab baseline.
- Deterministic runs under the same inputs yield same verdict and reproducible normalized artifact fingerprints; timestamps/provenance are recorded separately.
- No private-key extraction; synthetic-only testing and bounded/scoped network probes.
- Record false positive rate, false negative rate, observability coverage, drift-detection latency, evidence age, cloud-cost impact and assessment execution duration.

## Example final verdict object

```json
{
  "assessment_id": "KCAEF-DEMO-001",
  "scope": "Synthetic PII demo: browser to API to database",
  "assertions": {
    "encrypted_transport": "verified",
    "true_end_to_end_encryption": "failed",
    "fips_140_3_validated_use": "inconclusive"
  },
  "evidence": {
    "proxy_terminates_tls": true,
    "backend_tls_observed": true,
    "cmvp_reference_present": false,
    "coverage": "partial"
  },
  "overall": "requires_review",
  "note": "Illustration only. No production scan or assessment has run."
}
```

**Scientific evaluation priority:** benchmark ground truth and false-assurance rate before generalizing risk scores or automatic regulatory verdicts. A correct `inconclusive` is more valuable than an unjustified `verified`.
