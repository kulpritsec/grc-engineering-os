# Kulprit Crypto Assurance — CBOM, encryption paths, and FIPS 140-3 validation

**Status:** Proposed product design and test specifications only. Not implemented or executed.  
**Parent:** GRC Engineering OS / Kulprit Scout Suite  
**Integrations:** GRCML Studio (model), Kulprit Trace (data paths), Audit Runner (continuous tests), Kulprit Evidence (provenance), RiskAI (prioritization).  
**References:** CycloneDX v1.7 CBOM (https://cyclonedx.org/capabilities/cbom/); NIST CMVP (https://csrc.nist.gov/Projects/cryptographic-module-validation-program/validated-modules); FIPS 140-3 (https://csrc.nist.gov/pubs/fips/140-3/final).

## Questions this product must answer

1. What cryptographic assets are deployed and *where are they used*? Discover certificates, key identifiers/metadata, algorithms, protocols, cipher suites, modules, crypto libraries, HSM/KMS, signer/verifier services, endpoints, versions and dependencies.
2. For an explicitly scoped data journey, what encryption protects each segment and where do decryption/termination boundaries exist? Distinguish end-to-end encryption (only defined ultimate endpoints can decrypt) from hop-by-hop TLS, transport encryption, encrypted storage, application payload encryption and unverified transit.
3. Is a **particular** in-scope cryptographic service demonstrably implemented through a CMVP-validated FIPS 140-3 cryptographic module in the approved operational mode, with the correct version, platform/operating environment, algorithm/service, validation certificate status and security-policy restrictions? If not fully demonstrated, record an evidence gap, not a binary claim of FIPS compliance.
4. Which assets are due for expiry, cryptographic rotation, deprecation, remediation or post-quantum migration?

## Functional modules

- **CryptoDiscover:** Approved active TLS/SSH inspection and read-only endpoint, source, binary/package, configuration, certificate, cloud KMS/HSM and trust-store collection. Record vantage point and collector limitations; scope all network probes.
- **CryptoBOM:** Emit schema-valid CycloneDX **1.7** CBOM with cryptographic assets and dependencies; optional 1.6 exchange compatibility. Internal relational graph includes system, service, trust boundary, endpoint, certificate, algorithm, protocol, library, cryptographic module, key *reference*, FIPS certificate *reference*, data flow and policy.
- **CryptoPath:** Annotate TraceMap edges with protection type, TLS versions/cipher observations, termination, plaintext handling, re-encryption, mTLS/authentication and at-rest encryption. A TLS handshake proves a specific observed endpoint exchange—not complete application or endpoint-to-endpoint confidentiality.
- **CryptoValidate:** Evaluate FIPS assurance through vendor CMVP certificate evidence (status, module/firmware/software version, approved mode, validated operating environment, covered algorithm/service, security-policy restrictions). A CAVP algorithm certificate alone is not sufficient; a cloud service marketing statement alone is not sufficient. Check status against the current NIST CMVP source.
- **CryptoAgility:** Identify deprecated primitives, vulnerable dependencies, certificate replacement/rotation and cryptographic reliance for eventual PQ migration. This is preparedness analysis, not a claim of PQ resistance.
- **CryptoProof:** Emit GRCML-linked Control Verification Procedure (CVP) results with observation IDs, scope, timestamps, evidence hashes, source provenance and limitations. No secret key materials in the BOM or evidence.

## Claim taxonomy (distinct results)

### Encryption path status
- `true_e2ee_supported`: evidence that only the defined legitimate ultimate endpoints control decryption keys and intermediate systems cannot decrypt; verification procedures define boundary and limits.
- `hop_by_hop_encrypted`: encrypted transport on observed segments with an intermediate termination/decryption point.
- `partially_encrypted`: at least one required segment observed or configured in plaintext.
- `encryption_unverified`: insufficient evidence for one or more relevant segments, especially encrypted inner payloads or managed services.
- `not_applicable`: documented exception/irrelevant cryptographic assertion.

### FIPS service assessment
- `validated_use_verified`: validated FIPS 140-3 module identified from official CMVP certificate; exact deployed version, appropriate validated/allowed operational environment, approved mode and algorithm/service use evidenced for scoped function.
- `module_validated_use_unverified`: corresponding module validated but insufficient proof of actual deployed operation.
- `vendor_claim_only`: vendor materials cite a validation without sufficient technical deployment evidence.
- `mismatch_or_nonapproved`: tested configuration does not satisfy module certificate/security policy requirements.
- `unassessed`: required evidence absent.
- `exception_or_out_of_scope`: formally documented.

Do **not** equate an algorithm's FIPS-approved status with a module's CMVP validation; do **not** describe a product or network path as globally "FIPS 140-3 certified." As of 2026-09-22, FIPS 140-2 validations moved to Historical; retain distinct historical/legacy status and never silently treat it as 140-3 (see NIST CMVP program transition guidance).

## CBOM minimum evidence catalog

| Type | Example metadata, never private material |
|---|---|
| X.509 certificate | Fingerprint, SAN, issuer/subject, key type and length, algorithm, notBefore/notAfter, chain anchors, endpoint(s), certificate location and export permission |
| Algorithm | Algorithm name/OID, primitive, parameters, mode, strength/usage, discovered library or module |
| Protocol/session | TLS/SSH/IPsec version, negotiated suite, direction, endpoint, certificate/peer auth, timestamp/vantage point |
| Module | Vendor, exact version/build, CMVP certificate ID/status, validated environments, restrictions and approved operating mode evidence |
| Crypto library | Product/package, version/build, process/workload, linked binary/container, loaded provider and configuration |
| Key metadata | Provider, non-secret key ID, key class/algorithm/length, lifecycle, location/region, roles, key origin and rotation evidence |
| KMS/HSM | Provider/service, region/partition, supported functions, module supplier and evidence references |
| Protection boundary | Data classification, trust boundary, application/transport encryption mode, termination point, plain-processing point |
| Evidence | Collector version, source, timestamp, input hash, validation method, target, scope and limitations |

Use official CycloneDX `cryptographic-asset` and `cryptoProperties` definitions for serializable assets, with versioned Kulprit extensions or companion provenance records where the standard does not encode assessment/CMVP specifics. Validate generated files against the official 1.7 JSON schema; never claim interchange compliance from an unvalidated custom JSON format.

## Example crypto path: important semantics

```text
External client -- TLS --> CDN/WAF (TLS terminates, plaintext available to service)
CDN/WAF -- TLS --> Application (TLS terminates, process plaintext)
Application -- TLS --> Database (TLS terminates, storage uses separate at-rest encryption)
```

All three transport segments may be encrypted without the overall application providing *true end-to-end encryption*. A report must identify its endpoint definition, sources of verification and explicit decrypt/re-encrypt boundaries. For third-party SaaS or managed-service segments without internal visibility, show vendor attestations and evidence confidence rather than invent internal dataflow observation.

## GRCML Control Verification Procedures

- `CVP-CRYPTO-001`: endpoint certificate and trust-chain/expiry validation.
- `CVP-CRYPTO-002`: scoped data path encryption and termination classification (E2EE versus hop-to-hop).
- `CVP-CRYPTO-003`: FIPS 140-3 validated-module deployed-use review with official certificate and approved-mode proof.
- `CVP-CRYPTO-004`: key-management lifecycle and constrained access tests (metadata and test-key only).
- `CVP-CRYPTO-005`: CBOM completeness, schema validity, lineage/provenance, and drift.
- `CVP-CRYPTO-006`: crypto-agility risk inventory / weak algorithm deprecation.

Each CVP returns scope and method, result `verified | failed | inconclusive | not_tested | exception`, underlying observations, expected standards, current evidence, missing evidence and confidence/coverage. FIPS evidence verdicts remain a separate field; non-FIPS crypto security control results need not be the same.

## Local laboratory

Use Debian 13 with rootless Podman, two mock services, Nginx/Caddy TLS terminator, PostgreSQL, test-only certificates/CA, sample application code/crypto libraries, and optionally software HSM / PKCS#11 or configured FIPS module only if genuine certificate and environment evidence available. No claim of validated FIPS operation solely on a FIPS-named package.

| ID | Case | Oracle |
|---|---|---|
| C01 | Direct mTLS between defined endpoints | Connection/cert chain and authenticated peer observed |
| C02 | Reverse proxy terminates and re-encrypts | Reports hop-by-hop, not E2EE |
| C03 | Proxy terminates to cleartext backend | Flags partial encryption on scoped path |
| C04 | Expired, SAN-mismatched or untrusted certificate | Identifies specific affected endpoints/negative evidence |
| C05 | Certificate rotation and inventory diff | Updates CBOM and detects unexpected changed chain |
| C06 | Software package/library and algorithm discovery | Produces schema-valid CycloneDX 1.7 CBOM and documented coverage |
| C07 | Mock certificate with FIPS marketing claim but no CMVP ID | Does not claim validated FIPS use |
| C08 | Correct module certificate but wrong version/approved-mode evidence | Returns mismatch or use-unverified |
| C09 | Approved test key lifecycle and denied access | Access test result; never exports private key |
| C10 | Missing scanner permissions / opaque encrypted payload | Explicit coverage-gap/inconclusive assessment |

## AWS cloud sandbox

| ID | Case | Oracle |
|---|---|---|
| A01 | TLS client -> load balancer -> service -> RDS | Distinguishes every TLS termination and database connection |
| A02 | S3 SSE-KMS and KMS access rights | Records at-rest configuration, observed test-only allowed/denied decrypt attempts; never treats it as E2EE |
| A03 | Managed-service FIPS vendor assertion | Collect CMVP vendor/module references, matched or unverified in-scope operational use |
| A04 | ACM certificate lifecycle and drift | CBOM status/history reflects renewal/change and exposed endpoint |

## Azure cloud sandbox

| ID | Case | Oracle |
|---|---|---|
| Z01 | App Gateway -> App Service -> Azure SQL | Documents TLS and application decryption boundaries |
| Z02 | Key Vault and blob access | Distinct key-management and data-at-rest assurance; test identity cannot read protected object |
| Z03 | Azure-managed HSM FIPS evidence | Records exact service/module/vendor certificate and remaining deployment evidence gaps |
| Z04 | Certificate rotation and data-flow scope | Detects expected vs unexpected endpoint/key/cert change |

## Guardrails / acceptance criteria

- Only approved endpoints/sandboxes; synthetic records; no private-key extraction; scanner rate limits and passive-first operation; explicit cloud budgets/cleanup before provisioning.
- Collect read-only configuration by default; use synthetic keys/objects for access-control tests; label negative control tests as test-only.
- No unsupported whole-enterprise claims: make path scope, data type, direction, trust boundaries, coverage and timestamp visible.
- Evidence attribution: both positive and negative results link to original observations; sensitive contents and identifiers are minimized.
- Schema-valid CycloneDX CBOM and stable refs with tested round-trip import/export.
- FIPS determination must explicitly match **module validation**, **installed module/version**, **operational environment**, **approved mode**, **service/algorithm** and **validation status**.
- Expected behavior for incomplete telemetry or vendor opaqueness: inconclusive, never verified.
- All cloud labs are plans only until costs, approval, and teardown are agreed.

## Suggested implementation sequence

1. Inventory/certificate scanner adapters and CBOM 1.7 emission + validation.
2. Scoped CryptoPath graph over local reverse-proxy and database journeys.
3. FIPS module evidence model and CMVP certificate verification workflow.
4. Local negative tests, crypto rotation/diff and GRCML CVP bindings.
5. AWS, then Azure test environments, after explicit authorization and budgets.
6. Continuous scheduling, dashboards, risk scoring, PQ migration/planning.

**This document and the accompanying test catalog specify future implementation. No scanners or cloud resources have been created or executed by this PR.**
