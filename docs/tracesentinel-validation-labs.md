# Kulprit TraceSentinel — active tracer and assurance validation labs

**Status:** design/test specification only; not yet implemented or executed.  
**Owner:** Kulprit GRC Engineering OS / Kulprit Trace.  
**Architecture:** separate Debian-based assurance appliance, rootless/isolated collectors, no assumption of installed Kali tools.  
**Test manifest:** `tests/specifications/tracesentinel-cases.json`.

## Product hypothesis

A synthetic, registered tracer introduced into an **authorized ingestion point** can be followed across instrumented storage, processing, transport, backup, archive, identity, and AI-agent boundaries. Every observed hop must have a source, timestamp, environment, actor/workload when observable, collection method, confidence/coverage statement, and provenance reference. A tracer does not independently emit telemetry: instrumentation and approved event triggers are required.

**Three graph relations must not be conflated:**
- **Declared:** expected or authorized movement from policy/architecture.
- **Observed:** data/tracer-specific occurrence supported by sensor evidence.
- **Verified:** a control assertion independently tested with sufficient evidence for that assertion and scope.

Absence of an event never proves non-occurrence when sensor coverage, data access logs, or correlation are incomplete.

## Components and contracts

1. **TraceSeed**: mints synthetic markers and classification/retention policies; registers generation time, injection point, ID, expected destinations, expected prohibited destinations, seed fingerprint (not actual customer PII).
2. **TraceAgent**: platform adapters collect allowed metadata; maintain event IDs, process/service identity, system, operation, UTC timestamp + uncertainty, trace ID if present, redacted data/object references.
3. **TraceSentinel**: correlates events, safely escalates scoped telemetry on matching observations; maintains event ancestry, rate limits, retry/deduplication, authorization scope.
4. **TraceMap**: directed, time-aware graph, explicitly recording observed, inferred, expected, and unknown edges and transformations.
5. **TracePolicy**: tests classification, approved routes, identity entitlement, encryption, retention, backup recoverability; maps to GRCML/Control Verification Procedures.
6. **TraceProof**: emits auditable evidence bundles, hashes/canonicalization details and source links; sign/attest in later maturity stages (a SHA-256 hash alone is not authenticity).

Minimum normalized event: `trace_id`, `event_id`, `timestamp_utc`, `source_system`, `source_kind`, `operation`, `actor_type`, `actor_id` (where available), `object_ref`, `parent_event_ids`, `observed_vs_inferred`, `sensor_health`, `evidence_ref`, `classification`, `policy_context`. Never include secrets or real PII in test fixture outputs.

Assessment states: `verified`, `failed`, `inconclusive`, `not_tested`, and `exception`. A partial graph must be described as partial. Verification attaches to a particular assertion; it is not a compliance certification.

## Local laboratory (L01–L10)

Use an isolated Debian VM/rootless Podman test network. FastAPI intake, PostgreSQL, queue (Redis or equivalent), ETL service, MinIO object store, backup/restore worker, controllable AI-agent stub, collector/event bus, TraceMap API, and local evidence store. Start with deterministic synthetic data. Use dedicated test roles with no access to non-test resources.

| ID | Scenario | Primary hurdle / test oracle |
|---|---|---|
| L01 | Seed creation and intake | Unique registered ID and timestamp correlate to database persistence |
| L02 | Approved data read | Attributed identity, row/object operation, and supported event chain |
| L03 | Denied access attempt | A denied synthetic-user action creates a test result; data not returned |
| L04 | Modify/upsert/delete | Old/new fingerprints, event ancestry, applicable retention handling |
| L05 | ETL strips tracer marker | Explicit parent-child provenance from ETL; no invented link if missing |
| L06 | Backup and isolated restore | Snapshot/job correlation and tracer recovered from actual restored copy |
| L07 | Archive/lifecycle transitions | Archival evidence vs actual retrieval; retention and deletion distinctions |
| L08 | Unexpected export to local test sink | Known prohibited route flagged with network + application context |
| L09 | AI-agent retrieval and tool call | Agent/workload identity, source retrieval, tool event, destination |
| L10 | Sensor failure or missing data | Inconclusive/coverage gap rather than false pass; recovery replay |

Every case specifies a baseline run, one deliberate fault or prohibited action, expected observations, negative observations, and a signed-off evidence checklist before its test can be considered complete.

## AWS validation laboratory (A01–A05)

Use a **dedicated, budget-limited sandbox account**, region, unique tags, private test networking, explicitly enabled data events where required, and Terraform/OpenTofu destroy plan. Candidate pipeline: API Gateway/Lambda -> SQS -> S3 object(s) -> Lambda transform -> optional RDS test database; CloudTrail S3 data events, CloudWatch logs, IAM logs and a separate validation collector. Scope only test-owned systems.

| ID | Scenario | Reality to validate |
|---|---|---|
| A01 | Lambda/SQS/S3 propagation | Correlate injection, transformation, object writes and asynchronous retries |
| A02 | Allowed vs denied S3 object access | IAM decision vs actual test identity outcome; S3 data events must be enabled |
| A03 | AWS Backup snapshot and restore | Backup success is not record recoverability; validate content after restore |
| A04 | KMS encrypted object | Metadata/lineage without plaintext inspection; key permissions logged |
| A05 | Telemetry lag/disabled source | Identify missing S3 data events or late delivery as unknown/partial |

Avoid data-access assumptions from CloudTrail management events. Do not enable public object access or simulate exfiltration to real external destinations; use a dedicated internal test bucket/sink.

## Azure validation laboratory (Z01–Z05)

Use a **dedicated sandbox subscription/resource group**, budgets/alerts where supported, least-privilege workload identities, short TTL and IaC teardown. Candidate pipeline: Azure Functions -> Service Bus -> Blob Storage -> Functions/optional Azure SQL; diagnostic settings exported to Log Analytics / event hub / controlled store. Keep test data synthetic.

| ID | Scenario | Reality to validate |
|---|---|---|
| Z01 | Functions/Service Bus/Blob propagation | Correlate async retries, message ID, storage operations |
| Z02 | Allowed vs denied blob access | RBAC, SAS scope/expiry; compare evaluated policy with observed outcome |
| Z03 | Azure Backup/recovery or storage snapshot restore | Validate actual recovered tracer, not merely job success |
| Z04 | Cross-region copy and residency policy | Declare zones, observe replica/copy events, block unauthorized transfer in test |
| Z05 | Diagnostic settings missing or delayed | Report incomplete coverage, timestamps, uncertainty, and false-negative risk |

## Critical cross-environment failure modes

- A marker stripped by ETL, hashing, compression, aggregation, deduplication, or encryption; use **instrumented transformation lineage** rather than guessing from content matches.
- Bulk/physical backup reading pages or snapshots without per-record access events; **restore then search for tracer**.
- A "read" visible at host/process level but **not attributable to a specific database row** without DB/app instrumentation.
- Cloud audit sources not enabled by default, eventually consistent delivery, missing permissions, or clock skew.
- Agent memory, retrieval caches, vector embeddings, RAG context and tool calls where semantic influence **does not mean literal marker propagation**.
- Multiple simultaneous seeds, retry/replay, fork/join, and time-order skew; preserve ancestry and deduplicate observations.
- Privacy: avoid production PII, plaintext capture, aggressive instrumentation, uncontrolled callbacks, and monitoring beyond approved scope.

## Test protocol and acceptance gates

**Gate 0 — Safety & scope:** Written scope, isolated resources, synthetic-only seeds, explicit cloud-cost budgets, short-lived credentials, egress restrictions, teardown verification, no unapproved adversarial activity.

**Gate 1 — Local deterministic trace:** L01–L04 generate provenance-linked evidence; deny test does not leak; event replay and deduplication verified.

**Gate 2 — Local difficult cases:** L05–L10; transformation evidence and backup restore demonstrated; unknown/coverage states emitted on sensor failures.

**Gate 3 — Cloud realistic tracing:** AWS then Azure; at least one actual allowed flow, one denied access, one async processing transformation, one restore, and one missing-telemetry experiment per provider (corresponding to the catalog).

**Gate 4 — GRC product connection:** Each run produces a GRCML-linked Control Verification Procedure outcome, annotated flow diagram, timestamped evidence bundle, data classification handling record, drift comparison and actionable finding.

Proposed (not yet measured) quality metrics:
- 100% of test assertions state **exact scope, source coverage, and limitation**.
- 100% of observed/inferred edges distinguished and evidence-linked; no unsupported claim of full trace.
- No generated report claims `verified` when essential telemetry or the test oracle is missing.
- Tracer content is synthetic; secrets and unnecessary payloads never enter the evidence store.
- Environment teardown and budget report required after each cloud test.

## Development sequence and decision points

1. **Specification & test harness:** trace event JSON schema, seed registry, simple fixture generator, local test oracle, machine-readable test catalog (this plan).
2. **Local vertical slice:** FastAPI -> PostgreSQL -> ETL -> MinIO; Graph API + audit evidence.
3. **Hard cases:** access deny, backup+restore, transformed data, sensor outage, AI-agent tool traces.
4. **AWS test adapters:** instrument and validate managed events, IAM outcomes and restore.
5. **Azure test adapters:** validate RBAC, async message lineage, diagnostic pipelines and restore.
6. **Continuous runs:** scheduler, drift detection, GRCML control bindings, assurance scoring, evidence attestation.

**Not yet included:** deployed environments, live credentials, cloud expenditure, production monitoring agents, certified compliance claims, or operational dashboards. Cloud infrastructure templates should be reviewed, budgeted and explicitly approved before provisioning.
