# Terraform Assurance Rules

This document defines the Terraform and OpenTofu assurance rules currently implemented by GRC Engineering OS.

The scanner assesses the JSON representation of a saved Terraform or OpenTofu plan. It produces structured findings and cryptographically hashed evidence; it does not apply infrastructure or modify the assessed plan.

## Running an assessment

Generate a saved plan and convert it to JSON:

```bash
tofu init
tofu validate
tofu plan -out=tfplan
tofu show -json -plan=tfplan > plan.json
```

Run the assessment:

```bash
uv run grcctl scan terraform plan.json
```

Use `--fail-on-findings` in CI or other enforcement workflows when findings should result in a non-zero exit status:

```bash
uv run grcctl scan terraform plan.json --fail-on-findings
```

The default evidence output is `evidence/terraform-assessment.json`.

## Implemented rules

### GRCOS-AWS-NET-001 — Administrative service exposed to the internet

- Severity: High
- Resource: `aws_security_group`
- Condition: An ingress rule exposes an administrative service, currently SSH on TCP/22 or RDP on TCP/3389, to `0.0.0.0/0` or `::/0`.
- Risk: Internet-wide administrative access increases the likelihood of credential attacks, exploitation, and unauthorized access.
- Recommended remediation: Restrict ingress to approved management networks, a VPN, a bastion host, or a zero-trust access path.
- Example mappings: CIS Controls v8 4.4 and 13.3; NIST SP 800-53 AC-3, AC-4, and SC-7.

### GRCOS-AWS-S3-001 — S3 public-access protections disabled

- Severity: High
- Resource: `aws_s3_bucket_public_access_block`
- Condition: One or more public-access protection settings are explicitly disabled: `block_public_acls`, `block_public_policy`, `ignore_public_acls`, or `restrict_public_buckets`.
- Risk: Disabled safeguards can permit public bucket or object exposure when combined with permissive policies or ACLs.
- Recommended remediation: Enable all four protections unless a reviewed and documented public-access requirement exists.
- Example mappings: CIS Controls v8 3.3 and 3.12; NIST SP 800-53 AC-3, AC-6, and SC-7.

### GRCOS-AWS-S3-002 — No explicit managed encryption configuration

- Severity: Medium
- Resource: `aws_s3_bucket`
- Condition: The plan contains an S3 bucket without a corresponding explicit managed server-side encryption configuration.
- Risk: The infrastructure definition does not demonstrate the intended encryption configuration or key-management policy.
- Recommended remediation: Declare a managed S3 server-side encryption configuration and, where required, an approved KMS key.
- Example mappings: CIS Controls v8 3.11; NIST SP 800-53 SC-12 and SC-13.

This is an evidence-strength heuristic. It reports the absence of an explicit managed configuration in the assessed plan; it does not prove that stored objects will be unencrypted because provider and service defaults may still apply.

### GRCOS-AWS-S3-003 — Destructive bucket deletion enabled

- Severity: Medium
- Resource: `aws_s3_bucket`
- Condition: `force_destroy` is explicitly set to `true`.
- Risk: A bucket and its objects may be deleted without first removing or separately preserving stored evidence.
- Recommended remediation: Set `force_destroy` to `false` for evidence repositories and add retention, versioning, backup, and deletion-approval controls appropriate to the system.
- Example mappings: CIS Controls v8 3.4 and 11.2; NIST SP 800-53 CP-9, SI-12, and AU-9.

## Evidence and integrity

Each assessment records:

- schema and assessment type;
- collection timestamp and scanner provenance;
- source-plan metadata;
- resources assessed;
- findings, severities, and control mappings;
- an evidence hash calculated over the canonical evidence content.

Verify an assessment artifact with:

```bash
uv run grcctl evidence verify evidence/terraform-assessment.json
```

A successful verification demonstrates that the artifact is structurally valid and that its calculated hash matches its stored hash. It does not establish who created the evidence, prove the truth of the source plan, or replace digital signing, trusted timestamps, or independent attestation.

## Assessment boundaries

The current scanner:

- reads saved-plan JSON and never applies a plan;
- evaluates only implemented resource types and rule conditions;
- may encounter values that remain unknown until apply;
- does not inspect live cloud state, organization-level controls, runtime configuration, or manually configured safeguards;
- provides engineering evidence and control context, not certification or a complete compliance determination.

Control mappings are informative crosswalks. Applicability and operating effectiveness must be validated within the assessed organization's scope, architecture, risk model, and control environment.

## Planned extensions

Future releases are expected to add external policy packs, additional cloud providers and resource types, configurable severity gates, exception handling, SARIF output, OSCAL-aligned evidence, signed attestations, and live-state comparison.
