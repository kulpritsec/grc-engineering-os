# Terraform plan results as CVP observations

**Status:** development slice of the G3 vertical slice (tracks [issue 28](https://github.com/kulpritsec/grc-engineering-os/issues/28), part of [issue 14](https://github.com/kulpritsec/grc-engineering-os/issues/14)). The API endpoint and operator UI from issue 14 are later slices. A Terraform plan describes intended configuration; nothing here observes deployed resources.

## Decision record

Approved by the project product owner on 2026-10-28 before implementation:

1. GRCOS-AWS-S3-002 is fail-or-unknown, never pass. Its configuration-presence heuristic is not bucket-specific.
2. The bridge ingests the plan and scan evidence into the Evidence Vault so the resulting report can be published.
3. The CVP procedure is operator-supplied JSON. The tool never generates control assertions or scope.

## Per-rule results

Scan evidence schema `0.2.0` adds `rule_results`: one entry per implemented rule with `outcome`, `resources_evaluated` and `notes`. Findings, `--fail-on-findings` and `grcctl evidence verify` are unchanged; `0.1.0` scan evidence still verifies.

A finding is always `fail`, even when other values are unknown. Without a finding, a rule is `pass` only when it evaluated at least one applicable resource and every value it depends on is explicitly known. Everything else is `unknown`, so **absence of a finding is never a pass by itself**.

| Rule | Pass requires | `unknown` when |
| --- | --- | --- |
| NET-001 administrative ingress | Every `aws_security_group` has a known ingress list; public entries have known protocol and TCP ports | No security groups; ingress or nested values are computed (`after_unknown`); malformed ingress; any `aws_security_group_rule` or `aws_vpc_security_group_ingress_rule` exists (not inspected) |
| S3-001 public access block | All four flags explicitly `true` on every declared block | No blocks; a flag is missing or computed; fewer blocks than buckets |
| S3-002 encryption | Never passes | Always, unless a finding makes it `fail` |
| S3-003 force_destroy | `force_destroy` explicitly `false` on every bucket | No buckets; value missing or computed |

Bucket-to-block references are not resolved, so an S3-001 pass covers the declared blocks, not proof that each bucket has one. Provider defaults are not modelled.

## Bridge

```powershell
uv run grcctl assurance terraform PLAN.json --procedure CVP.json `
    --output-dir evidence/terraform-cvp --vault-root evidence/vault `
    [--assessment-id ID] [--scope-confirmed] [--coverage-complete]
```

1. Validates the procedure and reads the plan (64 MiB limit).
2. Runs the existing scanner, writing `terraform-scan.json`.
3. Ingests the plan (`terraform-plan`) and scan evidence (`terraform-scan`) into the Vault. The plan digest must match across the initial read, the scan and the Vault copy, or the run is refused.
4. Writes `cvp-input.json` with one observation per **required** rule ID. Rules the procedure does not require are not observations, so they cannot decide its verdict, but their findings stay in the retained scan evidence. Unsupported required IDs are reported as missing checks.
5. Evaluates it with the existing CVP engine into `cvp-report.json`, including the [freshness gate](EVIDENCE_FRESHNESS.md).

Plan evidence uses Terraform's top-level `timestamp` as `collected_at`. A missing, unparseable or offset-free timestamp leaves plan freshness unknown, so the verdict is `inconclusive`. Scan evidence uses the scan time. Scope and coverage stay unconfirmed, and the verdict `inconclusive`, unless the operator passes the flags. Exit code 0 means the evaluation completed, not that the control passed; refused inputs exit 2.

If evaluation fails after ingestion, the plan and scan remain preserved Vault records with no report, the same "preservation without publication" boundary as report ingestion.

## Lab demonstration

`labs/terraform-cvp` holds synthetic known-good, known-failure and unknown/unsupported plans and an example procedure. The example uses a one-year freshness window only so the fixed lab timestamps stay usable; real procedures should use a window that matches how often plans are regenerated.

```powershell
uv sync --locked
foreach ($case in "good", "failing", "unknown") {
  uv run grcctl assurance terraform labs/terraform-cvp/$case-plan.json `
      --procedure labs/terraform-cvp/procedure.json `
      --output-dir evidence/terraform-cvp/$case `
      --vault-root evidence/terraform-cvp/vault `
      --scope-confirmed --coverage-complete
}
uv run grcctl evidence verify evidence/terraform-cvp/good/cvp-report.json
uv run grcctl assurance publish evidence/terraform-cvp/good/cvp-report.json `
    --vault-root evidence/terraform-cvp/vault
```

Expected verdicts: `VERIFIED`, `FAILED` and `INCONCLUSIVE`. The lab timestamps are 2026-10-28, so after 2027-10-28 the good case becomes `inconclusive` as stale evidence, which is the intended behavior.

## Limitations

- Plans can be generated against any state, workspace or variable set; `--scope-confirmed` is an operator claim, not authorization.
- The plan `timestamp` and scan time are unauthenticated; see the freshness limitations.
- Rule coverage is four AWS rules. A `verified` CVP means the required rules passed on known planned values, not that the configuration is secure or compliant.
- Control mappings remain candidate crosswalks.

## Validation

```powershell
uv run pytest -q tests/test_tf_rule_results.py tests/test_terraform_cvp.py
uv run ruff format --check .
uv run ruff check .
uv run --no-sync --with-requirements requirements/platform-dev.txt mypy src
uv run --no-sync --with-requirements requirements/platform-dev.txt pytest --cov=grcctl --cov-report=term-missing --cov-fail-under=70
```
