"""Route Terraform plan scan results through an operator-defined CVP.

The scanner observes a planned configuration, not deployed infrastructure.
Only rules the procedure requires become observations, and a rule passes only
on positive, fully known plan evidence (see ``RuleResult``).
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from ..models import TerraformScanEvidence
from ..plugins.tf_assure import TerraformPlanError, scan_terraform_plan
from ..vault import LocalEvidenceVault, VaultError
from .engine import AssessmentInputError, evaluate_file
from .models import (
    ArtifactReference,
    AssessmentInput,
    AssessmentReport,
    ControlVerificationProcedure,
    Observation,
)

MAX_PLAN_BYTES = 64 * 1024 * 1024
PLAN_EVIDENCE_ID = "EV-TF-PLAN"
SCAN_EVIDENCE_ID = "EV-TF-SCAN"


class TerraformBridgeError(ValueError):
    """The plan, procedure or evidence chain cannot support an assessment."""


@dataclass(frozen=True)
class TerraformAssessment:
    report: AssessmentReport
    scan: TerraformScanEvidence
    scan_path: Path
    input_path: Path
    report_path: Path


def _plan_timestamp(plan_bytes: bytes) -> datetime | None:
    """Terraform's own plan time; unparseable or naive values are unknown."""
    try:
        value = json.loads(plan_bytes).get("timestamp")
        parsed = datetime.fromisoformat(value) if isinstance(value, str) else None
    except (ValueError, AttributeError):
        return None
    return parsed if parsed is not None and parsed.tzinfo is not None else None


def _load_procedure(path: Path) -> ControlVerificationProcedure:
    try:
        return ControlVerificationProcedure.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise TerraformBridgeError(f"Invalid CVP procedure: {exc}") from exc


def _read_plan(path: Path) -> bytes:
    try:
        if path.stat().st_size > MAX_PLAN_BYTES:
            raise TerraformBridgeError(
                f"Terraform plan exceeds {MAX_PLAN_BYTES} bytes."
            )
        return path.read_bytes()
    except OSError as exc:
        raise TerraformBridgeError(f"Cannot read Terraform plan: {exc}") from exc


def assess_terraform_plan(
    plan_path: Path,
    procedure_path: Path,
    output_dir: Path,
    vault_root: Path,
    *,
    assessment_id: str | None = None,
    scope_confirmed: bool = False,
    coverage_complete: bool = False,
) -> TerraformAssessment:
    """Scan, retain plan and scan evidence in the Vault, then evaluate the CVP.

    The plan and scan evidence are ingested before evaluation. If a later step
    fails they remain preserved Vault records without any assessment report.
    """
    procedure = _load_procedure(procedure_path)
    plan_bytes = _read_plan(plan_path)
    plan_sha256 = hashlib.sha256(plan_bytes).hexdigest()

    output_dir.mkdir(parents=True, exist_ok=True)
    scan_path = output_dir / "terraform-scan.json"
    try:
        scan = scan_terraform_plan(plan_path, scan_path)
    except (OSError, TerraformPlanError) as exc:
        raise TerraformBridgeError(f"Terraform plan rejected: {exc}") from exc
    if scan.input_sha256 != plan_sha256:
        raise TerraformBridgeError("Terraform plan changed while it was scanned.")

    try:
        vault = LocalEvidenceVault(vault_root)
        stored_plan = vault.ingest(plan_path, kind="terraform-plan")
        if stored_plan.sha256 != plan_sha256:
            raise TerraformBridgeError("Terraform plan changed before Vault ingestion.")
        stored_scan = vault.ingest(scan_path, kind="terraform-scan")
    except (OSError, VaultError) as exc:
        raise TerraformBridgeError(f"Evidence could not be preserved: {exc}") from exc

    evidence_ids = [PLAN_EVIDENCE_ID, SCAN_EVIDENCE_ID]
    results = {result.rule_id: result for result in scan.rule_results}
    observations = [
        Observation(
            check_id=check_id,
            outcome=results[check_id].outcome,
            evidence_ids=evidence_ids,
            detail=" ".join(results[check_id].notes),
        )
        for check_id in procedure.required_check_ids
        if check_id in results
    ]
    assessment = AssessmentInput(
        assessment_id=assessment_id or f"terraform-{uuid4()}",
        procedure=procedure,
        observations=observations,
        evidence=[
            ArtifactReference(
                id=PLAN_EVIDENCE_ID,
                kind=stored_plan.kind,
                sha256=stored_plan.sha256,
                vault_artifact_id=stored_plan.artifact_id,
                collected_at=_plan_timestamp(plan_bytes),
            ),
            ArtifactReference(
                id=SCAN_EVIDENCE_ID,
                kind=stored_scan.kind,
                sha256=stored_scan.sha256,
                vault_artifact_id=stored_scan.artifact_id,
                collected_at=scan.collected_at,
            ),
        ],
        scope_confirmed=scope_confirmed,
        coverage_complete=coverage_complete,
    )

    input_path = output_dir / "cvp-input.json"
    report_path = output_dir / "cvp-report.json"
    try:
        input_path.write_text(assessment.model_dump_json(indent=2) + "\n", "utf-8")
        report = evaluate_file(input_path, report_path, vault_root=vault_root)
    except (OSError, AssessmentInputError) as exc:
        raise TerraformBridgeError(f"CVP evaluation failed: {exc}") from exc
    return TerraformAssessment(report, scan, scan_path, input_path, report_path)
