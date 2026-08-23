import json

import pytest
from typer.testing import CliRunner

from grcctl.cli import app
from grcctl.evidence import verify_evidence_file
from grcctl.plugins.tf_assure import (
    TerraformPlanError,
    scan_terraform_plan,
)

runner = CliRunner()


def insecure_plan() -> dict[str, object]:
    return {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "aws_vpc.lab",
                "type": "aws_vpc",
                "change": {
                    "actions": ["create"],
                    "after": {"cidr_block": "10.20.0.0/16"},
                },
            },
            {
                "address": "aws_security_group.admin_open",
                "type": "aws_security_group",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "ingress": [
                            {
                                "cidr_blocks": ["0.0.0.0/0"],
                                "ipv6_cidr_blocks": [],
                                "from_port": 22,
                                "to_port": 22,
                                "protocol": "tcp",
                            }
                        ]
                    },
                },
            },
            {
                "address": "aws_s3_bucket.evidence",
                "type": "aws_s3_bucket",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "bucket": "grcos-test-evidence",
                        "force_destroy": True,
                    },
                },
            },
            {
                "address": "aws_s3_bucket_public_access_block.evidence",
                "type": "aws_s3_bucket_public_access_block",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "block_public_acls": False,
                        "block_public_policy": False,
                        "ignore_public_acls": False,
                        "restrict_public_buckets": False,
                    },
                },
            },
            {
                "address": "aws_s3_bucket_policy.public_read",
                "type": "aws_s3_bucket_policy",
                "change": {
                    "actions": ["create"],
                    "after": {"region": "us-east-1"},
                },
            },
        ],
    }


def write_plan(tmp_path, plan: dict[str, object]):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def test_insecure_plan_produces_expected_findings(tmp_path) -> None:
    plan_path = write_plan(tmp_path, insecure_plan())
    output = tmp_path / "assessment.json"

    assessment = scan_terraform_plan(plan_path, output)

    rule_ids = {finding.rule_id for finding in assessment.findings}

    assert assessment.summary.resources_scanned == 5
    assert assessment.summary.findings_total == 4
    assert rule_ids == {
        "GRCOS-AWS-NET-001",
        "GRCOS-AWS-S3-001",
        "GRCOS-AWS-S3-002",
        "GRCOS-AWS-S3-003",
    }
    assert output.exists()
    assert output.stat().st_mode & 0o777 == 0o600


def test_terraform_evidence_verifies(tmp_path) -> None:
    plan_path = write_plan(tmp_path, insecure_plan())
    output = tmp_path / "assessment.json"

    scan_terraform_plan(plan_path, output)
    verification = verify_evidence_file(output)

    assert verification.schema_valid is True
    assert verification.integrity_valid is True
    assert verification.valid is True


def test_scan_cli_reports_findings(tmp_path) -> None:
    plan_path = write_plan(tmp_path, insecure_plan())
    output = tmp_path / "assessment.json"

    result = runner.invoke(
        app,
        [
            "scan",
            "terraform",
            str(plan_path),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert "FINDINGS DETECTED" in result.output
    assert "GRCOS-AWS-NET-001" in result.output


def test_fail_on_findings_returns_nonzero(tmp_path) -> None:
    plan_path = write_plan(tmp_path, insecure_plan())

    result = runner.invoke(
        app,
        [
            "scan",
            "terraform",
            str(plan_path),
            "--output",
            str(tmp_path / "assessment.json"),
            "--fail-on-findings",
        ],
    )

    assert result.exit_code == 1


def test_basic_plan_has_no_findings(tmp_path) -> None:
    plan = {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "aws_vpc.lab",
                "type": "aws_vpc",
                "change": {
                    "actions": ["create"],
                    "after": {"cidr_block": "10.20.0.0/16"},
                },
            }
        ],
    }

    assessment = scan_terraform_plan(
        write_plan(tmp_path, plan),
        tmp_path / "assessment.json",
    )

    assert assessment.summary.findings_total == 0


def test_unsupported_plan_version_is_rejected(tmp_path) -> None:
    plan_path = write_plan(
        tmp_path,
        {
            "format_version": "2.0",
            "resource_changes": [],
        },
    )

    with pytest.raises(TerraformPlanError):
        scan_terraform_plan(
            plan_path,
            tmp_path / "assessment.json",
        )
