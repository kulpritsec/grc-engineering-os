"""Per-rule outcomes: absence of a finding is never a pass by itself."""

import json
from pathlib import Path
from typing import Any

import pytest

from grcctl.evidence import verify_evidence_file
from grcctl.plugins.tf_assure import RULE_IDS, scan_terraform_plan

LABS = Path(__file__).resolve().parents[1] / "labs" / "terraform-cvp"


def lab(name: str) -> dict[str, Any]:
    return json.loads((LABS / f"{name}-plan.json").read_text(encoding="utf-8"))


def outcomes(tmp_path: Path, plan: dict[str, Any]) -> dict[str, str]:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    scan = scan_terraform_plan(path, tmp_path / "scan.json")
    assert [result.rule_id for result in scan.rule_results] == list(RULE_IDS)
    return {result.rule_id: result.outcome for result in scan.rule_results}


def resource(address: str, after: dict, unknown: dict | None = None) -> dict:
    return {
        "address": address,
        "type": address.split(".")[0],
        "change": {
            "actions": ["create"],
            "after": after,
            "after_unknown": unknown or {},
        },
    }


def test_known_good_plan_passes_supported_rules(tmp_path: Path) -> None:
    assert outcomes(tmp_path, lab("good")) == {
        "GRCOS-AWS-NET-001": "pass",
        "GRCOS-AWS-S3-001": "pass",
        "GRCOS-AWS-S3-002": "unknown",
        "GRCOS-AWS-S3-003": "pass",
    }


def test_known_failure_plan_fails_each_rule(tmp_path: Path) -> None:
    assert set(outcomes(tmp_path, lab("failing")).values()) == {"fail"}


def test_unknown_plan_never_passes(tmp_path: Path) -> None:
    assert set(outcomes(tmp_path, lab("unknown")).values()) == {"unknown"}


def test_empty_plan_is_unknown_not_pass(tmp_path: Path) -> None:
    plan = {"format_version": "1.2", "resource_changes": []}
    assert set(outcomes(tmp_path, plan).values()) == {"unknown"}


def test_s3_002_never_passes_even_with_encryption(tmp_path: Path) -> None:
    result = outcomes(tmp_path, lab("good"))["GRCOS-AWS-S3-002"]
    assert result == "unknown"


def test_known_failure_outranks_unknowns(tmp_path: Path) -> None:
    plan = lab("unknown")
    plan["resource_changes"].append(
        resource(
            "aws_security_group.open",
            {
                "ingress": [
                    {
                        "cidr_blocks": ["0.0.0.0/0"],
                        "from_port": 3389,
                        "to_port": 3389,
                        "protocol": "tcp",
                    }
                ]
            },
        )
    )
    assert outcomes(tmp_path, plan)["GRCOS-AWS-NET-001"] == "fail"


@pytest.mark.parametrize(
    "ingress",
    [
        [
            {
                "cidr_blocks": ["0.0.0.0/0"],
                "from_port": None,
                "to_port": 22,
                "protocol": "tcp",
            }
        ],
        [
            {
                "cidr_blocks": "0.0.0.0/0",
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
            }
        ],
        "not-a-list",
        ["not-an-object"],
    ],
)
def test_undeterminable_ingress_is_unknown(tmp_path: Path, ingress: object) -> None:
    plan = {
        "format_version": "1.2",
        "resource_changes": [resource("aws_security_group.sg", {"ingress": ingress})],
    }
    assert outcomes(tmp_path, plan)["GRCOS-AWS-NET-001"] == "unknown"


def test_nested_computed_cidr_is_unknown(tmp_path: Path) -> None:
    plan = lab("good")
    plan["resource_changes"][0]["change"]["after_unknown"] = {
        "ingress": [{"cidr_blocks": True}]
    }
    assert outcomes(tmp_path, plan)["GRCOS-AWS-NET-001"] == "unknown"


def test_public_non_admin_ingress_can_pass(tmp_path: Path) -> None:
    plan = {
        "format_version": "1.2",
        "resource_changes": [
            resource(
                "aws_security_group.web",
                {
                    "ingress": [
                        {
                            "cidr_blocks": ["0.0.0.0/0"],
                            "from_port": 443,
                            "to_port": 443,
                            "protocol": "tcp",
                        }
                    ]
                },
            )
        ],
    }
    assert outcomes(tmp_path, plan)["GRCOS-AWS-NET-001"] == "pass"


def test_standalone_ingress_rule_resource_is_unsupported(tmp_path: Path) -> None:
    plan = lab("good")
    plan["resource_changes"].append(
        resource("aws_vpc_security_group_ingress_rule.ssh", {"from_port": 22})
    )
    assert outcomes(tmp_path, plan)["GRCOS-AWS-NET-001"] == "unknown"


def test_bucket_without_matching_access_block_count_is_unknown(
    tmp_path: Path,
) -> None:
    plan = lab("good")
    plan["resource_changes"].append(
        resource("aws_s3_bucket.second", {"force_destroy": False})
    )
    assert outcomes(tmp_path, plan)["GRCOS-AWS-S3-001"] == "unknown"


def test_computed_force_destroy_is_unknown(tmp_path: Path) -> None:
    plan = lab("good")
    bucket = plan["resource_changes"][1]["change"]
    bucket["after"].pop("force_destroy")
    bucket["after_unknown"]["force_destroy"] = True
    assert outcomes(tmp_path, plan)["GRCOS-AWS-S3-003"] == "unknown"


def test_deleted_resources_are_ignored(tmp_path: Path) -> None:
    plan = lab("good")
    deleted = resource("aws_security_group.old", {})
    deleted["change"]["actions"] = ["delete"]
    plan["resource_changes"].append(deleted)
    assert outcomes(tmp_path, plan)["GRCOS-AWS-NET-001"] == "pass"


def test_rule_results_preserve_findings_and_verify(tmp_path: Path) -> None:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(lab("failing")), encoding="utf-8")
    output = tmp_path / "scan.json"
    scan = scan_terraform_plan(path, output)
    assert scan.schema_version == "0.2.0"
    assert scan.summary.findings_total == 4
    failed = {r.rule_id: r for r in scan.rule_results if r.outcome == "fail"}
    assert failed["GRCOS-AWS-S3-003"].resources_evaluated == ["aws_s3_bucket.evidence"]
    assert verify_evidence_file(output).valid
