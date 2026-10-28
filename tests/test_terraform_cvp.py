"""Terraform scan to CVP bridge: known-good, known-failure and unknown cases."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import grcctl.assurance.terraform as bridge
from grcctl.assurance.catalog import LocalAssuranceCatalog
from grcctl.assurance.terraform import TerraformBridgeError, assess_terraform_plan
from grcctl.cli import app
from grcctl.evidence import verify_evidence_file
from grcctl.vault import LocalEvidenceVault

LABS = Path(__file__).resolve().parents[1] / "labs" / "terraform-cvp"
runner = CliRunner()


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def lab_plan(tmp_path: Path, name: str, *, timestamp: str | None = "now") -> Path:
    plan = json.loads((LABS / f"{name}-plan.json").read_text(encoding="utf-8"))
    if timestamp is None:
        plan.pop("timestamp")
    else:
        plan["timestamp"] = _now() if timestamp == "now" else timestamp
    path = tmp_path / f"{name}-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def procedure(tmp_path: Path, **changes: Any) -> Path:
    data = json.loads((LABS / "procedure.json").read_text(encoding="utf-8"))
    data.update(changes)
    path = tmp_path / "procedure.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def run(tmp_path: Path, plan: Path, proc: Path | None = None, **flags: Any):
    options = {"scope_confirmed": True, "coverage_complete": True, **flags}
    return assess_terraform_plan(
        plan,
        proc or procedure(tmp_path),
        tmp_path / "out",
        tmp_path / "vault",
        assessment_id="TF-TEST-001",
        **options,
    )


def test_known_good_plan_is_verified_and_publishable(tmp_path: Path) -> None:
    result = run(tmp_path, lab_plan(tmp_path, "good"))
    report = result.report
    assert report.verdict == "verified"
    assert {o.check_id: o.outcome for o in report.observations} == {
        "GRCOS-AWS-NET-001": "pass",
        "GRCOS-AWS-S3-001": "pass",
        "GRCOS-AWS-S3-003": "pass",
    }
    assert set(report.artifact_checks.values()) == {"matched"}
    assert set(report.freshness_checks.values()) == {"fresh"}
    assert {item.kind for item in report.evidence} == {
        "terraform-plan",
        "terraform-scan",
    }
    assert verify_evidence_file(result.report_path).valid
    assert verify_evidence_file(result.scan_path).valid
    publication = LocalAssuranceCatalog(tmp_path / "vault").publish(result.report_path)
    assert publication.verdict == "verified"


def test_known_failure_plan_is_failed(tmp_path: Path) -> None:
    report = run(tmp_path, lab_plan(tmp_path, "failing")).report
    assert report.verdict == "failed"
    assert {o.outcome for o in report.observations} == {"fail"}


def test_unknown_plan_is_inconclusive(tmp_path: Path) -> None:
    report = run(tmp_path, lab_plan(tmp_path, "unknown")).report
    assert report.verdict == "inconclusive"
    assert {o.outcome for o in report.observations} == {"unknown"}
    assert all(o.detail for o in report.observations)


def test_non_required_failing_rule_does_not_decide_verdict(tmp_path: Path) -> None:
    proc = procedure(tmp_path, required_check_ids=["GRCOS-AWS-S3-003"])
    plan = json.loads(lab_plan(tmp_path, "good").read_text(encoding="utf-8"))
    plan["resource_changes"][0]["change"]["after"]["ingress"][0]["cidr_blocks"] = [
        "0.0.0.0/0"
    ]
    path = tmp_path / "mixed-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    result = run(tmp_path, path, proc)
    assert [o.check_id for o in result.report.observations] == ["GRCOS-AWS-S3-003"]
    assert result.report.verdict == "verified"
    # The finding is still preserved in the retained scan evidence.
    assert any(f.rule_id == "GRCOS-AWS-NET-001" for f in result.scan.findings)


def test_s3_002_requirement_cannot_verify(tmp_path: Path) -> None:
    proc = procedure(tmp_path, required_check_ids=["GRCOS-AWS-S3-002"])
    report = run(tmp_path, lab_plan(tmp_path, "good"), proc).report
    assert report.verdict == "inconclusive"


def test_unsupported_required_check_is_missing(tmp_path: Path) -> None:
    proc = procedure(tmp_path, required_check_ids=["GRCOS-AWS-IAM-999"])
    report = run(tmp_path, lab_plan(tmp_path, "good"), proc).report
    assert report.verdict == "not_tested"
    assert "Required check GRCOS-AWS-IAM-999 is missing." in report.reasons


def test_scope_and_coverage_default_to_unconfirmed(tmp_path: Path) -> None:
    result = assess_terraform_plan(
        lab_plan(tmp_path, "good"),
        procedure(tmp_path),
        tmp_path / "out",
        tmp_path / "vault",
    )
    assert result.report.scope_confirmed is False
    assert result.report.coverage_complete is False
    assert result.report.verdict == "inconclusive"
    assert result.report.assessment_id.startswith("terraform-")


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (None, "unknown_collection_time"),
        ("not-a-time", "unknown_collection_time"),
        ("2026-10-28T12:00:00", "unknown_collection_time"),
        ("2000-01-01T00:00:00Z", "stale"),
        ("2999-01-01T00:00:00Z", "future_timestamp"),
    ],
)
def test_plan_timestamp_governs_plan_freshness(
    tmp_path: Path, timestamp: str | None, expected: str
) -> None:
    report = run(tmp_path, lab_plan(tmp_path, "good", timestamp=timestamp)).report
    plan_ids = [e.id for e in report.evidence if e.kind == "terraform-plan"]
    assert report.freshness_checks[plan_ids[0]] == expected
    assert report.verdict == "inconclusive"


def test_short_policy_makes_old_plan_stale(tmp_path: Path) -> None:
    old = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    proc = procedure(tmp_path, max_evidence_age_seconds=86_400)
    report = run(tmp_path, lab_plan(tmp_path, "good", timestamp=old), proc).report
    assert "stale" in report.freshness_checks.values()
    assert report.verdict == "inconclusive"


def test_plan_changed_after_scan_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = lab_plan(tmp_path, "good")
    real_scan = bridge.scan_terraform_plan

    def scan_then_tamper(path: Path, output: Path):
        result = real_scan(path, output)
        path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
        return result

    monkeypatch.setattr(bridge, "scan_terraform_plan", scan_then_tamper)
    with pytest.raises(TerraformBridgeError, match="changed"):
        run(tmp_path, plan)
    assert not (tmp_path / "out" / "cvp-report.json").exists()


def test_invalid_inputs_are_refused(tmp_path: Path) -> None:
    plan = lab_plan(tmp_path, "good")
    bad_proc = tmp_path / "bad.json"
    bad_proc.write_text("{}", encoding="utf-8")
    with pytest.raises(TerraformBridgeError, match="procedure"):
        run(tmp_path, plan, bad_proc)
    bad_plan = tmp_path / "bad-plan.json"
    bad_plan.write_text('{"format_version": "2.0", "resource_changes": []}')
    with pytest.raises(TerraformBridgeError, match="format version"):
        run(tmp_path, bad_plan)
    with pytest.raises(TerraformBridgeError, match="plan"):
        run(tmp_path, tmp_path / "missing.json")


def test_oversized_plan_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bridge, "MAX_PLAN_BYTES", 64)
    with pytest.raises(TerraformBridgeError, match="exceeds"):
        run(tmp_path, lab_plan(tmp_path, "good"))
    assert not (tmp_path / "vault").exists()


def test_vault_records_plan_and_scan(tmp_path: Path) -> None:
    result = run(tmp_path, lab_plan(tmp_path, "good"))
    kinds = sorted(
        a.kind for a in LocalEvidenceVault(tmp_path / "vault").list_artifacts()
    )
    assert kinds == ["terraform-plan", "terraform-scan"]
    saved = json.loads(result.input_path.read_text(encoding="utf-8"))
    assert all(item["vault_artifact_id"] for item in saved["evidence"])


def test_cli_terraform_assessment(tmp_path: Path) -> None:
    out = tmp_path / "out"
    response = runner.invoke(
        app,
        [
            "assurance",
            "terraform",
            str(lab_plan(tmp_path, "failing")),
            "--procedure",
            str(procedure(tmp_path)),
            "--output-dir",
            str(out),
            "--vault-root",
            str(tmp_path / "vault"),
            "--scope-confirmed",
            "--coverage-complete",
        ],
    )
    assert response.exit_code == 0, response.output
    assert "FAILED" in response.output
    assert "GRCOS-AWS-NET-001: fail" in response.output
    assert verify_evidence_file(out / "cvp-report.json").valid

    missing = runner.invoke(
        app,
        ["assurance", "terraform", str(tmp_path / "nope.json"), "--procedure", "x"],
    )
    assert missing.exit_code == 2
