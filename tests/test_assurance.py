import hashlib
import json

import pytest
from typer.testing import CliRunner

from grcctl.assurance.engine import AssessmentInputError, evaluate_file
from grcctl.cli import app
from grcctl.evidence import verify_evidence_file


def make_case(tmp_path, *, outcome="pass", coverage=True, scope=True):
    source = tmp_path / "observation.txt"
    source.write_text("synthetic control observation", encoding="utf-8")
    payload = {
        "assessment_id": "ASSESS-001",
        "procedure": {
            "id": "CVP-DEMO-001",
            "title": "Synthetic access policy",
            "assertion": "Test identity is denied access",
            "scope": "synthetic sandbox",
            "required_check_ids": ["deny_access"],
            "required_evidence_kinds": ["test-result"],
        },
        "observations": [
            {"check_id": "deny_access", "outcome": outcome, "evidence_ids": ["EV-1"]}
        ],
        "evidence": [
            {
                "id": "EV-1",
                "kind": "test-result",
                "relative_path": "observation.txt",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }
        ],
        "scope_confirmed": scope,
        "coverage_complete": coverage,
    }
    path = tmp_path / "input.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path, source


def test_pass_requires_matching_evidence(tmp_path):
    input_path, source = make_case(tmp_path)
    output = tmp_path / "cvp-output.json"
    report = evaluate_file(input_path, output)
    assert report.verdict == "verified"
    assert report.artifact_checks["EV-1"] == "matched"
    assert verify_evidence_file(output).valid
    source.write_text("tampered", encoding="utf-8")
    assert evaluate_file(input_path, output).verdict == "inconclusive"


def test_failure_with_verified_artifact(tmp_path):
    input_path, _ = make_case(tmp_path, outcome="fail")
    assert evaluate_file(input_path, tmp_path / "out.json").verdict == "failed"


def test_unknown_or_incomplete_is_not_verified(tmp_path):
    input_path, _ = make_case(tmp_path, outcome="unknown")
    assert evaluate_file(input_path, tmp_path / "out.json").verdict == "inconclusive"
    input_path, _ = make_case(tmp_path, coverage=False)
    assert evaluate_file(input_path, tmp_path / "out.json").verdict == "inconclusive"
    input_path, _ = make_case(tmp_path, scope=False)
    assert evaluate_file(input_path, tmp_path / "out.json").verdict == "inconclusive"


def test_missing_check_and_unexecuted_are_not_pass(tmp_path):
    input_path, _ = make_case(tmp_path)
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    payload["observations"] = []
    input_path.write_text(json.dumps(payload), encoding="utf-8")
    assert evaluate_file(input_path, tmp_path / "out.json").verdict == "not_tested"
    payload["observations"] = [
        {"check_id": "unrelated", "outcome": "pass", "evidence_ids": ["EV-1"]}
    ]
    input_path.write_text(json.dumps(payload), encoding="utf-8")
    assert evaluate_file(input_path, tmp_path / "out.json").verdict == "inconclusive"


def test_unsafe_path_and_duplicate_ids(tmp_path):
    input_path, _ = make_case(tmp_path)
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    payload["evidence"][0]["relative_path"] = "../outside.txt"
    input_path.write_text(json.dumps(payload), encoding="utf-8")
    assert evaluate_file(input_path, tmp_path / "out.json").verdict == "inconclusive"
    payload["evidence"].append(payload["evidence"][0])
    input_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(AssessmentInputError):
        evaluate_file(input_path, tmp_path / "out.json")


def test_cli_assurance_evaluate(tmp_path):
    input_path, _ = make_case(tmp_path)
    output = tmp_path / "assess.json"
    response = CliRunner().invoke(
        app, ["assurance", "evaluate", str(input_path), "--output", str(output)]
    )
    assert response.exit_code == 0, response.output
    assert "VERIFIED" in response.output
    assert verify_evidence_file(output).valid
