import json

from typer.testing import CliRunner

from grcctl.cli import app
from grcctl.doctor import collect_doctor
from grcctl.evidence import verify_evidence_file

runner = CliRunner()


def test_valid_evidence_verifies(tmp_path) -> None:
    output = tmp_path / "baseline.json"
    collect_doctor(output)

    result = verify_evidence_file(output)

    assert result.schema_valid is True
    assert result.integrity_valid is True
    assert result.valid is True


def test_tampering_is_detected(tmp_path) -> None:
    output = tmp_path / "baseline.json"
    collect_doctor(output)

    loaded = json.loads(output.read_text(encoding="utf-8"))
    loaded["platform"]["kernel"] = "tampered-kernel"
    output.write_text(json.dumps(loaded), encoding="utf-8")

    result = verify_evidence_file(output)

    assert result.schema_valid is True
    assert result.integrity_valid is False
    assert result.valid is False


def test_evidence_verify_cli(tmp_path) -> None:
    output = tmp_path / "baseline.json"
    collect_doctor(output)

    result = runner.invoke(
        app,
        ["evidence", "verify", str(output)],
    )

    assert result.exit_code == 0
    assert "VERIFIED" in result.output
