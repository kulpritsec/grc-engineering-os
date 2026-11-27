import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer import Typer
from typer.testing import CliRunner

from grcctl.defense.cli import defense_app
from grcctl.defense.correlation import correlate, correlate_jsonl
from grcctl.defense.ingest import DefenseInputError, load_jsonl
from grcctl.defense.models import DefenseEvent

HERE = Path(__file__).resolve().parent.parent / "examples"


def test_fixture_correlation_is_candidate_not_verified():
    report = correlate_jsonl(
        HERE / "artex.jsonl", HERE / "suricata.jsonl", HERE / "wazuh.jsonl"
    )
    assert report.event_counts == {"artex": 1, "suricata": 3, "wazuh": 2}
    assert report.correlations[0].attribution == "candidate"
    assert report.correlations[0].conclusion == "inconclusive"
    assert len(report.correlations[0].candidate_event_ids) == 5
    assert len(report.correlations[0].candidate_alert_ids) == 2
    canonical = json.dumps(
        report.model_dump(mode="json", exclude={"evidence_hash"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert report.evidence_hash == hashlib.sha256(canonical).hexdigest()


def test_no_assurance_when_evidence_missing():
    actions, digest = load_jsonl(HERE / "artex.jsonl", "artex")
    report = correlate(actions, [digest])
    assert report.correlations[0].attribution == "not_observed"
    assert report.correlations[0].conclusion == "inconclusive"


def test_wrong_source_does_not_match():
    actions, digest = load_jsonl(HERE / "artex.jsonl", "artex")
    observed, other = load_jsonl(HERE / "suricata.jsonl", "suricata")
    changed = observed[0].model_copy(update={"src_ip": "192.168.77.99"})
    report = correlate(actions + [changed], [digest, other])
    assert report.correlations[0].attribution == "not_observed"


def test_outside_window_does_not_match():
    actions, digest = load_jsonl(HERE / "artex.jsonl", "artex")
    observed, other = load_jsonl(HERE / "suricata.jsonl", "suricata")
    changed = observed[0].model_copy(
        update={"observed_at": actions[0].observed_at + timedelta(hours=2)}
    )
    assert (
        correlate(actions + [changed], [digest, other]).correlations[0].attribution
        == "not_observed"
    )


def test_bad_json_fails_closed(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("{broken}\n", encoding="utf-8")
    with pytest.raises(DefenseInputError, match="Malformed JSON"):
        load_jsonl(path, "suricata")


def test_naive_time_rejected():
    with pytest.raises(ValidationError):
        DefenseEvent(
            id="x",
            source="artex",
            kind="execution",
            observed_at=datetime(2026, 11, 26),  # noqa: DTZ001
            source_file_sha256="0" * 64,
            source_line=1,
        )


def test_cli_creates_owner_only_report(tmp_path):
    root = Typer()
    root.add_typer(defense_app, name="defense")
    result = CliRunner().invoke(
        root,
        [
            "defense",
            "correlate",
            "--artex",
            str(HERE / "artex.jsonl"),
            "--suricata",
            str(HERE / "suricata.jsonl"),
            "--wazuh",
            str(HERE / "wazuh.jsonl"),
            "--output",
            str(tmp_path / "out.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "out.json").stat().st_mode & 0o077 == 0
    assert (
        json.loads((tmp_path / "out.json").read_text())["assessment_type"]
        == "defense-correlation"
    )
    second = CliRunner().invoke(
        root,
        [
            "defense",
            "correlate",
            "--artex",
            str(HERE / "artex.jsonl"),
            "--suricata",
            str(HERE / "suricata.jsonl"),
            "--wazuh",
            str(HERE / "wazuh.jsonl"),
            "--output",
            str(tmp_path / "out.json"),
        ],
    )
    assert second.exit_code == 2
