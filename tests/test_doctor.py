import json

from grcctl.doctor import collect_doctor, hash_payload


def test_hash_payload_is_deterministic() -> None:
    first = {"alpha": 1, "beta": 2}
    second = {"beta": 2, "alpha": 1}

    assert hash_payload(first) == hash_payload(second)
    assert len(hash_payload(first)) == 64


def test_doctor_writes_verifiable_evidence(tmp_path) -> None:
    output = tmp_path / "system-baseline.json"

    evidence = collect_doctor(output)

    assert output.exists()
    assert evidence.schema_version == "0.1.0"

    saved = json.loads(output.read_text(encoding="utf-8"))
    saved_hash = saved.pop("evidence_hash")

    assert hash_payload(saved) == saved_hash
