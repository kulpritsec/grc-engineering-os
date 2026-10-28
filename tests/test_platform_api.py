"""Tests for the optional local FastAPI starter.

The base CLI project does not depend on FastAPI. CI without API extras skips
these checks until the optional API dependencies are added to the lockfile.
"""

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from grcctl.platform_api import app

client = TestClient(app)


def _payload() -> dict[str, object]:
    return {
        "assessment_id": "ASSESS-DEMO-001",
        "procedure": {
            "id": "CVP-DEMO-001",
            "title": "Sandbox access test",
            "assertion": "Unauthorized test identity is denied access.",
            "scope": "synthetic sandbox",
            "required_check_ids": ["deny"],
            "required_evidence_kinds": ["test-result"],
            "max_evidence_age_seconds": 86400,
        },
        "observations": [
            {"check_id": "deny", "outcome": "pass", "evidence_ids": ["ev-1"]}
        ],
        "evidence": [
            {
                "id": "ev-1",
                "kind": "test-result",
                "relative_path": "test.txt",
                "sha256": "0" * 64,
                "collected_at": "2026-10-01T12:00:00Z",
            }
        ],
        "scope_confirmed": False,
        "coverage_complete": False,
    }


def test_landing_page_and_health() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Kulprit GRC Engineering OS" in response.text
    response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "development"


def test_module_inventory_does_not_claim_planned_are_live() -> None:
    response = client.get("/v1/modules")
    assert response.status_code == 200
    body = response.json()
    assert "authenticated-evidence-vault" in body["planned"]
    assert "local-evidence-vault-cli" in body["available"]
    assert not set(body["available"]) & set(body["planned"])


def test_cvp_schema_exposes_contract() -> None:
    response = client.get("/v1/assurance/schema")
    assert response.status_code == 200
    assert "properties" in response.json()
    assert "procedure" in response.json()["properties"]


def test_preflight_does_not_claim_verification() -> None:
    response = client.post("/v1/assurance/preflight", json=_payload())
    assert response.status_code == 200
    body = response.json()
    assert body["structurally_ready"] is True
    assert "verdict" not in body
    assert any("not verified" in line for line in body["limitations"])


def test_missing_required_observation_and_invalid_reference() -> None:
    payload = _payload()
    payload["observations"] = [
        {"check_id": "other", "outcome": "pass", "evidence_ids": ["missing-id"]}
    ]
    response = client.post("/v1/assurance/preflight", json=payload)
    assert response.status_code == 200
    assert response.json()["structurally_ready"] is False
    assert any("Required observation missing" in x for x in response.json()["issues"])
    assert any("unknown evidence" in x for x in response.json()["issues"])


def test_schema_validation_rejects_missing_procedure() -> None:
    payload = _payload()
    payload.pop("procedure")
    response = client.post("/v1/assurance/preflight", json=payload)
    assert response.status_code == 422


def test_preflight_accepts_vault_reference_without_verifying_source() -> None:
    payload = _payload()
    payload["evidence"][0].pop("relative_path")
    payload["evidence"][0]["vault_artifact_id"] = "synthetic-vault-uuid"
    response = client.post("/v1/assurance/preflight", json=payload)
    assert response.status_code == 200
    assert response.json()["structurally_ready"] is True
    assert "verdict" not in response.json()
    assert any("not verified" in item for item in response.json()["limitations"])


def test_preflight_rejects_ambiguous_evidence_source() -> None:
    payload = _payload()
    payload["evidence"][0]["vault_artifact_id"] = "synthetic-vault-uuid"
    response = client.post("/v1/assurance/preflight", json=payload)
    assert response.status_code == 422


def test_preflight_flags_missing_freshness_inputs() -> None:
    payload = _payload()
    payload["procedure"].pop("max_evidence_age_seconds")
    payload["evidence"][0].pop("collected_at")
    response = client.post("/v1/assurance/preflight", json=payload)
    assert response.status_code == 200
    issues = response.json()["issues"]
    assert response.json()["structurally_ready"] is False
    assert "Procedure declares no evidence freshness policy." in issues
    assert "Evidence ev-1 has no declared collection time." in issues


def test_preflight_rejects_naive_collection_time() -> None:
    payload = _payload()
    payload["evidence"][0]["collected_at"] = "2026-10-01T12:00:00"
    response = client.post("/v1/assurance/preflight", json=payload)
    assert response.status_code == 422
