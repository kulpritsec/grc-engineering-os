"""Read-only assurance API and operator view over a synthetic local Vault."""

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from grcctl.assurance import views
from grcctl.assurance.catalog import LocalAssuranceCatalog
from grcctl.assurance.engine import evaluate_file
from grcctl.platform_api import app
from grcctl.vault import LocalEvidenceVault

SOURCE_MARKER = "SYNTHETIC-SOURCE-CONTENT-7f3a"
client = TestClient(app)


def publish_case(
    root: Path,
    work: Path,
    *,
    outcome: str = "pass",
    coverage: bool = True,
    procedure_id: str = "CVP-API-001",
) -> tuple[str, str]:
    work.mkdir()
    source = work / "observation.txt"
    source.write_text(f"{SOURCE_MARKER} {outcome}", encoding="utf-8")
    stored = LocalEvidenceVault(root).ingest(source, kind="test-result")
    data = {
        "assessment_id": f"ASMT-{work.name}",
        "procedure": {
            "id": procedure_id,
            "title": "Synthetic API fixture",
            "assertion": "Synthetic test identity is denied access",
            "scope": "synthetic sandbox",
            "required_check_ids": ["deny"],
            "required_evidence_kinds": ["test-result"],
            "max_evidence_age_seconds": 86400,
        },
        "observations": [
            {"check_id": "deny", "outcome": outcome, "evidence_ids": ["EV-1"]}
        ],
        "evidence": [
            {
                "id": "EV-1",
                "kind": "test-result",
                "vault_artifact_id": stored.artifact_id,
                "sha256": stored.sha256,
                "collected_at": stored.ingested_at,
            }
        ],
        "scope_confirmed": True,
        "coverage_complete": coverage,
    }
    (work / "input.json").write_text(json.dumps(data), encoding="utf-8")
    report = work / "report.json"
    evaluate_file(work / "input.json", report, vault_root=root)
    publication = LocalAssuranceCatalog(root).publish(report)
    return publication.publication_id, stored.sha256


@pytest.fixture
def vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "vault"
    publish_case(root, tmp_path / "verified")
    publish_case(root, tmp_path / "failed", outcome="fail")
    publish_case(root, tmp_path / "inconclusive", coverage=False)
    monkeypatch.setenv("GRCOS_VAULT_ROOT", str(root))
    return root


def blob(root: Path, digest: str) -> Path:
    return root / "objects" / "sha256" / digest[:2] / digest


def inventory(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def listing() -> dict:
    response = client.get("/v1/assurance/publications")
    assert response.status_code == 200, response.text
    return response.json()


def test_lists_publications_as_stored_claims(vault: Path) -> None:
    body = listing()
    verdicts = sorted(p["stored_verdict"] for p in body["publications"])
    assert verdicts == ["failed", "inconclusive", "verified"]
    assert body["complete"] is True
    assert body["consistent"] is True
    assert body["journal"]["status"] == "consistent"
    for publication in body["publications"]:
        assert publication["current_assurance"] == "not_evaluated"
        assert publication["report_integrity"] == "matched"
        assert [e["integrity"] for e in publication["evidence"]] == ["matched"]
        assert publication["procedure_id"] == "CVP-API-001"
    assert any("not re-evaluated" in item for item in body["limitations"])


def test_detail_serves_verified_report_explanation(vault: Path) -> None:
    target = next(
        p for p in listing()["publications"] if p["stored_verdict"] == "failed"
    )
    response = client.get(f"/v1/assurance/publications/{target['publication_id']}")
    assert response.status_code == 200
    body = response.json()
    assert body["report_status"] == "matched"
    assert body["report"]["verdict"] == "failed"
    assert body["stored_verdict_matches_report"] is True
    assert "An evidenced, scoped control check failed." in body["report"]["reasons"]
    assert body["report"]["freshness_checks"] == {"EV-1": "fresh"}
    assert body["report"]["observations"][0]["outcome"] == "fail"


def test_tampered_evidence_is_visible(vault: Path, tmp_path: Path) -> None:
    _pub, digest = publish_case(vault, tmp_path / "tamper-ev")
    blob(vault, digest).write_text("tampered", encoding="utf-8")
    body = listing()
    states = [e["integrity"] for p in body["publications"] for e in p["evidence"]]
    assert "hash_mismatch" in states
    assert body["consistent"] is False


def test_tampered_report_is_not_served(vault: Path) -> None:
    target = listing()["publications"][0]
    record = LocalEvidenceVault(vault).get(target["report_artifact_id"])
    blob(vault, record.sha256).write_text('{"verdict": "verified"}', encoding="utf-8")
    response = client.get(f"/v1/assurance/publications/{target['publication_id']}")
    assert response.status_code == 200
    body = response.json()
    assert body["publication"]["report_integrity"] == "hash_mismatch"
    assert body["report_status"] == "hash_mismatch"
    assert body["report"] is None


def test_damaged_journal_is_inconsistent(vault: Path) -> None:
    with closing(sqlite3.connect(vault / "vault.db")) as db, db:
        db.execute(
            "UPDATE publication_journal SET event_hash = ? WHERE sequence = 1",
            ("0" * 64,),
        )
    body = listing()
    assert body["journal"]["status"] == "inconsistent"
    assert body["consistent"] is False


def test_requests_do_not_modify_the_vault(vault: Path) -> None:
    before = inventory(vault)
    publication_id = listing()["publications"][0]["publication_id"]
    for path in (
        "/v1/assurance/publications",
        f"/v1/assurance/publications/{publication_id}",
        "/operator",
        f"/operator/publications/{publication_id}",
    ):
        assert client.get(path).status_code == 200
    assert inventory(vault) == before


def test_source_content_is_never_served(vault: Path) -> None:
    publication_id = listing()["publications"][0]["publication_id"]
    for path in (
        "/v1/assurance/publications",
        f"/v1/assurance/publications/{publication_id}",
        "/operator",
        f"/operator/publications/{publication_id}",
    ):
        assert SOURCE_MARKER not in client.get(path).text


def test_missing_vault_is_not_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "absent" / "vault"
    monkeypatch.setenv("GRCOS_VAULT_ROOT", str(missing))
    assert client.get("/v1/assurance/publications").status_code == 404
    assert client.get("/operator").status_code == 404
    assert not (tmp_path / "absent").exists()


def test_unknown_publication_is_404(vault: Path) -> None:
    assert client.get("/v1/assurance/publications/not-a-publication").status_code == 404
    assert client.get("/operator/publications/not-a-publication").status_code == 404


def test_limit_is_bounded_and_reports_incompleteness(vault: Path) -> None:
    for bad in (0, 1001):
        response = client.get(f"/v1/assurance/publications?limit={bad}")
        assert response.status_code == 422
    body = client.get("/v1/assurance/publications?limit=1").json()
    assert len(body["publications"]) == 1
    assert body["complete"] is False


def test_operator_pages_escape_stored_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "vault"
    hostile = "<script>alert(1)</script>"
    publication_id, _ = publish_case(root, tmp_path / "hostile", procedure_id=hostile)
    monkeypatch.setenv("GRCOS_VAULT_ROOT", str(root))
    for path in ("/operator", f"/operator/publications/{publication_id}"):
        page = client.get(path)
        assert page.status_code == 200
        assert "text/html" in page.headers["content-type"]
        assert hostile not in page.text
        assert "&lt;script&gt;" in page.text
        assert "<script" not in page.text


def test_operator_pages_label_claims(vault: Path) -> None:
    page = client.get("/operator").text
    assert "Stored verdict" in page
    assert "not re-evaluated" in page
    failed = next(
        p for p in listing()["publications"] if p["stored_verdict"] == "failed"
    )
    detail = client.get(f"/operator/publications/{failed['publication_id']}").text
    assert "An evidenced, scoped control check failed." in detail
    assert "deny" in detail


def test_unsupported_store_is_409(vault: Path) -> None:
    with closing(sqlite3.connect(vault / "vault.db")) as db:
        db.execute("PRAGMA journal_mode=WAL")
    assert client.get("/v1/assurance/publications").status_code == 409
    assert client.get("/operator").status_code == 409


def test_report_reader_serves_only_valid_assessment_reports(
    vault: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalEvidenceVault(vault)
    summary = listing()["publications"][0]
    evidence_id = summary["evidence"][0]["artifact_id"]
    assert views._report(vault, {**summary, "report_artifact_id": evidence_id}) == (
        "not_an_assessment_report",
        None,
    )
    fake = tmp_path / "fake-report.json"
    fake.write_text('{"verdict": "verified"}', encoding="utf-8")
    forged = store.ingest(fake, kind="assessment-report").artifact_id
    assert views._report(vault, {**summary, "report_artifact_id": forged}) == (
        "invalid_report",
        None,
    )
    unknown = {**summary, "report_artifact_id": "missing-id"}
    assert views._report(vault, unknown) == ("missing_record", None)
    monkeypatch.setattr(views, "MAX_REPORT_BYTES", 8)
    assert views._report(vault, summary) == ("not_checked_budget", None)


def test_read_verified_single_read(tmp_path: Path) -> None:
    source = tmp_path / "artifact.txt"
    source.write_text("synthetic bytes", encoding="utf-8")
    store = LocalEvidenceVault(tmp_path / "vault")
    record = store.ingest(source, kind="test-result")
    reader = LocalEvidenceVault(tmp_path / "vault", readonly=True)
    assert reader.read_verified(record, max_bytes=1024) == (
        "matched",
        b"synthetic bytes",
    )
    assert reader.read_verified(record, max_bytes=4) == ("not_checked_budget", None)
    path = blob(tmp_path / "vault", record.sha256)
    path.write_bytes(b"synthetic BYTES")
    assert reader.read_verified(record, max_bytes=1024) == ("hash_mismatch", None)
    path.unlink()
    assert reader.read_verified(record, max_bytes=1024) == ("missing", None)
