"""Development-only local API and landing page for GRC Engineering OS.

The API validates CVP structures; it does not authenticate assessment scope or
evaluate arbitrary user-supplied evidence. Use only on a loopback interface.
"""

from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .assurance.models import AssessmentInput

app = FastAPI(
    title="Kulprit GRC Engineering OS",
    version="0.1.0-dev",
    description=(
        "Local-only platform starter. Structural preflight is not "
        "control verification or regulatory certification."
    ),
)


class PreflightResult(BaseModel):
    assessment_id: str
    structurally_ready: bool
    issues: list[str]
    limitations: list[str]


@app.get("/", response_class=HTMLResponse)
def landing_page() -> str:
    """Show the local development landing page without external resources."""
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kulprit GRC Engineering OS</title>
<style>
body{font:16px system-ui,sans-serif;max-width:850px;margin:5vh auto;
padding:0 24px;background:#111827;color:#f9fafb}
h1{font-size:2rem}p{line-height:1.6;color:#cbd5e1}
section{background:#1f2937;border:1px solid #374151;
padding:20px;border-radius:12px;margin:16px 0}
a{color:#93c5fd}small{color:#9ca3af}
</style>
</head>
<body>
<h1>Kulprit GRC Engineering OS</h1>
<p>Unified assurance platform — local development starter</p>
<section><h2>Assurance Core</h2>
<p>Versioned control verification contracts, evidence references,
and deterministic assessment logic.</p>
<p><a href="/docs">Open interactive API documentation</a></p></section>
<section><h2>Platform services</h2>
<p><a href="/v1/health">Service status</a> |
<a href="/v1/modules">Module roadmap</a> |
<a href="/v1/assurance/schema">CVP input schema</a></p></section>
<small>Development only. No authentication, remote scanners,
persistent Evidence Vault, or live compliance conclusions.</small>
</body></html>"""


@app.get("/v1/health")
def health() -> dict[str, str]:
    """Liveness only, not evidence of a secure production deployment."""
    return {"status": "development", "service": "grc-engineering-os"}


@app.get("/v1/modules")
def modules() -> dict[str, Any]:
    """Advertise actual components separately from planned modules."""
    return {
        "available": ["grcctl", "cvp-contracts", "cvp-local-evaluator"],
        "planned": [
            "evidence-vault",
            "grcml-studio",
            "kaeo",
            "scout",
            "tracesentinel",
            "crypto-assurance",
            "audit-runner",
            "evidence-dynamics",
            "engineering-control-tower",
        ],
        "note": "The HTTP API performs structural preflight only.",
    }


@app.get("/v1/assurance/schema")
def cvp_schema() -> dict[str, Any]:
    """Return the canonical CVP input JSON schema."""
    return AssessmentInput.model_json_schema()


@app.post("/v1/assurance/preflight", response_model=PreflightResult)
def cvp_preflight(payload: AssessmentInput) -> PreflightResult:
    """Check internal references without reading files or trusting outcomes."""
    issues: list[str] = []
    evidence_ids = [item.id for item in payload.evidence]
    observation_ids = [item.check_id for item in payload.observations]
    required = payload.procedure.required_check_ids

    if len(set(evidence_ids)) != len(evidence_ids):
        issues.append("Duplicate evidence IDs.")
    if len(set(observation_ids)) != len(observation_ids):
        issues.append("Duplicate observation check IDs.")
    if len(set(required)) != len(required):
        issues.append("Duplicate required check IDs.")

    for check_id in sorted(set(required) - set(observation_ids)):
        issues.append(f"Required observation missing: {check_id}.")
    for observation in payload.observations:
        if not observation.evidence_ids:
            issues.append(f"Observation {observation.check_id} has no evidence.")
        for evidence_id in observation.evidence_ids:
            if evidence_id not in evidence_ids:
                issues.append(
                    f"Observation {observation.check_id} references "
                    f"unknown evidence: {evidence_id}."
                )

    return PreflightResult(
        assessment_id=payload.assessment_id,
        structurally_ready=not issues,
        issues=issues,
        limitations=[
            "Structural readiness is not an assurance verdict.",
            (
                "Evidence files, hashes, scope, permissions and outcomes were "
                "not verified by this endpoint."
            ),
        ],
    )
