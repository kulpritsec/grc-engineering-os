"""Development-only local API and landing page for GRC Engineering OS.

The API validates CVP structures; it does not authenticate assessment scope or
evaluate arbitrary user-supplied evidence. Read-only assurance views read the
local Vault at ``GRCOS_VAULT_ROOT`` without writing to it. Use only on a
loopback interface.
"""

import os
from html import escape
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .assurance.models import AssessmentInput
from .assurance.views import (
    StoreUnsupportedError,
    VaultUnavailableError,
    list_publications,
    publication_detail,
)

Limit = Annotated[int, Query(ge=1, le=1000)]

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
<a href="/v1/assurance/schema">CVP input schema</a> |
<a href="/operator">Published assessments</a></p></section>
<small>Development only. No authentication, remote scanners,
HTTP access to source evidence, or live compliance conclusions.</small>
</body></html>"""


@app.get("/v1/health")
def health() -> dict[str, str]:
    """Liveness only, not evidence of a secure production deployment."""
    return {"status": "development", "service": "grc-engineering-os"}


@app.get("/v1/modules")
def modules() -> dict[str, Any]:
    """Advertise actual components separately from planned modules."""
    return {
        "available": [
            "grcctl",
            "cvp-contracts",
            "cvp-local-evaluator",
            "local-evidence-vault-cli",
        ],
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

    if payload.procedure.max_evidence_age_seconds is None:
        issues.append("Procedure declares no evidence freshness policy.")
    for item in payload.evidence:
        if item.collected_at is None:
            issues.append(f"Evidence {item.id} has no declared collection time.")

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


def _vault_root() -> Path:
    return Path(os.environ.get("GRCOS_VAULT_ROOT", "evidence/vault"))


def _load(call: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return call(_vault_root(), *args, **kwargs)
    except VaultUnavailableError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except StoreUnsupportedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/v1/assurance/publications")
def assurance_publications(limit: Limit = 200) -> dict[str, Any]:
    """List published assessments as stored claims with current byte checks."""
    result: dict[str, Any] = _load(list_publications, limit=limit)
    return result


@app.get("/v1/assurance/publications/{publication_id}")
def assurance_publication(publication_id: str, limit: Limit = 200) -> dict[str, Any]:
    """One publication with its verified stored report, never source evidence."""
    detail: dict[str, Any] | None = _load(
        publication_detail, publication_id, limit=limit
    )
    if detail is None:
        raise HTTPException(status_code=404, detail="Unknown publication ID.")
    return detail


_PAGE_STYLE = (
    "body{font:15px system-ui,sans-serif;max-width:1100px;margin:4vh auto;"
    "padding:0 16px;background:#111827;color:#f9fafb}"
    "table{border-collapse:collapse;width:100%}"
    "th,td{border-bottom:1px solid #374151;padding:6px 8px;text-align:left;"
    "vertical-align:top}"
    "a{color:#93c5fd}.note{background:#1f2937;border:1px solid #374151;"
    "padding:10px 14px;border-radius:8px}.bad{color:#fca5a5}"
)


def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    html = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escape(title)}</title><style>{_PAGE_STYLE}</style></head>"
        f"<body>{body}</body></html>"
    )
    return HTMLResponse(html, status_code=status_code)


def _text(value: object) -> str:
    return escape("" if value is None else str(value))


def _marked(value: object, good: str = "matched") -> str:
    text = _text(value)
    return text if value == good else f'<span class="bad">{text}</span>'


def _notes(items: list[str]) -> str:
    return "".join(f"<li>{_text(item)}</li>" for item in items)


def _page_load(call: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return _load(call, *args, **kwargs)
    except HTTPException as exc:
        return _page(
            "Unavailable",
            f"<h1>Unavailable</h1><p>{_text(exc.detail)}</p>",
            exc.status_code,
        )


@app.get("/operator", response_class=HTMLResponse)
def operator_publications(limit: Limit = 200) -> HTMLResponse:
    """Read-only list of publications; stored verdicts are not re-evaluated."""
    data = _page_load(list_publications, limit=limit)
    if isinstance(data, HTMLResponse):
        return data
    rows = "".join(
        "<tr>"
        f'<td><a href="/operator/publications/{_text(p["publication_id"])}">'
        f"{_text(p['assessment_id'])}</a></td>"
        f"<td>{_text(p['procedure_id'])}<br><small>{_text(p['scope'])}</small></td>"
        f"<td>{_text(p['stored_verdict'])}</td>"
        f"<td>{_text(p['published_at'])}</td>"
        f"<td>{_marked(p['report_integrity'])}</td>"
        f"<td>{', '.join(_marked(e['integrity']) for e in p['evidence'])}</td>"
        "</tr>"
        for p in data["publications"]
    )
    journal = data["journal"].get("status", "not_present")
    diagnostics = _notes(data["diagnostics"]) or "<li>None</li>"
    body = (
        "<h1>Published assessments</h1>"
        f'<div class="note"><ul>{_notes(data["limitations"])}</ul></div>'
        f"<p>Journal: {_marked(journal, 'consistent')} · "
        f"Complete: {_text(data['complete'])} · "
        f"Consistent: {_text(data['consistent'])}</p>"
        "<table><tr><th>Assessment</th><th>Procedure / scope</th>"
        "<th>Stored verdict</th><th>Published</th><th>Report bytes</th>"
        f"<th>Evidence bytes</th></tr>{rows}</table>"
        f"<h2>Diagnostics</h2><ul>{diagnostics}</ul>"
    )
    return _page("Published assessments", body)


@app.get("/operator/publications/{publication_id}", response_class=HTMLResponse)
def operator_publication(publication_id: str, limit: Limit = 200) -> HTMLResponse:
    """Read-only explanation of one publication from its verified report."""
    data = _page_load(publication_detail, publication_id, limit=limit)
    if isinstance(data, HTMLResponse):
        return data
    if data is None:
        return _page("Not found", "<h1>Unknown publication</h1>", 404)
    publication = data["publication"]
    report = data["report"]
    if report is None:
        explanation = (
            '<p class="bad">Stored report not shown: '
            f"{_text(data['report_status'])}.</p>"
        )
    else:
        observations = "".join(
            f"<tr><td>{_text(o['check_id'])}</td><td>{_text(o['outcome'])}</td>"
            f"<td>{_text(o['detail'])}</td></tr>"
            for o in report["observations"]
        )
        checks = "".join(
            f"<tr><td>{_text(key)}</td><td>{_marked(value)}</td>"
            f"<td>{_marked(report['freshness_checks'].get(key), 'fresh')}</td></tr>"
            for key, value in report["artifact_checks"].items()
        )
        explanation = (
            f"<p>Report verdict: <strong>{_text(report['verdict'])}</strong> "
            f"(evaluated {_text(report['evaluated_at'])}; matches stored verdict: "
            f"{_text(data['stored_verdict_matches_report'])})</p>"
            f"<p>{_text(report['procedure']['assertion'])}</p>"
            f"<h2>Reasons</h2><ul>{_notes(report['reasons'])}</ul>"
            "<h2>Observations</h2><table><tr><th>Check</th><th>Outcome</th>"
            f"<th>Detail</th></tr>{observations}</table>"
            "<h2>Evidence at evaluation</h2><table><tr><th>Evidence</th>"
            f"<th>Bytes</th><th>Freshness</th></tr>{checks}</table>"
            f"<h2>Report limitations</h2><ul>{_notes(report['limitations'])}</ul>"
        )
    current = "".join(
        f"<tr><td>{_text(e['evidence_id'])}</td><td>{_text(e['kind'])}</td>"
        f"<td>{_marked(e['integrity'])}</td></tr>"
        for e in publication["evidence"]
    )
    body = (
        '<p><a href="/operator">All publications</a></p>'
        f"<h1>{_text(publication['assessment_id'])}</h1>"
        f'<div class="note"><ul>{_notes(data["limitations"])}</ul></div>'
        f"<p>Procedure: {_text(publication['procedure_id'])} · "
        f"Scope: {_text(publication['scope'])}<br>"
        f"Stored verdict: <strong>{_text(publication['stored_verdict'])}</strong> · "
        f"Published: {_text(publication['published_at'])} · "
        f"Report bytes now: {_marked(publication['report_integrity'])}</p>"
        f"{explanation}"
        "<h2>Evidence bytes now</h2><table><tr><th>Evidence</th><th>Kind</th>"
        f"<th>Bytes</th></tr>{current}</table>"
    )
    return _page(str(publication["assessment_id"]), body)
