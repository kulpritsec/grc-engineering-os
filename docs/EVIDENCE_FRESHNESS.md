# CVP evidence freshness gate

**Status:** development contract. Closes the G2 baseline gap "a stale artifact can currently support `verified`" and enforces the AGENTS.md rule that missing or stale evidence cannot yield a verified control conclusion. It does not introduce trusted time.

## Decision record

Approved by the project product owner on 2026-10-21 (Claude Code session) before implementation:

1. A procedure **must** declare a freshness policy for any `verified` or `failed` verdict. Without one, the result is `inconclusive` with the reason that freshness was not evaluated. This is a deliberate breaking change for policy-free CVP inputs.
2. Freshness gates trust uniformly. Stale evidence behind a `fail` observation yields `inconclusive`, not `failed`, because it says nothing about the control's current state.
3. `assurance publish` rechecks freshness at **publication time**, not the report's caller-controlled `evaluated_at`. Evidence that ages out between evaluation and publication is refused.

## Input contract

| Field | Location | Rule |
| --- | --- | --- |
| `max_evidence_age_seconds` | `procedure` | Strict integer, 1 to 315,360,000 (ten 365-day years). Strings, floats and booleans are rejected. |
| `collected_at` | each `evidence` reference | ISO 8601 timestamp string with an explicit offset; normalized to UTC. Naive times and numeric epochs are rejected. |

```json
"procedure": { "...": "...", "max_evidence_age_seconds": 86400 },
"evidence": [
  {
    "id": "EV-1",
    "kind": "test-result",
    "vault_artifact_id": "PASTE-ARTIFACT-UUID",
    "sha256": "PASTE-SHA256",
    "collected_at": "2026-10-21T09:00:00Z"
  }
]
```

## Evaluation

Each reference whose bytes match receives a status in the report's new `freshness_checks` map. `artifact_checks` keeps its existing byte-integrity meaning.

| Status | Meaning | Can support a conclusion |
| --- | --- | --- |
| `fresh` | Earliest known time is within the policy window, inclusive | Yes |
| `stale` | Evaluation time minus the earliest known time exceeds the window | No |
| `no_policy` | Procedure declares no `max_evidence_age_seconds` | No |
| `unknown_collection_time` | No `collected_at`, and no Vault ingestion old enough to prove staleness | No |
| `future_timestamp` | `collected_at` or Vault ingestion time is after the evaluation time | No |
| `collected_after_ingestion` | Declared collection time is later than the Vault ingestion time | No |
| `invalid_ingestion_time` | Stored Vault ingestion time is unparseable or has no offset | No |
| `not_checked` | Bytes did not match, so freshness was not assessed | No |

The reference time is the **earlier** of `collected_at` and the Vault `ingested_at`. Collection cannot follow ingestion, so an old ingestion proves staleness even when a caller declares a recent collection time. Ingestion alone never proves freshness, because the bytes may have been collected long before they were ingested.

An observation is trusted only when every evidence reference it cites is both `matched` and `fresh`. Untrusted observations cannot satisfy required evidence kinds or produce `failed`. Report schema version is now `0.2.0`; `0.1.0` reports still parse and still pass `grcctl evidence verify`.

## Publication

`LocalAssuranceCatalog.publish` reevaluates at the host clock. Its programmatic `at` argument exists for deterministic tests and may only move the check later, never earlier. If bytes still match but any freshness status differs from the report, publication is refused with a freshness error; byte tampering keeps its existing errors. Schema `0.1.0` reports carry no freshness checks and are therefore refused, so they must be re-evaluated with a policy. Stored publications and journal events are unchanged; there is no SQLite migration.

The structural API preflight now reports a missing policy and any reference without `collected_at` as issues.

## Limitations

- `collected_at` is a caller claim and `ingested_at` is the local host clock. Neither is a trusted timestamp, and both can be rewritten by the local operator.
- The procedure, including its policy window, is caller-supplied. A rehashed report with a widened window is honored as declared; an authenticated procedure registry remains future work.
- A signed manifest's `collected_at` is not yet used here. Authenticated collection time remains separate from CVP verdicts, as in [Signed Evidence Manifests](SIGNED_EVIDENCE_MANIFESTS.md).
- One window applies to all evidence kinds in a procedure. Per-kind windows, clock-skew tolerance and revocation of previously published conclusions are not implemented.
- `fresh` means only "within the declared window by local clocks". It does not establish that the observation is accurate or that the control is effective.

## Reproduce

```powershell
uv sync --locked
uv run pytest -q tests/test_evidence_freshness.py
uv run ruff format --check .
uv run ruff check .
uv run --no-sync --with-requirements requirements/platform-dev.txt mypy src
uv run --no-sync --with-requirements requirements/platform-dev.txt pytest --cov=grcctl --cov-report=term-missing --cov-fail-under=70
```
