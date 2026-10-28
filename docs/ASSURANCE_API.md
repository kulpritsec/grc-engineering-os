# Read-only assurance API and operator view

**Status:** development slice of the G3 vertical slice (tracks [issue 31](https://github.com/kulpritsec/grc-engineering-os/issues/31), part of [issue 14](https://github.com/kulpritsec/grc-engineering-os/issues/14)). Unauthenticated and local-only: bind to `127.0.0.1`.

## Decision record

Approved by the project product owner on 2026-10-28 before implementation:

1. Read-only GET endpoints only. No assessment execution, uploads or Vault writes over HTTP.
2. A minimal server-rendered operator page now, with no JavaScript framework or external assets, instead of deferring the UI.

## Run

```powershell
$env:GRCOS_VAULT_ROOT = "evidence/vault"   # default when unset
uv run --no-sync --with-requirements requirements/platform-dev.txt `
    uvicorn grcctl.platform_api:app --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080/operator`. To populate a synthetic Vault, follow the lab in [Terraform CVP](TERRAFORM_CVP.md) or the [CVP Vault](CVP_VAULT_LINKS.md) and [publication](ASSURANCE_HISTORY.md) walkthroughs, then point `GRCOS_VAULT_ROOT` at that Vault.

## Endpoints

| Route | Returns |
| --- | --- |
| `GET /v1/assurance/publications?limit=200` | Publications newest first: assessment and procedure IDs, scope, **stored** verdict, times, current report and evidence byte integrity, journal status, `complete`, `consistent`, diagnostics and limitations |
| `GET /v1/assurance/publications/{id}` | The same summary plus the stored report's verdict, reasons, observations, artifact and freshness checks and limitations, and whether the report verdict matches the stored verdict |
| `GET /operator` | HTML list of the first route |
| `GET /operator/publications/{id}` | HTML explanation of the second route |

`limit` is 1–1000 rows per source table. A missing Vault returns 404 and is never created. A store the read-only projection cannot safely read, such as a WAL-mode database, returns 409. Unknown or out-of-limit publication IDs return 404.

## Trust semantics

- **Stored verdicts are claims.** They were recorded at publication and are not re-evaluated; evidence may have aged past its freshness window since. `current_assurance` is always `not_evaluated`.
- **Byte integrity is current.** Report and evidence bytes are rechecked on each request through the existing [relationship projection](EVIDENCE_RELATIONSHIPS.md), within a 64 MiB verification budget.
- **Only stored assessment reports are served.** A report is returned only if its record kind is `assessment-report`, its bytes match the recorded digest and size in a single bounded read (4 MiB), and it parses as a CVP report. Otherwise the response gives the reason (`hash_mismatch`, `not_an_assessment_report`, `invalid_report`, `not_checked_budget`, `missing_record`) and no report body. Source evidence content is never returned.
- **No writes.** Reads use SQLite `mode=ro` and `query_only`; tests confirm the Vault's file inventory and bytes are unchanged after requests. As with the projection, file access times may change.
- Every stored value on the HTML pages is escaped. Stored values are still operator-controlled text.

## Limitations

- No authentication, authorization, rate limiting or TLS. Never bind beyond loopback.
- The view does not re-run CVPs or evaluate current freshness; use `grcctl assurance evaluate` for a current verdict.
- Each request re-projects up to `limit` rows and re-hashes up to 64 MiB, which suits a local development Vault, not large stores.
- `/v1/modules` does not list this API yet; the module inventory is being corrected separately in PR #30.

## Validation

```powershell
uv run --no-sync --with-requirements requirements/platform-dev.txt pytest -q tests/test_assurance_api.py tests/test_platform_api.py
```
