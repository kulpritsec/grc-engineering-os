# Capability inventory

**Checked:** 2026-10-28 against `main` and open pull requests. Update this file when a capability merges or a status changes. "Implemented" means implemented for local, single-user development with synthetic data; nothing here is production-ready or certified.

## Implemented on `main`

| Capability | Entry point | Boundary | Docs |
| --- | --- | --- | --- |
| System baseline evidence | `grcctl doctor` | Local host facts; hash is byte consistency only | README |
| Evidence hash and schema verification | `grcctl evidence verify` | Not origin authentication | README |
| Terraform/OpenTofu plan scanner, four AWS rules | `grcctl scan terraform` | Planned configuration, findings only; no finding is not a pass | [Rules](terraform-assurance-rules.md) |
| CVP evaluator: `verified`/`failed`/`inconclusive`/`not_tested` | `grcctl assurance evaluate` | Caller-declared scope, coverage and outcomes | [CVP Vault Links](CVP_VAULT_LINKS.md) |
| Evidence freshness gate | CVP evaluation and publication | Caller and host-clock times, not trusted time | [Freshness](EVIDENCE_FRESHNESS.md) |
| Local Evidence Vault | `grcctl vault ingest/list/verify` | SQLite plus content-addressed files; operator-mutable, not WORM | [Vault](LOCAL_EVIDENCE_VAULT.md) |
| Publication history and evidence usage | `grcctl assurance publish/history/evidence-usage` | Reevaluates before recording; local metadata | [History](ASSURANCE_HISTORY.md) |
| Hash-chained publication journal | `grcctl assurance journal-verify` | Detects inconsistent local edits; not a signature or witness | [Journal](LOCAL_PUBLICATION_JOURNAL.md) |
| Signed collection-manifest verification | `grcctl manifest` | Development Ed25519 profile against external trust policy; never upgrades CVP verdicts | [Manifests](SIGNED_EVIDENCE_MANIFESTS.md) |
| Read-only evidence relationship projection | `grcctl assurance relationships` | Bounded JSON graph; stored claims are not re-verified | [Relationships](EVIDENCE_RELATIONSHIPS.md) |
| Local API: health, module list, CVP schema, structural preflight | `platform_api` (FastAPI, optional) | Loopback only, unauthenticated, reads no evidence | [Start platform](START_PLATFORM.md) |

## In review

| Capability | Status |
| --- | --- |
| Terraform scan results as CVP observations, per-rule pass/fail/unknown | Draft PR #29 (issue #28, slice of #14) |

## Partial or planned

| Capability | Status | Tracking |
| --- | --- | --- |
| Read-only API and operator view over assurance records | Next slice of G3 | #14 |
| Engineering Control Tower | Specified, not implemented | #15 |
| Canonical control and evidence contracts, stable identifiers | Partially covered by CVP and Vault models | #12 |
| Authenticated collectors, protected storage, trusted time, custody | Not implemented; development manifests only | #13, #21 |
| Deployment-context and applicability assessment | Proposed; needs an ADR and human decisions before implementation | none yet |
| Container, CI/CD, Kubernetes, hypervisor and cloud adapters | Not implemented | none yet |
| Audit Runner, Scout, GRCML Studio, RiskAI | Not implemented | ARCHITECTURE |
| Crypto assurance (CBOM, encryption paths, FIPS evidence) | Design on unmerged branches only | #7–#10 |
| TraceSentinel synthetic tracing labs | Design and case catalog on unmerged branches only | #3–#5 |

## Known documentation and platform debt

- `G2_BASELINE_REVIEW.md` is a historical snapshot; some of its gaps have closed.
- Required evidence kinds are aggregated across observations rather than bound to each required check.
- `scan terraform` prints `Status: PASSED` when there are no findings; that means only that no findings were raised.
- Local Windows runs have two known environment failures (POSIX `0600` mode, symlink privilege). Linux CI is authoritative.
- Platform dependencies are pinned in `requirements/platform-dev.txt` rather than in `uv.lock`.
