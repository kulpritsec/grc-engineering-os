# Engineering Control Tower — initial dashboard contract

**Status:** Requirements; dashboard and live data collectors are not implemented.

## Sources of truth

GitHub Issues are the work backlog; PRs represent proposed changes; commits provide code history; CI is the build/test source; ADRs record human architecture decisions; experimental evidence bundles record acceptance tests. Do not fabricate metrics or treat PR creation as issue completion.

## Views

1. **Decision queue:** architecture approvals, security-sensitive changes, cloud cost authorizations and release approvals; state owner and age.
2. **Sprint board:** issue status, dependencies, blocked reason, target milestone, accepted/non-accepted tests and carried-over scope.
3. **Agent execution:** assigned task, agent role, branch/PR link, test log reference, estimated vs actual human review effort.
4. **CI and code health:** lint/type/test/build results, artifact validity, open vulnerability findings and regression trend.
5. **Assurance of development:** requirement → change → validation → reviewer signoff → release artifact chain.
6. **Architecture drift:** changes crossing module boundaries, missing schema migration, undocumented interfaces.
7. **Capacity:** 20 human hours/week budget; blocked time, cost, rework, acceptance throughput.

## Core metrics, once instrumented

- **Accepted work items/week** (PR merged is not equivalent to accepted).
- **Lead time to accepted change** and **review time**.
- **CI success** by branch, with timestamp and link.
- **Ground-truth test outcomes:** passed/failed/inconclusive, tracked separately.
- **Evidence verification** (integrity check vs authentic-signed evidence).
- **Open critical blockers** with owner and age.
- **Change failure and rollback incidents**, later in pilot.
- **Human effort spent** (planned and actual) and agent task expenses.

Use blank/unknown values until source systems are connected. Preserve historical values when definitions evolve, and provide source links and collection timestamps.

## Decision rules

- High-risk schema, evidence trust, authentication, authorization, agent execution, FIPS/evidence-claim semantics and production operations always require a recorded human decision.
- No CI run can replace a deliberate assertion-specific ground-truth validation.
- No automated cloud deployment without approved account scope, budget limits, and teardown.
- A failed or missing telemetry source must be represented as unknown/incomplete rather than success.

## Proposed first implementation

Build a read-only report generator from GitHub Issues/PR metadata and CI artifacts. Do not grant any dashboard agent write or merge permissions initially. Add a UI only after metrics are derived reliably.
