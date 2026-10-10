# Agentic development SOP — solo technical lead

**Operating capacity:** 20 human review/leadership hours per week; initial limit of **two concurrent implementation tasks**. AI coding agents are task-execution tools, not authorized independent code owners or approvers.

## Agent roles

- **Architect:** propose ADR, interface contracts, implementation plan; must not merge its own design.
- **Builder:** implement exactly one scoped GitHub issue/acceptance contract; publish a small PR.
- **Validator:** independently add/execute success, failure, unknown, tamper, replay and boundary tests.
- **Security reviewer:** inspect authorization, secrets, supply chain, privilege separation, denial of service and evidentiary overclaims.
- **Integrator:** check lock files, dependency versions, branch divergence and CI.
- **Documentation:** update API/schema and operator limitations as part of feature PR.

Roles may be performed sequentially by one assistant, but **validation requires independent fixtures/criteria** set before the implementation whenever feasible. Human approval is required for security-sensitive design and releases.

## Development task contract

Every issue: business objective, actor/user, scoped assertion, dependencies, threat assumptions, input/output schema, negative tests, explicit non-goals, permitted tools/environment, risk category, time budget, definition of done, and decision owner.

Every pull request:
1. Link issue + ADR, if relevant.
2. State change scope, example command, migration impact and external API compatibility.
3. Include tests, evidence of local/CI results and coverage limits.
4. State what was AI-assisted and any unverified assumptions.
5. Include secret scan and dependency checks; no production credentials.
6. Name a human approver for high-impact changes.
7. Avoid automatic deployments, merges or changes to cloud resources absent explicit authorization.

## Autonomy boundaries

| Change | Agent autonomy |
|---|---|
| Documentation, unit-test fixtures, formatting | Prepare PR; normal review |
| Internal code behind existing stable interfaces | Prepare PR; automated CI plus human review |
| API or schema changes | Architectural approval before implementation |
| Policy evaluation, cryptographic proof, evidence trust | Independent adversarial tests; human sign-off |
| Secrets, IAM, active testing, data capture, cloud spend | Explicit human authorization first |
| Production deployment, release tagging, public statements | Human-only approval |

## Six-week proof of productivity

- Week 1: freeze architecture baseline, control vocabulary and first CVP.
- Week 2: scaffold modules and test contracts; CI configuration and branch discipline.
- Week 3: local artifact provenance verification and evidence ingestion design.
- Week 4: bounded CVP engine and adverse/unknown tests.
- Week 5: data model/graph projection and an initial operator view specification.
- Week 6: integrate the existing Terraform evidence source, demonstrate a reproducible report and evaluate actual cycle time.

Do not equate number of generated commits with progress. Measure accepted stories, elapsed review hours, defect escapes, CI pass rate, rework rate and cost per accepted deliverable.

## Weekly human review cadence

- Monday (45–60 min): scope two work items, expected artifacts and acceptance criteria.
- During week: review task reports and CI summaries, approve design decisions, restrict scope creep.
- Friday (60–90 min): demo actual behavior, inspect failure cases, review security/evidence, update forecast and explicitly choose next tasks.

A monitoring dashboard may summarize repository activity, but it may not silently mark a task accepted or a control verified. No agents run continuously without separately configured authorized automation.
