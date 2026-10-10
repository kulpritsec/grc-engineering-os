# Kulprit GRC Engineering OS — repository agent instructions

This repo is a human-led security assurance platform. Agents should produce bounded, reviewable changes and demonstrate limitations.

## Before coding
- Read `docs/ARCHITECTURE.md`, `docs/AGENTIC_DEVELOPMENT.md`, and relevant existing CVP/evidence documentation.
- Use one GitHub issue per task, list acceptance criteria and identify the human approval boundary.
- Do not modify `main` directly or merge your own PR.
- Do not introduce production API credentials, real PII, externally routed canaries or unrestricted active scans.
- Do not deploy AWS/Azure resources or incur costs without explicit authorization.
- Preserve existing `grcctl` commands and test coverage.

## Assurance semantics
- Separate observed facts from inferences and assessment verdicts.
- Missing or stale evidence cannot yield a verified control conclusion.
- A hash match proves byte consistency only, not authenticity or trustworthy collection.
- An AI agent may summarize findings; it may not independently certify its own assessment.
- Regulatory control mappings are candidates until applicability and evidence are reviewed.

## Development workflow
- Python 3.13+, Pydantic v2 and Typer are already in the repo.
- Run `uv sync --locked`, `uv run ruff format --check .`, `uv run ruff check .`, `uv run mypy src`, and `uv run pytest --cov=grcctl --cov-report=term-missing --cov-fail-under=70` before requesting merge.
- Add positive, negative, missing-evidence and tamper tests for assurance logic.
- Provide an operator reproduction command and a PR summary with limitations and risk implications.

See `docs/ENGINEERING_CONTROL_TOWER.md` for monitoring/decision requirements. The control tower is not implemented yet.
