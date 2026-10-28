# Start the Kulprit GRC Engineering OS development API

**Status:** optional, local-only FastAPI starter on `main`. Not a production
backend.

## 1. Install the existing locked CLI dependencies

```bash
git clone https://github.com/kulpritsec/grc-engineering-os.git
cd grc-engineering-os
uv sync --locked
```

## 2. Launch the starter API (loopback only)

The existing `uv.lock` remains unchanged. API development requirements
are applied to this run without changing the project's locked base environment:

```bash
uv run --no-sync --with-requirements requirements/platform-dev.txt \
    uvicorn grcctl.platform_api:app --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080/` and `http://127.0.0.1:8080/docs`.
The server exposes a landing page, health, module statuses, CVP JSON
schema, structural CVP preflight and read-only views of published
assessments (see [Assurance API](ASSURANCE_API.md)). It **does not** run
scanners from HTTP, store evidence, serve source evidence or prove assessment
claims.

## 3. Run focused API tests

```bash
uv run --no-sync --with-requirements requirements/platform-dev.txt \
    pytest -q tests/test_platform_api.py tests/test_assurance.py
```

Base project checks remain `uv sync --locked`, `uv run ruff ...`,
`uv run mypy src`, `uv run pytest ...`, and `uv build` as documented
in README. The API tests may skip under the base CI environment until API
dependencies are integrated into the lockfile. This is temporary scaffolding,
not a completed release dependency strategy.

## 4. Exercise CVP preflight

The endpoint `POST /v1/assurance/preflight` accepts the
`AssessmentInput` Pydantic JSON contract and checks missing required
observation IDs, duplicate IDs and broken evidence references. It **does
not** read untrusted file paths, hash files, authenticate the caller, or
assert `verified` based on caller-supplied data.

The local CLI's separate `grcctl assurance evaluate` command is currently
the only bounded evidence-byte evaluator. Its `verified` verdict is
conditional on caller-declared scope and **local hash consistency only**.

## 5. Next step

Add the authenticated evidence ingestion service, signing, reference
validation and persistent storage **before** exposing assessment APIs on a
network. The HTTP server currently has no authentication, request rate limits,
or tenant isolation. **Never bind to `0.0.0.0` or expose it to the internet.**
