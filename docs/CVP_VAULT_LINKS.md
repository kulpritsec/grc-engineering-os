# CVP Evidence Vault References — G1 integration

**Status:** development-only link between persistent local Evidence Vault records and a scoped Control Verification Procedure (CVP) evaluation. Not a production-grade assurance or chain-of-custody implementation.

## One artifact, many assessments

Every Vault ingest produces a **stable UUID**, SHA-256 digest, declared evidence kind, time of ingestion and unverified origin claim. A CVP can now reference this UUID instead of an ephemeral source file path. The evaluator resolves the specific *ingestion record*, checks that its recorded type and digest match the assessment's expected type/digest, and verifies the referenced stored object bytes. If the source file is deleted after ingestion, the assessment can still evaluate the preserved copy.

**The current result `verified` means only that a specifically defined assessment assertion had passing observations backed by locally matching bytes, with operator-asserted scope.** It does not prove the original observation, authenticated source, compliance, FIPS validation or signed evidence custody.

## Reproducible local workflow

Use the development branch `feature/cvp-vault-artifact-links` and synthetic data:

```bash
uv sync --locked
printf "synthetic allowed-vs-denied access test\n" > synthetic-test-result.txt
uv run grcctl vault ingest synthetic-test-result.txt --kind test-result
uv run grcctl vault list
```

Copy the **Artifact ID** and **SHA-256** shown by `vault ingest` into the CVP JSON below (replace placeholders):

```json
{
  "assessment_id": "DEMO-001",
  "procedure": {
    "id": "CVP-SYNTH-ACCESS",
    "title": "Synthetic access-control check",
    "assertion": "A designated synthetic user was denied access",
    "scope": "isolated sandbox",
    "required_check_ids": ["deny-access"],
    "required_evidence_kinds": ["test-result"]
  },
  "observations": [
    {"check_id": "deny-access", "outcome": "pass", "evidence_ids": ["EV-1"]}
  ],
  "evidence": [
    {
      "id": "EV-1",
      "kind": "test-result",
      "vault_artifact_id": "PASTE-ARTIFACT-UUID",
      "sha256": "PASTE-SHA256"
    }
  ],
  "scope_confirmed": true,
  "coverage_complete": true
}
```

Save as `demo-cvp.json` and run:

```bash
uv run grcctl assurance evaluate demo-cvp.json \
    --vault-root evidence/vault \
    --output evidence/demo-cvp-evaluation.json
uv run grcctl evidence verify evidence/demo-cvp-evaluation.json
```

The CLI uses `evidence/vault` as its default vault root. Programmatic evaluations that omit a vault root return **inconclusive**, not `verified`. This safeguard prevents opening a different vault accidentally or silently inventing missing evidence.

## Contract

Each evidence reference must contain **exactly one** of:

- `relative_path`: a file inside the assessment JSON workspace (legacy workflow, unchanged); or
- `vault_artifact_id`: a stable UUID of a record in the configured Evidence Vault (new workflow).

Both forms also require `id`, `kind`, and expected `sha256`. The schema rejects both/neither location types. References to missing Vaults, unknown IDs, mismatched kind/digest, tampered/missing object bytes or corrupt stores **cannot** contribute to a passing assessment.

The report retains the evidence IDs, Vault UUID, expected hash, checks performed, reasons, timestamps, and limitations. The existing `grcctl evidence verify` command checks the resulting report's canonical hash and Pydantic structure. This check remains byte integrity, not independently authenticated attestation.

## Review cases

```bash
uv run pytest -q tests/test_vault_assurance.py
uv run ruff format --check .
uv run ruff check .
uv run mypy src
```

The suite tests successful Vault references after deleting original source files; tampered blobs; absent Vault/unknown UUID; kind and digest mismatch; reported failed observations; incomplete scope; combined local-file and Vault evidence; and model-validation rejection of ambiguous source declarations.

## Next integration gate

We are not yet writing a persistent graph index of **which assessments referenced which Vault artifacts**. G2 should introduce an append-only, authenticated assessment publication transaction with stable control IDs, collector identity, retained source evidence, signed manifest, timestamp and reviewer approval. A read-only relationship graph can then be built from verified persisted assessment records, rather than a mutable local JSON report. Avoid adding unrestricted HTTP upload until access controls are implemented.
