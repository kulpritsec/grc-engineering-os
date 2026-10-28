# Local Publication Journal — G2 Integrity Prototype

**Status: development-only, unsigned, locally mutable SQLite hash chain.**
This feature does **not** constitute an authenticated provenance service, a legal chain of custody, digital signature, trusted timestamp, immutable audit ledger, or WORM storage.

## Purpose and method

Every time `grcctl assurance publish` commits a CVP publication, it now adds a journal event **within the same SQLite transaction**. The event records:

- Sequence number and publication UUID.
- UTC event-generation timestamp (local system clock, **not trusted**).
- Previous event SHA-256 or a fixed genesis marker.
- Digest of the Vault-preserved assessment report.
- Canonical digest of all saved evidence-ID/UUID/kind/digest relationships.
- Event SHA-256 calculated from the canonical serialized fields.

The journal verifier recomputes the chain, detects gaps, and compares events with current publication and relationship rows. The publisher refuses new publications when the pre-existing chain is inconsistent. A single-writer SQLite transaction serializes publication appends.

## Usage

From `main`, after preparing the synthetic
demo in [Assurance History](ASSURANCE_HISTORY.md):

```bash
uv run grcctl assurance publish evidence/demo-cvp-evaluation.json \
    --vault-root evidence/vault

uv run grcctl assurance journal-verify --vault-root evidence/vault
```

A successful result means only that local journal rows, publications and links agree with the stored hashes *at the time checked*. Use `grcctl vault verify` or the catalog's `publication_integrity` to separately recheck underlying artifact bytes; the journal status alone **cannot detect a damaged source blob** if metadata/link rows were unchanged.

## Known limitations

- A sufficiently privileged local operator can modify SQLite and recompute the entire chain.
- Deleting an entire history, rolling back a database, or rewriting the last event alongside metadata can evade a purely local, non-anchored verifier. An independent checkpoint/witness is needed for stronger deletion/rollback detection.
- The local clock is not authenticated; this is not a trusted timestamp.
- The event chain attests neither collector identity nor whether reported observations occurred.
- If older assessment publications predate journal creation, the consistency checker detects a count mismatch and blocks further events. Historic import requires a **separately labeled migration/bootstrap procedure**, not forged retrospective events. No automated backfill is provided.
- SQLite/host filesystem and blob storage still need backup, access policy, locking, encryption, disaster recovery, and security review.
- No HTTP publication or unauthenticated evidence access has been added.

## Next trust boundary

Design a signed external or separately administered checkpoint, authenticated collector/service identities, immutable object retention, and independent audit review. Consider in-toto attestations and hardware-backed or customer-managed signing keys after a threat-model review, with explicit key custody and rotation rules.

## Test cases

`tests/test_assurance_journal.py` validates initial genesis, multiple publications, changed middle hashes, missing events, modified evidence links, publication refusal on inconsistent history, CLI exit codes and separation between journal and blob integrity.
