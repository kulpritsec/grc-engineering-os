"""Local hash-chained publication journal; NOT digitally signed or WORM.

The same local SQLite operator can alter rows, rewrite the chain and delete
history. Use for accidental/mid-stream corruption detection, not legal custody.
"""

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from ..doctor import hash_payload

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class JournalCheck:
    valid: bool
    events_checked: int
    problems: list[str]


def _link_hash(links: list[dict[str, str]]) -> str:
    """Canonical commitment to a publication's saved evidence link set."""
    normalized = sorted(
        links, key=lambda item: (item["evidence_id"], item["artifact_id"])
    )
    return hash_payload({"links": normalized})


def _event_hash(
    sequence: int,
    publication_id: str,
    occurred_at: str,
    previous_hash: str,
    report_sha256: str,
    links_sha256: str,
) -> str:
    return hash_payload(
        {
            "sequence": sequence,
            "publication_id": publication_id,
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
            "report_sha256": report_sha256,
            "links_sha256": links_sha256,
        }
    )


def create_journal(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS publication_journal (
            sequence INTEGER PRIMARY KEY,
            publication_id TEXT NOT NULL UNIQUE,
            occurred_at TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            report_sha256 TEXT NOT NULL,
            links_sha256 TEXT NOT NULL,
            event_hash TEXT NOT NULL
        )
        """
    )


def append_publication(
    db: sqlite3.Connection,
    *,
    publication_id: str,
    report_sha256: str,
    links: list[dict[str, str]],
) -> str:
    """Append a record inside the caller's publication DB transaction."""
    last = db.execute(
        "SELECT sequence, event_hash FROM publication_journal "
        "ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    sequence = last["sequence"] + 1 if last is not None else 1
    previous_hash = last["event_hash"] if last is not None else GENESIS_HASH
    occurred_at = datetime.now(UTC).isoformat()
    links_sha256 = _link_hash(links)
    event_hash = _event_hash(
        sequence,
        publication_id,
        occurred_at,
        previous_hash,
        report_sha256,
        links_sha256,
    )
    db.execute(
        """
        INSERT INTO publication_journal (
            sequence, publication_id, occurred_at, previous_hash,
            report_sha256, links_sha256, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sequence,
            publication_id,
            occurred_at,
            previous_hash,
            report_sha256,
            links_sha256,
            event_hash,
        ),
    )
    return event_hash


def verify_journal(db: sqlite3.Connection) -> JournalCheck:
    """Check linked records and the local chain against each other."""
    events = db.execute(
        "SELECT * FROM publication_journal ORDER BY sequence"
    ).fetchall()
    publications = db.execute(
        "SELECT publication_id, report_sha256 FROM assessment_publications"
    ).fetchall()
    by_id = {row["publication_id"]: row["report_sha256"] for row in publications}
    problems: list[str] = []
    if len(events) != len(publications):
        problems.append("Publication/event count mismatch.")

    previous = GENESIS_HASH
    for expected_sequence, event in enumerate(events, start=1):
        sequence = event["sequence"]
        pub_id = event["publication_id"]
        if sequence != expected_sequence:
            problems.append(f"Event sequence gap at {expected_sequence}.")
        if event["previous_hash"] != previous:
            problems.append(f"Broken previous-hash link at {sequence}.")
        expected_hash = _event_hash(
            sequence,
            pub_id,
            event["occurred_at"],
            event["previous_hash"],
            event["report_sha256"],
            event["links_sha256"],
        )
        if event["event_hash"] != expected_hash:
            problems.append(f"Event hash mismatch at {sequence}.")
        if by_id.get(pub_id) != event["report_sha256"]:
            problems.append(f"Publication/report metadata mismatch at {sequence}.")

        rows = db.execute(
            """
            SELECT evidence_id, artifact_id, kind, sha256
            FROM assessment_evidence_links
            WHERE publication_id = ?
            """,
            (pub_id,),
        ).fetchall()
        normalized = [
            {
                "evidence_id": row["evidence_id"],
                "artifact_id": row["artifact_id"],
                "kind": row["kind"],
                "sha256": row["sha256"],
            }
            for row in rows
        ]
        if _link_hash(normalized) != event["links_sha256"]:
            problems.append(f"Evidence relationship digest mismatch at {sequence}.")
        previous = event["event_hash"]

    return JournalCheck(
        valid=not problems,
        events_checked=len(events),
        problems=problems,
    )
