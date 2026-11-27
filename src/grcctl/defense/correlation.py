"""Deterministic candidate correlations; never infer a verified control outcome."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from .ingest import DefenseInputError, load_jsonl
from .models import Correlation, DefenseEvent, DefenseReport, Source, SourceDigest


def correlate(
    events: list[DefenseEvent], sources: list[SourceDigest], window_seconds: int = 90
) -> DefenseReport:
    if not 1 <= window_seconds <= 3600:
        raise DefenseInputError("window_seconds must be in the range 1..3600")
    actions = [e for e in events if e.source == "artex" and e.kind == "execution"]
    telemetry = [e for e in events if e.source in ("wazuh", "suricata")]
    links: list[Correlation] = []
    for action in actions:
        candidates = [
            event
            for event in telemetry
            if action.src_ip is not None
            and action.dest_ip is not None
            and event.src_ip == action.src_ip
            and event.dest_ip == action.dest_ip
            and (
                not action.requested_ports
                or event.dest_port is None
                or event.dest_port in action.requested_ports
            )
            and abs((event.observed_at - action.observed_at).total_seconds())
            <= window_seconds
        ]
        links.append(
            Correlation(
                action_event_id=action.id,
                candidate_event_ids=[e.id for e in candidates],
                candidate_alert_ids=[e.id for e in candidates if e.kind == "alert"],
                attribution="candidate" if candidates else "not_observed",
                reason=(
                    "Matching source, destination, and approximate time; attribution not independently verified."
                    if candidates
                    else "No matching observation in supplied logs/window; not evidence of prevention or non-occurrence."
                ),
            )
        )
    report = DefenseReport(
        generated_at=datetime.now(UTC),
        window_seconds=window_seconds,
        source_digests=sources,
        event_counts={
            source: sum(e.source == source for e in events)
            for source in ("artex", "suricata", "wazuh")
        },
        correlations=links,
        limitations=[
            "All timestamps are source-reported; clock synchronization and latency are unverified.",
            "Source/destination/time joins are candidate correlations, not proof of attribution; NAT or concurrent traffic may confound.",
            "The ARTEX input is a reviewed JSONL export contract, not a verified native ARTEX API adapter.",
            "Input digests show byte consistency only; no collector authentication or forensic custody is asserted.",
            "No control effectiveness or compliance verdict is established by this report.",
        ],
    )
    canonical = json.dumps(
        report.model_dump(mode="json", exclude={"evidence_hash"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    report.evidence_hash = hashlib.sha256(canonical).hexdigest()
    return report


def correlate_jsonl(
    artex: Path, suricata: Path, wazuh: Path, window_seconds: int = 90
) -> DefenseReport:
    sources: list[SourceDigest] = []
    events: list[DefenseEvent] = []
    source_paths: tuple[tuple[Path, Source], ...] = (
        (artex, "artex"),
        (suricata, "suricata"),
        (wazuh, "wazuh"),
    )
    for path, source in source_paths:
        new_events, digest = load_jsonl(path, source)
        events.extend(new_events)
        sources.append(digest)
    return correlate(events, sources, window_seconds)
