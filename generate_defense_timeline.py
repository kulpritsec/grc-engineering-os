#!/usr/bin/env python3
"""Build a read-only ARTEX/Suricata/Wazuh forensic timeline from lab exports.

Inputs are verified against known SHA-256 hashes before interpretation. The
output is written once (never overwritten) under ~/lab-evidence/.
"""

import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

root = Path.home() / "lab-evidence"

files = {
    "artex": (
        "artex-conv8-tool66-provenance.jsonl",
        "099e34ed5a422ec0bf884ce10c831cd668b55458f081420e4d6e9dc21aa82291",
    ),
    "suricata": (
        "suricata-target-window-20261127.jsonl",
        "dd706cdfe4ec28af7a153e16e4b3273cfe76bd86e6a1a6b0cc4a9786ef440bec",
    ),
    "wazuh": (
        "wazuh-agent006.jsonl",
        "3d593d49f1b31223abd44438ce90f0f9627e48579a4c561edbfdf0bffa75a845",
    ),
}

records = {}
digests = {}

for source, (filename, expected) in files.items():
    raw = (root / filename).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected:
        raise SystemExit(
            f"Hash mismatch: {filename}\nExpected: {expected}\nActual:   {digest}"
        )
    records[source] = [
        json.loads(line) for line in raw.splitlines() if line.strip()
    ]
    digests[source] = digest

if len(records["artex"]) != 1:
    raise SystemExit("Expected exactly one ARTEX provenance record")
action = records["artex"][0]


def utc(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Naive timestamp refused")
    return dt.astimezone(timezone.utc)


approved = utc(action["authorization_decided_at"])
ended = utc(action["execution_ended_at"])

events = []
counts = Counter()

for source in ("suricata", "wazuh"):
    for record in records[source]:
        time = utc(record["timestamp"])

        if source == "wazuh":
            src = (record.get("data") or {}).get("srcip")
            dst = (
                (record.get("data") or {}).get("dstip")
                or (record.get("agent") or {}).get("ip")
            )
            kind = f"wazuh-rule-{record['rule']['id']}"
        else:
            src = record.get("src_ip")
            dst = record.get("dest_ip")
            kind = record.get("event_type")

        if (src, dst) != ("192.168.77.10", "192.168.77.20"):
            raise SystemExit(f"Unexpected endpoints in {source}: {src} -> {dst}")

        if time < approved:
            phase = "before_recorded_authorization"
        elif time <= ended:
            phase = "authorization_to_execution_end"
        else:
            phase = "after_recorded_execution_end"

        counts[(source, phase)] += 1
        events.append(
            {
                "time_utc": time.isoformat(),
                "source": source,
                "kind": kind,
                "phase": phase,
            }
        )

events.sort(key=lambda e: e["time_utc"])

report = {
    "assessment_type": "defense-timeline-pilot",
    "conclusion": "inconclusive",
    "art_ex_tool_use_id": action["tool_use_id"],
    "art_ex_provenance": action,
    "source_sha256": digests,
    "event_counts": {source: len(records[source]) for source in records},
    "events": events,
    "limitations": [
        "Source timestamps have not been independently synchronized.",
        "ARTEX tool request time is not proven command execution start.",
        "Pre-authorization events cannot be attributed to this authorized execution.",
        "Post-completion network records may reflect delayed flow logging.",
        "Temporal association alone does not establish causation.",
    ],
}

output = root / "defense-real-timeline-20261127.json"
os.umask(0o077)

with output.open("x", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
    f.write("\n")

print("=== Timeline classification ===")
for (source, phase), count in sorted(counts.items()):
    print(f"{source:9} {phase:38} {count}")

print("\nTotal sensor observations:", len(events))
print("Report:", output)
print("SHA-256:", hashlib.sha256(output.read_bytes()).hexdigest())
