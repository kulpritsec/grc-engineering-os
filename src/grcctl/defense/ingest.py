"""Read-only JSONL adapters; reject malformed observations rather than skipping."""

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .models import DefenseEvent, Source, SourceDigest

MAX_BYTES = 20 * 1024 * 1024
MAX_RECORDS = 20_000


class DefenseInputError(ValueError):
    """Input is missing, unsafe for this bounded pilot, or malformed."""


def _as_map(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DefenseInputError(f"{label}: expected a JSON object")
    return value


def _normalize(
    source: Source, record: dict[str, Any], *, digest: str, line: int
) -> DefenseEvent:
    fields: dict[str, Any] = {
        "id": f"{source}-{digest[:12]}-{line}",
        "source": source,
        "source_file_sha256": digest,
        "source_line": line,
        "observed_at": record.get("timestamp"),
    }
    if source == "artex":
        # Explicit reviewed export contract, NOT a native ARTEX API payload yet.
        fields.update(
            kind=record.get("kind"),
            source_record_id=str(record["id"])
            if record.get("id") is not None
            else None,
            src_ip=record.get("src_ip"),
            dest_ip=record.get("dest_ip"),
            requested_ports=record.get("requested_ports", []),
            description=str(record.get("tool", "")),
        )
    elif source == "suricata":
        alert = _as_map(record.get("alert", {}), "Suricata alert")
        fields.update(
            kind="alert" if record.get("event_type") == "alert" else "network",
            source_record_id=str(record["flow_id"])
            if record.get("flow_id") is not None
            else None,
            src_ip=record.get("src_ip"),
            dest_ip=record.get("dest_ip"),
            dest_port=record.get("dest_port"),
            description=str(alert.get("signature", record.get("event_type", ""))),
            rule_id=str(alert["signature_id"])
            if alert.get("signature_id") is not None
            else None,
        )
    else:
        agent = _as_map(record.get("agent", {}), "Wazuh agent")
        rule = _as_map(record.get("rule", {}), "Wazuh rule")
        data = _as_map(record.get("data", {}), "Wazuh data")
        fields.update(
            kind="alert" if rule.get("id") is not None else "endpoint",
            source_record_id=str(record["id"])
            if record.get("id") is not None
            else None,
            src_ip=data.get("srcip"),
            dest_ip=data.get("dstip") or agent.get("ip"),
            description=str(rule.get("description", "")),
            rule_id=str(rule["id"]) if rule.get("id") is not None else None,
        )
    try:
        return DefenseEvent.model_validate(fields)
    except (ValidationError, ValueError) as exc:
        raise DefenseInputError(
            f"Invalid {source} record at line {line}: {exc}"
        ) from exc


def load_jsonl(path: Path, source: Source) -> tuple[list[DefenseEvent], SourceDigest]:
    """Read one bounded UTF-8 JSONL input; retain source file digest and line numbers."""
    if not path.is_file() or path.is_symlink():
        raise DefenseInputError(f"Missing or non-regular input file: {path}")
    if path.stat().st_size > MAX_BYTES:
        raise DefenseInputError(f"Input exceeds {MAX_BYTES} bytes: {path}")
    payload = path.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    try:
        rows = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise DefenseInputError(f"Input is not UTF-8: {path}") from exc
    if len(rows) > MAX_RECORDS:
        raise DefenseInputError(f"Input exceeds {MAX_RECORDS} records: {path}")
    events: list[DefenseEvent] = []
    for index, row in enumerate(rows, 1):
        if not row.strip():
            continue
        try:
            record = _as_map(json.loads(row), "input")
        except (json.JSONDecodeError, DefenseInputError) as exc:
            raise DefenseInputError(f"Malformed JSON at {path}:{index}: {exc}") from exc
        events.append(_normalize(source, record, digest=digest, line=index))
    return events, SourceDigest(
        source=source, path=str(path), sha256=digest, records=len(events)
    )
