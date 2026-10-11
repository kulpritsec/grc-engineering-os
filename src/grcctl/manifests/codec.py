"""Restricted JSON profile; not a general JSON canonicalization standard."""

import json
import os
import stat
from pathlib import Path
from typing import Any

from .models import Contract, ManifestPayload

MAX_JSON_BYTES = 256 * 1024
DOMAIN = b"kulprit-grc/evidence-manifest/v1\x00"


class ManifestError(ValueError):
    """A manifest operation could not establish its contract."""


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("Duplicate JSON key.")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    raise ManifestError("Floating point and non-finite JSON numbers are forbidden.")


def parse_contract[T: Contract](raw: bytes, model: type[T]) -> T:
    if len(raw) > MAX_JSON_BYTES:
        raise ManifestError("JSON exceeds byte budget.")
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        return model.model_validate(data)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ManifestError(f"Invalid {model.__name__}: {exc}") from exc


def canonical_payload(payload: ManifestPayload) -> bytes:
    # Revalidate even programmatic models; frozen models still contain mutable lists.
    payload = ManifestPayload.model_validate(payload.model_dump(mode="json"))
    data = payload.model_dump(mode="json")
    data["artifacts"] = sorted(data["artifacts"], key=lambda item: item["artifact_id"])
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def signing_bytes(payload: ManifestPayload) -> bytes:
    return DOMAIN + canonical_payload(payload)


def read_bounded(path: Path, limit: int = MAX_JSON_BYTES) -> bytes:
    """Refuse symlink paths and nonregular files; bound reads, including growth."""
    fd: int | None = None
    try:
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ManifestError("Symbolic-link paths are refused.")
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ManifestError("Input is not a bounded regular file.")
        fd = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ManifestError("Input is not a bounded regular file.")
        with os.fdopen(fd, "rb") as reader:
            fd = None
            raw = reader.read(limit + 1)
        if len(raw) > limit:
            raise ManifestError("Input exceeds byte budget.")
        return raw
    except OSError as exc:
        raise ManifestError(f"Cannot read bounded input: {exc}") from exc
    finally:
        if fd is not None:
            os.close(fd)
