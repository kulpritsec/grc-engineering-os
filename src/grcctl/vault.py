"""Development-only, content-addressed local evidence storage.

This implementation checks local byte integrity and stores operator-provided
metadata. It does not authenticate collectors, establish chain of custody,
enforce immutable retention, or provide a production security boundary.
"""

import hashlib
import os
import re
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

_CHUNK_BYTES = 1024 * 1024
_MAX_BYTES = 64 * 1024 * 1024
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_KIND = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")


class VaultError(ValueError):
    """Invalid artifact, corrupted storage, or unsupported local operation."""


@dataclass(frozen=True)
class VaultArtifact:
    artifact_id: str
    sha256: str
    kind: str
    filename: str
    size_bytes: int
    ingested_at: str
    origin_claim: str


@dataclass(frozen=True)
class VaultCheck:
    artifact_id: str
    sha256: str
    status: str
    detail: str

    @property
    def valid(self) -> bool:
        return self.status == "matched"


def _private_dir(path: Path) -> None:
    """Create local vault directories with owner-only permissions."""
    if path.is_symlink():
        raise VaultError(f"Symbolic-link vault directory refused: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir() or path.is_symlink():
        raise VaultError(f"Not a regular vault directory: {path}")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise VaultError(f"Vault directory must be private (0700): {path}")


class LocalEvidenceVault:
    """A bounded local adapter; PostgreSQL/object storage is a later milestone."""

    def __init__(self, root: Path) -> None:
        self.root = root.absolute()
        _private_dir(self.root)
        self.blobs = self.root / "objects" / "sha256"
        self.staging = self.root / "staging"
        _private_dir(self.root / "objects")
        _private_dir(self.blobs)
        _private_dir(self.staging)
        self.db_path = self.root / "vault.db"
        if self.db_path.is_symlink():
            raise VaultError("Symbolic-link vault metadata database refused.")
        if not self.db_path.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            try:
                handle = os.open(self.db_path, flags, 0o600)
                os.close(handle)
            except FileExistsError:
                pass
        if not self.db_path.is_file() or self.db_path.is_symlink():
            raise VaultError("Vault metadata is not a regular file.")
        if os.name == "posix" and self.db_path.stat().st_mode & 0o077:
            raise VaultError("Vault metadata file must be private (0600).")
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                  artifact_id TEXT PRIMARY KEY,
                  sha256 TEXT NOT NULL,
                  kind TEXT NOT NULL,
                  filename TEXT NOT NULL,
                  size_bytes INTEGER NOT NULL,
                  ingested_at TEXT NOT NULL,
                  origin_claim TEXT NOT NULL
                )
                """
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_artifact_digest ON artifacts(sha256)"
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def _object_path(self, digest: str) -> Path:
        if not _DIGEST.fullmatch(digest):
            raise VaultError("Invalid stored SHA-256 digest.")
        return self.blobs / digest[:2] / digest

    def _inspect_object(self, digest: str, expected_size: int) -> tuple[str, str]:
        path = self._object_path(digest)
        if path.is_symlink() or path.parent.is_symlink():
            return "unsafe_store", "Stored object path is a symbolic link."
        if not path.exists():
            return "missing", "Stored object is unavailable."
        fd: int | None = None
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                return "unsafe_store", "Stored object is not a regular file."
            actual = hashlib.sha256()
            size = 0
            with os.fdopen(fd, "rb") as handle:
                fd = None
                for block in iter(lambda: handle.read(_CHUNK_BYTES), b""):
                    actual.update(block)
                    size += len(block)
            if size != expected_size or actual.hexdigest() != digest:
                return "hash_mismatch", "Stored bytes no longer match the record."
            return "matched", "Local artifact bytes match their recorded digest."
        except OSError as exc:
            return "unsafe_store", f"Unable to inspect stored object: {exc}"
        finally:
            if fd is not None:
                os.close(fd)

    def ingest(
        self,
        source: Path,
        *,
        kind: str = "technical-artifact",
        origin_claim: str = "operator-provided (unverified)",
        max_bytes: int = _MAX_BYTES,
    ) -> VaultArtifact:
        """Stage, hash and atomically retain a bounded regular local file."""
        if not _KIND.fullmatch(kind):
            raise VaultError("Artifact kind must be a simple lowercase token.")
        if not origin_claim.strip() or len(origin_claim) > 256:
            raise VaultError("An origin claim of 1–256 characters is required.")
        if max_bytes <= 0:
            raise VaultError("Maximum artifact size must be positive.")
        if source.is_symlink():
            raise VaultError("Refusing to ingest symbolic-link sources.")
        try:
            fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            raise VaultError(f"Unable to read source: {exc}") from exc
        staged_path: Path | None = None
        try:
            with os.fdopen(fd, "rb") as reader:
                if not stat.S_ISREG(os.fstat(reader.fileno()).st_mode):
                    raise VaultError("Source must be a regular file.")
                with tempfile.NamedTemporaryFile(
                    dir=self.staging, prefix="intake-", delete=False
                ) as staged:
                    staged_path = Path(staged.name)
                    os.chmod(staged_path, 0o600)
                    digest = hashlib.sha256()
                    size = 0
                    while chunk := reader.read(_CHUNK_BYTES):
                        size += len(chunk)
                        if size > max_bytes:
                            raise VaultError(
                                "Artifact exceeds the configured size limit."
                            )
                        digest.update(chunk)
                        staged.write(chunk)
                    staged.flush()
                    os.fsync(staged.fileno())
            sha = digest.hexdigest()
            object_path = self._object_path(sha)
            _private_dir(object_path.parent)
            try:
                os.link(staged_path, object_path)
            except FileExistsError:
                # Never silently replace a damaged object with fresh content.
                status, detail = self._inspect_object(sha, size)
                if status != "matched":
                    raise VaultError(f"Existing stored object is invalid: {detail}")
            status, detail = self._inspect_object(sha, size)
            if status != "matched":
                raise VaultError(f"Stored object verification failed: {detail}")
            artifact = VaultArtifact(
                artifact_id=str(uuid4()),
                sha256=sha,
                kind=kind,
                filename=source.name,
                size_bytes=size,
                ingested_at=datetime.now(UTC).isoformat(),
                origin_claim=origin_claim,
            )
            with self._connect() as db:
                db.execute(
                    """
                    INSERT INTO artifacts (
                      artifact_id, sha256, kind, filename, size_bytes,
                      ingested_at, origin_claim
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact.artifact_id,
                        artifact.sha256,
                        artifact.kind,
                        artifact.filename,
                        artifact.size_bytes,
                        artifact.ingested_at,
                        artifact.origin_claim,
                    ),
                )
            return artifact
        finally:
            if staged_path is not None:
                staged_path.unlink(missing_ok=True)

    def get(self, artifact_id: str) -> VaultArtifact:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
        if row is None:
            raise VaultError("Unknown artifact ID.")
        return VaultArtifact(**dict(row))

    def list_artifacts(self, limit: int = 100) -> list[VaultArtifact]:
        if not 1 <= limit <= 1000:
            raise VaultError("Listing limit must be between 1 and 1000.")
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM artifacts ORDER BY ingested_at DESC, "
                "artifact_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [VaultArtifact(**dict(row)) for row in rows]

    def verify(self, artifact_id: str) -> VaultCheck:
        artifact = self.get(artifact_id)
        status, detail = self._inspect_object(artifact.sha256, artifact.size_bytes)
        return VaultCheck(artifact_id, artifact.sha256, status, detail)
