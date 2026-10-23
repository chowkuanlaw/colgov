"""Save verified audit log checkpoints outside the log, locally or in S3."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from os import PathLike
from typing import Any
from urllib.parse import urlsplit

from colgov.audit import audit_state

__all__ = ["AuditCheckpoint", "CheckpointError", "load_checkpoint", "save_checkpoint"]


class CheckpointError(ValueError):
    """A checkpoint destination or checkpoint document is invalid."""


@dataclass(frozen=True)
class AuditCheckpoint:
    count: int
    final_hash: str
    created_at: str

    @classmethod
    def from_dict(cls, data: Any) -> AuditCheckpoint:
        if not isinstance(data, dict) or set(data) != {"version", "count", "final_hash", "created_at"}:
            raise CheckpointError("checkpoint must have version, count, final_hash and created_at")
        if (
            data["version"] != 1
            or not isinstance(data["count"], int)
            or isinstance(data["count"], bool)
            or data["count"] < 0
        ):
            raise CheckpointError("unsupported checkpoint version or count")
        value = data["final_hash"]
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise CheckpointError("checkpoint final_hash must be 64 lowercase hex digits")
        timestamp = data["created_at"]
        if not isinstance(timestamp, str):
            raise CheckpointError("checkpoint created_at must be an ISO 8601 timestamp")
        try:
            if datetime.fromisoformat(timestamp).tzinfo is None:
                raise ValueError("timezone required")
        except ValueError as exc:
            raise CheckpointError("checkpoint created_at must have a timezone") from exc
        return cls(data["count"], value, timestamp)

    def to_dict(self) -> dict[str, Any]:
        return {"version": 1, "count": self.count, "final_hash": self.final_hash, "created_at": self.created_at}


def _s3_location(uri: str) -> tuple[str, str] | None:
    if not uri.startswith("s3://"):
        return None
    parsed = urlsplit(uri)
    if not parsed.netloc or not parsed.path.lstrip("/") or parsed.query or parsed.fragment:
        raise CheckpointError("S3 checkpoint URI must be s3://bucket/key without a query or fragment")
    return parsed.netloc, parsed.path.lstrip("/")


def _s3_client() -> Any:
    try:
        import boto3
    except ImportError as exc:
        raise CheckpointError('S3 checkpoints need boto3: pip install "colgov[aws]"') from exc
    return boto3.client("s3")


def save_checkpoint(
    log: str | PathLike[str],
    destination: str | PathLike[str],
    *,
    retention_days: int | None = None,
    s3_client: Any = None,
) -> AuditCheckpoint:
    """Verify ``log`` and save its count and hash without overwriting a checkpoint.

    S3 uses a conditional put. For immutable checkpoints, configure S3 Object
    Lock and provide ``retention_days``; the bucket must support Object Lock.
    Local checkpoint files are created exclusively with mode 0600.
    """
    if retention_days is not None and retention_days < 1:
        raise CheckpointError("retention_days must be positive")
    count, final_hash = audit_state(log)
    checkpoint = AuditCheckpoint(count, final_hash, datetime.now(timezone.utc).isoformat())
    payload = (json.dumps(checkpoint.to_dict(), sort_keys=True) + "\n").encode("utf-8")
    target = os.fspath(destination)
    location = _s3_location(target)
    if location is not None:
        bucket, key = location
        options: dict[str, Any] = {
            "Bucket": bucket,
            "Key": key,
            "Body": payload,
            "ContentType": "application/json",
            "IfNoneMatch": "*",
        }
        if retention_days is not None:
            options["ObjectLockMode"] = "COMPLIANCE"
            options["ObjectLockRetainUntilDate"] = datetime.now(timezone.utc) + timedelta(days=retention_days)
            options["ChecksumAlgorithm"] = "SHA256"
        try:
            (s3_client or _s3_client()).put_object(**options)
        except Exception as exc:
            raise CheckpointError(f"S3 checkpoint write failed: {exc}") from exc
    else:
        if retention_days is not None:
            raise CheckpointError("retention_days requires an S3 destination")
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
    return checkpoint


def load_checkpoint(source: str | PathLike[str], *, s3_client: Any = None) -> AuditCheckpoint:
    """Read and validate a checkpoint from a local file or S3 object."""
    location = _s3_location(os.fspath(source))
    if location is not None:
        bucket, key = location
        try:
            payload = (s3_client or _s3_client()).get_object(Bucket=bucket, Key=key)["Body"].read(4097)
        except Exception as exc:
            raise CheckpointError(f"S3 checkpoint read failed: {exc}") from exc
    else:
        with open(source, "rb") as file:
            payload = file.read(4097)
    if len(payload) > 4096:
        raise CheckpointError("checkpoint is too large")
    try:
        data = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CheckpointError("checkpoint is not valid JSON") from exc
    return AuditCheckpoint.from_dict(data)
