"""Audit trail for access to governed data.

Every policy-controlled detokenization is recorded, whether it was allowed,
denied or failed, before any plaintext is returned. Views built with
:meth:`colgov.Policy.apply` can be recorded too.

Events never contain data: no plaintext and no tokens, only who, what, when,
why and how many values.

:class:`JsonlAuditLog` writes one JSON object per line and chains each
record to the previous one with SHA-256. Editing, deleting or reordering an
earlier line breaks the chain, which :func:`verify_audit_log` detects.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from os import PathLike
from typing import Any, Protocol

__all__ = [
    "AuditEvent",
    "AuditLog",
    "AuditLogError",
    "JsonlAuditLog",
    "MemoryAuditLog",
    "verify_audit_log",
]

_GENESIS = "0" * 64


class AuditLogError(ValueError):
    """An audit log is malformed or has been tampered with."""


@dataclass(frozen=True)
class AuditEvent:
    """One access attempt. ``outcome`` is ``allowed``, ``denied`` or ``error``."""

    actor: str
    role: str
    action: str
    outcome: str
    columns: tuple[str, ...]
    reason: str
    purpose: str = ""
    count: int = 0
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "at": self.at.isoformat(),
            "actor": self.actor,
            "role": self.role,
            "action": self.action,
            "outcome": self.outcome,
            "columns": list(self.columns),
            "count": self.count,
            "purpose": self.purpose,
            "reason": self.reason,
        }


class AuditLog(Protocol):
    """Anything that can durably record an :class:`AuditEvent`.

    ``record`` must raise if the event could not be stored; callers treat
    that as a reason to withhold data.
    """

    def record(self, event: AuditEvent) -> None: ...


class MemoryAuditLog:
    """Keeps events in a list. For tests and short-lived scripts."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


class JsonlAuditLog:
    """Append-only, hash-chained JSON Lines audit log.

    Each line holds the event plus ``prev`` (the previous line's hash) and
    ``hash`` (SHA-256 over this line's canonical JSON without ``hash``).
    Designed for a single writer; concurrent writers would fork the chain.
    """

    def __init__(self, path: str | PathLike[str]) -> None:
        self.path = os.fspath(path)
        self._last_hash = _last_hash(self.path)

    def record(self, event: AuditEvent) -> None:
        entry = event.to_dict()
        entry["prev"] = self._last_hash
        entry["hash"] = _entry_hash(entry)
        line = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._last_hash = entry["hash"]


def verify_audit_log(path: str | PathLike[str]) -> int:
    """Check a :class:`JsonlAuditLog` file's hash chain. Returns the event count.

    Raises :class:`AuditLogError` naming the first line that fails.
    """
    prev = _GENESIS
    count = 0
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            if not line.strip():
                raise AuditLogError(f"line {lineno}: blank line in audit log")
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditLogError(f"line {lineno}: not valid JSON") from exc
            if not isinstance(entry, dict) or "hash" not in entry or "prev" not in entry:
                raise AuditLogError(f"line {lineno}: missing hash chain fields")
            if entry["prev"] != prev:
                raise AuditLogError(f"line {lineno}: chain broken (a line was removed or reordered)")
            if entry["hash"] != _entry_hash(entry):
                raise AuditLogError(f"line {lineno}: hash mismatch (the line was modified)")
            prev = entry["hash"]
            count += 1
    return count


def record_event(
    audit: AuditLog,
    *,
    actor: str,
    role: str,
    action: str,
    outcome: str,
    columns: Sequence[str],
    reason: str,
    purpose: str = "",
    count: int = 0,
) -> None:
    audit.record(
        AuditEvent(
            actor=actor,
            role=role,
            action=action,
            outcome=outcome,
            columns=tuple(columns),
            reason=reason,
            purpose=purpose,
            count=count,
        )
    )


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _last_hash(path: str) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            if f.tell() == 0:
                return _GENESIS
            # Read backwards to the start of the last line.
            pos = f.tell() - 1
            f.seek(pos)
            if f.read(1) != b"\n":
                raise AuditLogError(f"{path}: last line is incomplete")
            while pos > 0:
                pos -= 1
                f.seek(pos)
                if f.read(1) == b"\n":
                    break
            if pos > 0:
                pos += 1
            f.seek(pos)
            last = f.readline()
    except FileNotFoundError:
        return _GENESIS
    try:
        return json.loads(last)["hash"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise AuditLogError(f"{path}: last line is not a valid audit entry") from exc
