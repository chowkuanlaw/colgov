"""Exact, bounded-memory risk profiles and enforceable thresholds.

Values are keyed with a random process-local HMAC before they reach the
temporary SQLite database. Only counts and opaque digests touch disk.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from colgov.risk import DEFAULT_MIN_DISTINCT, ColumnRisk

__all__ = ["RiskThresholdError", "RiskThresholds", "profile_columns", "risk_violations"]


class RiskThresholdError(ValueError):
    """A column failed a configured risk threshold."""


@dataclass(frozen=True)
class RiskThresholds:
    min_distinct: int = DEFAULT_MIN_DISTINCT
    max_top_share: float | None = None
    min_frequency: int | None = None

    def __post_init__(self) -> None:
        if self.min_distinct < 1:
            raise ValueError("min_distinct must be positive")
        if self.max_top_share is not None and not 0 <= self.max_top_share <= 1:
            raise ValueError("max_top_share must be between 0 and 1")
        if self.min_frequency is not None and self.min_frequency < 1:
            raise ValueError("min_frequency must be positive")


def risk_violations(risk: ColumnRisk, thresholds: RiskThresholds) -> list[str]:
    """Return failed threshold descriptions for a column profile."""
    if not risk.n_non_null:
        return []
    failures = []
    if risk.n_distinct < thresholds.min_distinct:
        failures.append(f"distinct {risk.n_distinct} < {thresholds.min_distinct}")
    if thresholds.max_top_share is not None and risk.top_share > thresholds.max_top_share:
        failures.append(f"top share {risk.top_share:.4f} > {thresholds.max_top_share:.4f}")
    if thresholds.min_frequency is not None and risk.min_frequency < thresholds.min_frequency:
        failures.append(f"minimum frequency {risk.min_frequency} < {thresholds.min_frequency}")
    return failures


def profile_columns(rows: Iterable[Sequence[str | None]], columns: Sequence[str]) -> dict[str, ColumnRisk]:
    """Profile string columns exactly while bounding memory via temporary SQLite.

    ``rows`` must contain one value per ``columns`` entry. The temporary file
    contains HMAC digests and counts, never the source values. The HMAC key is
    generated afresh for each call and is never persisted.
    """
    names = list(columns)
    if len(set(names)) != len(names) or any(not isinstance(name, str) or not name for name in names):
        raise ValueError("columns must have unique non-empty names")
    key = secrets.token_bytes(32)
    descriptor, path = tempfile.mkstemp(prefix="colgov-risk-", suffix=".sqlite3")
    os.close(descriptor)
    n_rows = 0
    nulls = dict.fromkeys(names, 0)
    try:
        with sqlite3.connect(path) as connection:
            connection.execute(
                "CREATE TABLE frequencies (column_name TEXT NOT NULL, digest BLOB NOT NULL, "
                "frequency INTEGER NOT NULL, PRIMARY KEY (column_name, digest))"
            )
            for row in rows:
                if len(row) != len(names):
                    raise ValueError("row length does not match columns")
                n_rows += 1
                for name, value in zip(names, row, strict=True):
                    if value is None:
                        nulls[name] += 1
                        continue
                    if not isinstance(value, str):
                        raise ValueError(f"column {name!r} contains a non-string value")
                    digest = hmac.digest(key, value.encode("utf-8"), hashlib.sha256)
                    connection.execute(
                        "INSERT INTO frequencies VALUES (?, ?, 1) "
                        "ON CONFLICT (column_name, digest) DO UPDATE SET frequency = frequency + 1",
                        (name, digest),
                    )
            profiles = {}
            for name in names:
                distinct, minimum, maximum = connection.execute(
                    "SELECT COUNT(*), MIN(frequency), MAX(frequency) FROM frequencies WHERE column_name = ?", (name,)
                ).fetchone()
                non_null = n_rows - nulls[name]
                profiles[name] = ColumnRisk(
                    n_rows=n_rows,
                    n_null=nulls[name],
                    n_distinct=distinct,
                    min_frequency=minimum or 0,
                    top_share=(maximum or 0) / non_null if non_null else 0.0,
                )
            return profiles
    finally:
        os.unlink(path)
