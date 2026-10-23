"""Preview key rotation without changing or revealing token values."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from colgov.tokenization import InvalidToken, Tokenizer

__all__ = ["RotationError", "RotationImpact", "preview_rotation"]


class RotationError(ValueError):
    """A token cannot be authenticated under its declared domain and keyring."""


@dataclass(frozen=True)
class RotationImpact:
    column: str
    domain: str
    total: int
    null: int
    current: int
    reissue: int


def preview_rotation(
    rows: Iterable[Mapping[str, str | None]],
    domains: Mapping[str, str],
    tokenizer: Tokenizer,
) -> list[RotationImpact]:
    """Authenticate every token and count those needing reissue.

    No plaintext or token is included in the result. An invalid token aborts
    the preview with its row and column, before a misleading count is shown.
    """
    if not domains or any(not column or not domain for column, domain in domains.items()):
        raise RotationError("domains must map at least one column to a non-empty token domain")
    counts = {column: {"total": 0, "null": 0, "current": 0, "reissue": 0} for column in domains}
    for row_number, row in enumerate(rows, start=1):
        for column, domain in domains.items():
            try:
                value = row[column]
            except KeyError as exc:
                raise RotationError(f"row {row_number}: missing column {column!r}") from exc
            count = counts[column]
            count["total"] += 1
            if value is None:
                count["null"] += 1
                continue
            if not isinstance(value, str):
                raise RotationError(f"row {row_number}, column {column!r}: token must be a string")
            try:
                tokenizer.detokenize(value, column=domain)
            except InvalidToken as exc:
                raise RotationError(f"row {row_number}, column {column!r}: invalid token") from exc
            count["current" if tokenizer.is_current(value) else "reissue"] += 1
    return [RotationImpact(column, domain, **counts[column]) for column, domain in domains.items()]
