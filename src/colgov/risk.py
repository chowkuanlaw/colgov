"""Re-identification risk scoring for tabular data.

Deterministic tokens keep a column's frequency distribution intact. A column
with few distinct values (gender, state, a yes/no flag) can be read back by
anyone who knows roughly how common each value is, whatever the encryption.
These helpers measure that exposure so a policy can refuse to rely on
tokenization alone.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Hashable, Iterable, Mapping, Sequence
from dataclasses import dataclass

__all__ = [
    "DEFAULT_MIN_DISTINCT",
    "ColumnRisk",
    "KAnonymity",
    "LowCardinalityError",
    "column_risk",
    "k_anonymity",
]

DEFAULT_MIN_DISTINCT = 10
"""Fewest distinct non-null values a column needs before it is tokenized."""


@dataclass(frozen=True)
class ColumnRisk:
    """Frequency profile of a single column. Nulls are counted, not profiled.

    ``min_frequency`` is the column's k: the size of the smallest group of
    rows sharing one value. ``top_share`` is the fraction of non-null rows
    holding the most common value — the chance of guessing a row's value
    right from its token's frequency alone.
    """

    n_rows: int
    n_null: int
    n_distinct: int
    min_frequency: int
    top_share: float

    @property
    def n_non_null(self) -> int:
        return self.n_rows - self.n_null

    def is_low_cardinality(self, min_distinct: int = DEFAULT_MIN_DISTINCT) -> bool:
        """True when the column holds values but too few distinct ones.

        An all-null column is never low cardinality: it has nothing to leak.
        """
        return self.n_non_null > 0 and self.n_distinct < min_distinct


@dataclass(frozen=True)
class KAnonymity:
    """k-anonymity of a table over a set of quasi-identifier columns.

    ``k`` is the size of the smallest equivalence class — the smallest group
    of rows that share every quasi-identifier value. ``k == 1`` means at
    least one row is unique and can be singled out. ``k`` is 0 for an empty
    table.
    """

    k: int
    n_rows: int
    n_classes: int
    class_sizes: tuple[int, ...]
    """Size of every equivalence class, smallest first."""

    def rows_below(self, k: int) -> int:
        """Number of rows sitting in equivalence classes smaller than ``k``."""
        return sum(size for size in self.class_sizes if size < k)


class LowCardinalityError(ValueError):
    """Raised when asked to tokenize a column too predictable to protect."""

    def __init__(self, column: str, risk: ColumnRisk, min_distinct: int) -> None:
        self.column = column
        self.risk = risk
        self.min_distinct = min_distinct
        super().__init__(
            f"column {column!r} has {risk.n_distinct} distinct values "
            f"(minimum {min_distinct}); its tokens could be reversed from "
            f"value frequencies alone. Suppress or generalize the column "
            f"instead, or lower the minimum if you accept that risk."
        )


def column_risk(values: Iterable[Hashable | None]) -> ColumnRisk:
    """Profile one column's values. ``None`` is treated as null."""
    counts: Counter[Hashable] = Counter()
    n_rows = n_null = 0
    for value in values:
        n_rows += 1
        if value is None:
            n_null += 1
        else:
            counts[value] += 1
    n_non_null = n_rows - n_null
    return ColumnRisk(
        n_rows=n_rows,
        n_null=n_null,
        n_distinct=len(counts),
        min_frequency=min(counts.values(), default=0),
        top_share=max(counts.values(), default=0) / n_non_null if n_non_null else 0.0,
    )


def k_anonymity(
    rows: Iterable[Mapping[str, Hashable | None]],
    quasi_identifiers: Sequence[str],
) -> KAnonymity:
    """Measure k-anonymity of ``rows`` over ``quasi_identifiers``.

    Each row is a mapping from column name to value. Nulls take part in
    grouping like any other value. A row missing a quasi-identifier raises
    ``KeyError``.

    >>> rows = [
    ...     {"age": 30, "zip": "50450"},
    ...     {"age": 30, "zip": "50450"},
    ...     {"age": 41, "zip": "10200"},
    ... ]
    >>> result = k_anonymity(rows, ["age", "zip"])
    >>> result.k, result.rows_below(2)
    (1, 1)
    """
    if isinstance(quasi_identifiers, str) or not quasi_identifiers:
        raise ValueError("quasi_identifiers must be a non-empty sequence of column names")
    classes = Counter(tuple(row[c] for c in quasi_identifiers) for row in rows)
    sizes = tuple(sorted(classes.values()))
    return KAnonymity(
        k=sizes[0] if sizes else 0,
        n_rows=sum(sizes),
        n_classes=len(sizes),
        class_sizes=sizes,
    )
