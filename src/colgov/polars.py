"""Polars helpers: classify, govern and detokenize DataFrames.

Install with ``pip install "colgov[polars]"``. Nulls stay nulls. Tokenized
columns must hold strings; cast other types first, e.g.
``df.with_columns(pl.col("id").cast(pl.String))``. These functions take an
eager ``DataFrame``; call ``.collect()`` on a ``LazyFrame`` first.
"""

from __future__ import annotations

from typing import Any

try:
    import polars as pl
except ImportError as exc:  # pragma: no cover - exercised only without polars
    raise ImportError('colgov.polars needs Polars: pip install "colgov[polars]"') from exc

from colgov.audit import AuditLog
from colgov.policy import (
    Policy,
    PolicyError,
    Resolution,
    Treatment,
    _require_text,
    _tokenize_column,
    record_view,
    summarize,
)
from colgov.review import Catalog
from colgov.risk import DEFAULT_MIN_DISTINCT
from colgov.rules import DEFAULT_SAMPLE_SIZE, RulePack, Suggestion
from colgov.tokenization import Tokenizer

__all__ = ["apply", "classify", "detokenize"]


def classify(
    df: pl.DataFrame,
    pack: RulePack | None = None,
    *,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> dict[str, list[Suggestion]]:
    """Suggest labels for every column of ``df``. Uses the ``core`` pack by default."""
    pack = pack or RulePack.builtin()
    head = df.head(sample_size)
    return {
        column: pack.classify_column(column, head.get_column(column).to_list(), sample_size=sample_size)
        for column in df.columns
    }


def apply(
    df: pl.DataFrame,
    policy: Policy,
    *,
    role: str,
    catalog: Catalog,
    table: str | None = None,
    tokenizer: Tokenizer | None = None,
    min_distinct: int = DEFAULT_MIN_DISTINCT,
    audit: AuditLog | None = None,
    actor: str | None = None,
) -> pl.DataFrame:
    """Return the columns of ``df`` that ``role`` may see, tokenized where required.

    Same rules and auditing as :meth:`colgov.Policy.apply`. ``clear``
    columns keep their dtype; tokenized columns become ``String``.
    """
    if audit is not None:
        _require_text(actor, "actor")
    plan = policy.plan(role, df.columns, catalog, table=table)
    try:
        out = _build(df, plan, role, tokenizer, min_distinct)
    except Exception as exc:
        if audit is not None:
            record_view(audit, actor, role, plan, "error", str(exc), 0)  # type: ignore[arg-type]
        raise
    if audit is not None:
        record_view(audit, actor, role, plan, "allowed", summarize(plan), df.height)  # type: ignore[arg-type]
    return out


def detokenize(
    tokens: pl.Series,
    policy: Policy,
    *,
    role: str,
    catalog: Catalog,
    tokenizer: Tokenizer,
    actor: str,
    purpose: str,
    audit: AuditLog,
    column: str | None = None,
    table: str | None = None,
) -> pl.Series:
    """Detokenize a Series under :meth:`colgov.Policy.detokenize`.

    ``column`` defaults to the Series name.
    """
    column = column or tokens.name
    if not column:
        raise ValueError("pass column=... or give the Series a name")
    plaintext = policy.detokenize(
        tokens.to_list(),
        column=column,
        table=table,
        role=role,
        catalog=catalog,
        tokenizer=tokenizer,
        actor=actor,
        purpose=purpose,
        audit=audit,
    )
    return pl.Series(tokens.name, plaintext, dtype=pl.String)


def _build(
    df: pl.DataFrame,
    plan: list[Resolution],
    role: str,
    tokenizer: Tokenizer | None,
    min_distinct: int,
) -> pl.DataFrame:
    if tokenizer is None and any(r.treatment is Treatment.TOKENIZE for r in plan):
        raise PolicyError(f"role {role!r} needs a tokenizer to view this table")
    columns: list[pl.Series] = []
    for r in plan:
        series = df.get_column(r.column)
        if r.treatment is Treatment.CLEAR:
            columns.append(series)
        elif r.treatment is Treatment.TOKENIZE:
            if series.dtype not in (pl.String, pl.Categorical, pl.Null):
                raise TypeError(f"column {r.column!r} is {series.dtype}, not String; cast it before tokenizing")
            values: list[Any] = series.cast(pl.String).to_list()
            tokens = _tokenize_column(tokenizer, values, r, min_distinct)  # type: ignore[arg-type]
            columns.append(pl.Series(r.column, tokens, dtype=pl.String))
    return pl.DataFrame(columns)
