"""pandas helpers: classify, govern and detokenize DataFrames.

Install with ``pip install "colgov[pandas]"``. Missing values (``None``,
``NaN``, ``pd.NA``) are treated as nulls. Tokenized columns must hold
strings; convert other types first, e.g. ``df["id"].astype("string")``.
"""

from __future__ import annotations

from typing import Any

try:
    import pandas as pd
except ImportError as exc:  # pragma: no cover - exercised only without pandas
    raise ImportError('colgov.pandas needs pandas: pip install "colgov[pandas]"') from exc

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
    df: pd.DataFrame,
    pack: RulePack | None = None,
    *,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> dict[str, list[Suggestion]]:
    """Suggest labels for every column of ``df``. Uses the ``core`` pack by default."""
    pack = pack or RulePack.builtin()
    return {
        str(column): pack.classify_column(str(column), _values(df[column]), sample_size=sample_size)
        for column in df.columns
    }


def apply(
    df: pd.DataFrame,
    policy: Policy,
    *,
    role: str,
    catalog: Catalog,
    table: str | None = None,
    tokenizer: Tokenizer | None = None,
    min_distinct: int = DEFAULT_MIN_DISTINCT,
    audit: AuditLog | None = None,
    actor: str | None = None,
) -> pd.DataFrame:
    """Return the columns of ``df`` that ``role`` may see, tokenized where required.

    Same rules and auditing as :meth:`colgov.Policy.apply`. The index is
    kept, and ``clear`` columns keep their original dtype.
    """
    _check_columns(df)
    if audit is not None:
        _require_text(actor, "actor")
    plan = policy.plan(role, list(df.columns), catalog, table=table)
    try:
        out = _build(df, plan, role, tokenizer, min_distinct)
    except Exception as exc:
        if audit is not None:
            record_view(audit, actor, role, plan, "error", str(exc), 0)  # type: ignore[arg-type]
        raise
    if audit is not None:
        record_view(audit, actor, role, plan, "allowed", summarize(plan), len(df))  # type: ignore[arg-type]
    return out


def _build(
    df: pd.DataFrame,
    plan: list[Resolution],
    role: str,
    tokenizer: Tokenizer | None,
    min_distinct: int,
) -> pd.DataFrame:
    if tokenizer is None and any(r.treatment is Treatment.TOKENIZE for r in plan):
        raise PolicyError(f"role {role!r} needs a tokenizer to view this table")
    out: pd.DataFrame = pd.DataFrame(index=df.index)
    for r in plan:
        if r.treatment is Treatment.CLEAR:
            out[r.column] = df[r.column]
        elif r.treatment is Treatment.TOKENIZE:
            tokens = _tokenize_column(tokenizer, _values(df[r.column]), r, min_distinct)  # type: ignore[arg-type]
            out[r.column] = pd.Series(tokens, index=df.index, dtype=object)
    return out


def detokenize(
    tokens: pd.Series,
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
) -> pd.Series:
    """Detokenize a Series under :meth:`colgov.Policy.detokenize`.

    ``column`` defaults to the Series name.
    """
    if column is None:
        column = tokens.name if isinstance(tokens.name, str) else None
    if not isinstance(column, str) or not column:
        raise ValueError("pass column=... or give the Series a name")
    plaintext = policy.detokenize(
        _values(tokens),
        column=column,
        table=table,
        role=role,
        catalog=catalog,
        tokenizer=tokenizer,
        actor=actor,
        purpose=purpose,
        audit=audit,
    )
    return pd.Series(plaintext, index=tokens.index, name=tokens.name, dtype=object)


def _values(series: pd.Series) -> list[Any]:
    """Series values as a list, with every kind of missing value as None."""
    values: list[Any] = series.astype(object).where(series.notna(), None).tolist()
    return values


def _check_columns(df: pd.DataFrame) -> None:
    if not all(isinstance(c, str) for c in df.columns):
        raise TypeError("column names must be strings")
    if df.columns.has_duplicates:
        raise ValueError("column names must be unique")
