"""PySpark helpers: classify and govern Spark DataFrames.

Install with ``pip install "colgov[spark]"``. Tokenization runs in a UDF on
the executors, so the :class:`colgov.Tokenizer` (and its master key) is
shipped to them with the job. Run it only on a cluster you trust with the
key, and prefer a key from your secret manager over one in a notebook.
colgov must be installed on the executors as well as the driver.
"""

from __future__ import annotations

try:
    from pyspark.sql import DataFrame
    from pyspark.sql import functions as F
    from pyspark.sql.types import StringType
except ImportError as exc:  # pragma: no cover - exercised only without pyspark
    raise ImportError('colgov.spark needs PySpark: pip install "colgov[spark]"') from exc

from colgov.audit import AuditLog
from colgov.policy import (
    Policy,
    PolicyError,
    Resolution,
    Treatment,
    _require_text,
    record_view,
    summarize,
)
from colgov.review import Catalog
from colgov.risk import DEFAULT_MIN_DISTINCT, ColumnRisk, LowCardinalityError
from colgov.rules import DEFAULT_SAMPLE_SIZE, RulePack, Suggestion
from colgov.tokenization import Tokenizer

__all__ = ["apply", "classify"]


def classify(
    sdf: DataFrame,
    pack: RulePack | None = None,
    *,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> dict[str, list[Suggestion]]:
    """Suggest labels for every column. Uses the ``core`` pack by default.

    Values are sampled from the first ``sample_size`` rows, which are
    collected to the driver.
    """
    pack = pack or RulePack.builtin()
    rows = sdf.limit(sample_size).collect()
    return {
        column: pack.classify_column(column, [row[i] for row in rows], sample_size=sample_size)
        for i, column in enumerate(sdf.columns)
    }


def apply(
    sdf: DataFrame,
    policy: Policy,
    *,
    role: str,
    catalog: Catalog,
    table: str | None = None,
    tokenizer: Tokenizer | None = None,
    min_distinct: int = DEFAULT_MIN_DISTINCT,
    audit: AuditLog | None = None,
    actor: str | None = None,
) -> DataFrame:
    """Return a DataFrame with only the columns ``role`` may see.

    Same rules as :meth:`colgov.Policy.apply`: denied columns are dropped,
    tokenized columns go through a UDF, and a tokenized column with fewer
    than ``min_distinct`` distinct non-null values raises
    :class:`colgov.LowCardinalityError`. The cardinality check runs one
    aggregation job; the result itself is lazy, like any Spark DataFrame.

    With ``audit``, the request is recorded when the plan is built (the row
    count is not known then and is recorded as 0).
    """
    if len(set(sdf.columns)) != len(sdf.columns):
        raise ValueError("column names must be unique")
    if audit is not None:
        _require_text(actor, "actor")
    plan = policy.plan(role, sdf.columns, catalog, table=table)
    try:
        out = _build(sdf, plan, role, tokenizer, min_distinct)
    except Exception as exc:
        if audit is not None:
            record_view(audit, actor, role, plan, "error", str(exc), 0)  # type: ignore[arg-type]
        raise
    if audit is not None:
        record_view(audit, actor, role, plan, "allowed", summarize(plan), 0)  # type: ignore[arg-type]
    return out


def _build(
    sdf: DataFrame,
    plan: list[Resolution],
    role: str,
    tokenizer: Tokenizer | None,
    min_distinct: int,
) -> DataFrame:
    to_tokenize = [r.column for r in plan if r.treatment is Treatment.TOKENIZE]
    if to_tokenize and tokenizer is None:
        raise PolicyError(f"role {role!r} needs a tokenizer to view this table")
    types = dict(sdf.dtypes)
    for column in to_tokenize:
        if types[column] != "string":
            raise TypeError(
                f"column {column!r} is {types[column]}, not string; cast it before tokenizing"
            )
    _check_cardinality(sdf, to_tokenize, min_distinct)

    selected = []
    for r in plan:
        if r.treatment is Treatment.CLEAR:
            selected.append(F.col(_quote(r.column)))
        elif r.treatment is Treatment.TOKENIZE:
            udf = _tokenize_udf(tokenizer, r.domain or r.column)  # type: ignore[arg-type]
            selected.append(udf(F.col(_quote(r.column))).alias(r.column))
    return sdf.select(*selected)


def _check_cardinality(sdf: DataFrame, columns: list[str], min_distinct: int) -> None:
    if not columns:
        return
    counts = sdf.agg(*[F.countDistinct(F.col(_quote(c))).alias(f"_{i}") for i, c in enumerate(columns)]).first()
    for i, column in enumerate(columns):
        n_distinct = counts[i]
        if 0 < n_distinct < min_distinct:
            raise LowCardinalityError(column, _small_column_risk(sdf, column), min_distinct)


def _small_column_risk(sdf: DataFrame, column: str) -> ColumnRisk:
    """Exact profile of a column known to have few distinct values."""
    freq = {row[0]: row[1] for row in sdf.groupBy(F.col(_quote(column))).count().collect()}
    n_null = freq.pop(None, 0)
    n_rows = n_null + sum(freq.values())
    n_non_null = n_rows - n_null
    return ColumnRisk(
        n_rows=n_rows,
        n_null=n_null,
        n_distinct=len(freq),
        min_frequency=min(freq.values(), default=0),
        top_share=max(freq.values(), default=0) / n_non_null if n_non_null else 0.0,
    )


def _tokenize_udf(tokenizer: Tokenizer, column: str):
    # No type hints: Spark would try to infer an Arrow (pandas) UDF from them.
    def tokenize(value):
        return tokenizer.tokenize(value, column=column)

    return F.udf(tokenize, StringType())


def _quote(column: str) -> str:
    return "`" + column.replace("`", "``") + "`"
