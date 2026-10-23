"""Generate an ANSI SQL view over raw and pretokenized companion columns.

This module emits SQL; it never connects to a warehouse. The caller must
produce the token columns with colgov, keep them current with the raw data,
and restrict direct access to the source table in the warehouse.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from colgov.policy import Policy, Treatment
from colgov.review import Catalog

__all__ = ["SQL_DIALECTS", "SqlViewError", "generate_view_sql"]

SQL_DIALECTS = ("ansi", "postgres", "snowflake", "bigquery")


class SqlViewError(ValueError):
    """A SQL view cannot safely be generated from the supplied schema."""


def generate_view_sql(
    policy: Policy,
    catalog: Catalog,
    *,
    role: str,
    columns: Sequence[str],
    source: str,
    view: str,
    token_columns: Mapping[str, str],
    table: str | None = None,
    dialect: str = "ansi",
) -> str:
    """Return a ``CREATE VIEW`` statement for the selected SQL dialect.

    ``columns`` are the physical source columns, including any pretokenized
    companions. ``token_columns`` maps a logical column to its token column.
    A ``tokenize`` grant requires a mapping; the raw column is never used for
    that treatment. Companion columns are excluded from the output schema.

    The source table must be protected by warehouse permissions. This view
    does not tokenize data, validate tokens, check cardinality, or grant SQL
    permissions. Its token columns must be populated separately with colgov.
    """
    if dialect not in SQL_DIALECTS:
        raise SqlViewError(f"unsupported SQL dialect {dialect!r}")
    physical = list(columns)
    if len(set(physical)) != len(physical) or any(not isinstance(c, str) or not c for c in physical):
        raise SqlViewError("physical column names must be unique, non-empty strings")
    if not physical:
        raise SqlViewError("source must have columns")
    names = set(physical)
    targets: set[str] = set()
    for logical, token in token_columns.items():
        if logical not in names or token not in names:
            raise SqlViewError(f"token mapping {logical!r} -> {token!r} must name source columns")
        if logical == token:
            raise SqlViewError(f"token column for {logical!r} must differ from its raw column")
        if token in targets:
            raise SqlViewError(f"token column {token!r} is mapped more than once")
        targets.add(token)
    if any(logical in targets for logical in token_columns):
        raise SqlViewError("a token column cannot also be a logical column in a token mapping")

    logical_columns = [column for column in physical if column not in targets]
    selected = []
    for resolution in policy.plan(role, logical_columns, catalog, table=table):
        if resolution.treatment is Treatment.CLEAR:
            selected.append(_identifier(resolution.column, dialect))
        elif resolution.treatment is Treatment.TOKENIZE:
            mapped_token = token_columns.get(resolution.column)
            if mapped_token is None:
                raise SqlViewError(f"column {resolution.column!r} needs a pretokenized source column")
            selected.append(f"{_identifier(mapped_token, dialect)} AS {_identifier(resolution.column, dialect)}")
    if not selected:
        raise SqlViewError(f"role {role!r} has no visible columns")
    source_name = _qualified_identifier(source, dialect)
    view_name = _qualified_identifier(view, dialect)
    if source_name == view_name:
        raise SqlViewError("source and view must differ")
    return f"CREATE VIEW {view_name} AS\nSELECT\n  " + ",\n  ".join(selected) + f"\nFROM {source_name};"


def _identifier(name: str, dialect: str) -> str:
    if not isinstance(name, str) or not name or "\x00" in name:
        raise SqlViewError("SQL identifiers must be non-empty and cannot contain NUL")
    if dialect == "bigquery":
        return "`" + name.replace("\\", "\\\\").replace("`", "\\`") + "`"
    return '"' + name.replace('"', '""') + '"'


def _qualified_identifier(name: str, dialect: str) -> str:
    if not isinstance(name, str):
        raise SqlViewError("SQL table names must be strings")
    return ".".join(_identifier(part, dialect) for part in name.split("."))
