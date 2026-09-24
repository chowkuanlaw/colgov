"""Human review of classification suggestions: a machine suggests, a person decides.

A :class:`Catalog` records one decision per column: which label it carries,
who decided, when, and why. Only decided columns can ever become visible
under a :class:`colgov.Policy`; a column with suggestions but no decision
stays pending, and pending columns are denied.

Decisions are keyed by table and column, so an ``id`` column in two tables
gets two independent decisions. Decisions made without a table apply only
to lookups made without a table: there is no fallback between the two, so a
decision can never silently cover a column it wasn't made for.

Catalogs round-trip through YAML so decisions can be reviewed in a pull
request like any other change::

    version: 2
    tables:
      customers:
        columns:
          email: {label: email, decided_by: alice, decided_at: ..., domain: customer_email}
    columns:            # decisions made without a table (colgov 0.1-0.2 files)
      amount: {label: public, decided_by: alice, decided_at: ...}
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from os import PathLike
from typing import Any

import yaml

from colgov.rules import PUBLIC, Suggestion

__all__ = ["Catalog", "CatalogError", "Decision"]

_DECISION_KEYS = {"label", "decided_by", "decided_at", "note", "rule_ids", "domain"}
_CATALOG_KEYS = {"version", "columns", "tables"}
CATALOG_VERSION = 2


class CatalogError(ValueError):
    """A catalog file or decision is malformed."""


@dataclass(frozen=True)
class Decision:
    """A person's classification of one column.

    ``label`` is a rule-pack label, or :data:`colgov.PUBLIC` for a column the
    reviewer found not sensitive. ``rule_ids`` lists the rules behind the
    suggestion the reviewer accepted, if any. ``table`` is ``None`` for a
    decision made without a table.

    ``domain`` names the column's token domain: columns tokenized under the
    same domain (and key) can be joined. It defaults to the column name, so
    same-named columns join across tables; set it to join differently named
    columns (``customers.email`` with ``orders.buyer_email``), or to keep
    same-named columns apart.
    """

    column: str
    label: str
    decided_by: str
    decided_at: datetime
    note: str = ""
    rule_ids: tuple[str, ...] = ()
    table: str | None = None
    domain: str | None = None

    @property
    def is_public(self) -> bool:
        return self.label == PUBLIC

    @property
    def token_domain(self) -> str:
        """The domain used to tokenize this column."""
        return self.domain or self.column

    @property
    def key(self) -> tuple[str | None, str]:
        return (self.table, self.column)


class Catalog:
    """The reviewed classification of one or more tables' columns."""

    def __init__(self, decisions: Iterable[Decision] = ()) -> None:
        self._decisions: dict[tuple[str | None, str], Decision] = {}
        for d in decisions:
            self._add(d)

    # --- deciding -----------------------------------------------------------

    def decide(
        self,
        column: str,
        label: str,
        *,
        by: str,
        table: str | None = None,
        domain: str | None = None,
        note: str = "",
        at: datetime | None = None,
        rule_ids: Iterable[str] = (),
    ) -> Decision:
        """Record that ``column`` (of ``table``) holds ``label``.

        Replaces any earlier decision for the same table and column. Use
        ``label=colgov.PUBLIC`` to mark a column as reviewed and not
        sensitive.
        """
        decision = Decision(
            column=column,
            label=label,
            decided_by=by,
            decided_at=at or datetime.now(timezone.utc),
            note=note,
            rule_ids=tuple(rule_ids),
            table=table,
            domain=domain,
        )
        self._add(decision, replace=True)
        return decision

    def accept(
        self,
        suggestion: Suggestion,
        *,
        by: str,
        table: str | None = None,
        domain: str | None = None,
        note: str = "",
        at: datetime | None = None,
    ) -> Decision:
        """Confirm a machine suggestion as the column's decision."""
        return self.decide(
            suggestion.column,
            suggestion.label,
            by=by,
            table=table,
            domain=domain,
            note=note,
            at=at,
            rule_ids=suggestion.rule_ids,
        )

    def revoke(self, column: str, *, table: str | None = None) -> None:
        """Remove a column's decision. It goes back to pending (and denied)."""
        self._decisions.pop((table, column), None)

    # --- querying -----------------------------------------------------------

    def get(self, column: str, *, table: str | None = None) -> Decision | None:
        """The decision for exactly this table and column, if any."""
        return self._decisions.get((table, column))

    def __contains__(self, key: object) -> bool:
        """``"col" in catalog`` checks a table-less decision;
        ``("table", "col") in catalog`` checks a table's."""
        if isinstance(key, str):
            key = (None, key)
        return key in self._decisions

    def __iter__(self) -> Iterator[Decision]:
        return iter(self._decisions.values())

    def __len__(self) -> int:
        return len(self._decisions)

    @property
    def tables(self) -> list[str]:
        """Names of the tables with at least one decision."""
        return sorted({t for t, _ in self._decisions if t is not None})

    def pending(self, columns: Iterable[str], *, table: str | None = None) -> list[str]:
        """Columns from ``columns`` that nobody has decided on yet, in order.

        Pass a table's column names, or the keys of
        :meth:`colgov.RulePack.classify`'s result.
        """
        return [c for c in columns if (table, c) not in self._decisions]

    # --- persistence --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"version": CATALOG_VERSION}
        untabled = {c: _entry(d) for (t, c), d in sorted(self._items(None))}
        tables = {
            table: {"columns": {c: _entry(d) for (_, c), d in sorted(self._items(table))}} for table in self.tables
        }
        if tables:
            out["tables"] = tables
        if untabled or not tables:
            out["columns"] = untabled
        return out

    def _items(self, table: str | None) -> list[tuple[tuple[str, str], Decision]]:
        return [((t or "", c), d) for (t, c), d in self._decisions.items() if t == table]

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False, allow_unicode=True)

    def save(self, path: str | PathLike[str]) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_yaml())

    @classmethod
    def from_dict(cls, data: Any) -> Catalog:
        if not isinstance(data, dict) or set(data) - _CATALOG_KEYS:
            raise CatalogError("catalog must be a mapping with 'columns' and/or 'tables' keys")
        version = data.get("version", 1)
        if version not in (1, CATALOG_VERSION):
            raise CatalogError(f"unsupported catalog version {version!r}")
        decisions = _parse_columns(data.get("columns"), None)
        tables = data.get("tables")
        if tables is None:
            tables = {}
        if not isinstance(tables, Mapping):
            raise CatalogError("'tables' must be a mapping of table name to its columns")
        for table, body in tables.items():
            if not isinstance(table, str) or not table:
                raise CatalogError("table names must be non-empty strings")
            if not isinstance(body, Mapping) or set(body) - {"columns"}:
                raise CatalogError(f"table {table!r}: must be a mapping with a 'columns' key")
            decisions += _parse_columns(body.get("columns"), table)
        return cls(decisions)

    @classmethod
    def from_yaml(cls, text: str) -> Catalog:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise CatalogError(f"catalog is not valid YAML: {exc}") from exc
        return cls.from_dict(data if data is not None else {})

    @classmethod
    def load(cls, path: str | PathLike[str]) -> Catalog:
        with open(path, encoding="utf-8") as f:
            return cls.from_yaml(f.read())

    # --- internals ----------------------------------------------------------

    def _add(self, d: Decision, *, replace: bool = False) -> None:
        if not isinstance(d.column, str) or not d.column:
            raise CatalogError("column must be a non-empty string")
        if d.table is not None and (not isinstance(d.table, str) or not d.table):
            raise CatalogError("table must be a non-empty string or None")
        where = f"column {d.column!r}" if d.table is None else f"column {d.table}.{d.column}"
        if d.domain is not None and (not isinstance(d.domain, str) or not d.domain):
            raise CatalogError(f"{where}: domain must be a non-empty string")
        if not isinstance(d.label, str) or not d.label:
            raise CatalogError(f"{where}: label must be a non-empty string")
        if not isinstance(d.decided_by, str) or not d.decided_by.strip():
            raise CatalogError(f"{where}: a decision needs a named reviewer ('by')")
        if d.decided_at.tzinfo is None:
            raise CatalogError(f"{where}: 'decided_at' must be timezone-aware")
        if not replace and d.key in self._decisions:
            raise CatalogError(f"{where}: decided more than once")
        self._decisions[d.key] = d


def _entry(d: Decision) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "label": d.label,
        "decided_by": d.decided_by,
        "decided_at": d.decided_at.isoformat(),
    }
    if d.domain:
        entry["domain"] = d.domain
    if d.note:
        entry["note"] = d.note
    if d.rule_ids:
        entry["rule_ids"] = list(d.rule_ids)
    return entry


def _parse_columns(columns: Any, table: str | None) -> list[Decision]:
    if columns is None:
        return []
    if not isinstance(columns, Mapping):
        raise CatalogError("'columns' must be a mapping of column name to decision")
    decisions = []
    for column, entry in columns.items():
        where = f"column {column!r}" if table is None else f"column {table}.{column}"
        if not isinstance(entry, dict):
            raise CatalogError(f"{where}: decision must be a mapping")
        unknown = set(entry) - _DECISION_KEYS
        if unknown:
            raise CatalogError(f"{where}: unknown keys {sorted(map(str, unknown))}")
        decided_at = entry.get("decided_at")
        if isinstance(decided_at, str):
            try:
                decided_at = datetime.fromisoformat(decided_at)
            except ValueError as exc:
                raise CatalogError(f"{where}: 'decided_at' is not an ISO 8601 time") from exc
        if not isinstance(decided_at, datetime):
            raise CatalogError(f"{where}: 'decided_at' is required")
        rule_ids = entry.get("rule_ids") or []
        if not isinstance(rule_ids, list) or not all(isinstance(r, str) for r in rule_ids):
            raise CatalogError(f"{where}: 'rule_ids' must be a list of strings")
        decisions.append(
            Decision(
                column=column,
                label=entry.get("label", ""),  # validated by Catalog._add
                decided_by=entry.get("decided_by", ""),
                decided_at=decided_at,
                note=str(entry.get("note", "")),
                rule_ids=tuple(rule_ids),
                table=table,
                domain=entry.get("domain"),
            )
        )
    return decisions
