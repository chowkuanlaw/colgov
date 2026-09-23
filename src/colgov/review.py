"""Human review of classification suggestions: a machine suggests, a person decides.

A :class:`Catalog` records one decision per column: which label it carries,
who decided, when, and why. Only decided columns can ever become visible
under a :class:`colgov.Policy`; a column with suggestions but no decision
stays pending, and pending columns are denied.

Catalogs round-trip through YAML so decisions can be reviewed in a pull
request like any other change.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from os import PathLike
from typing import Any

import yaml

from colgov.rules import PUBLIC, Suggestion

__all__ = ["Catalog", "CatalogError", "Decision"]

_DECISION_KEYS = {"label", "decided_by", "decided_at", "note", "rule_ids"}


class CatalogError(ValueError):
    """A catalog file or decision is malformed."""


@dataclass(frozen=True)
class Decision:
    """A person's classification of one column.

    ``label`` is a rule-pack label, or :data:`colgov.PUBLIC` for a column the
    reviewer found not sensitive. ``rule_ids`` lists the rules behind the
    suggestion the reviewer accepted, if any.
    """

    column: str
    label: str
    decided_by: str
    decided_at: datetime
    note: str = ""
    rule_ids: tuple[str, ...] = ()

    @property
    def is_public(self) -> bool:
        return self.label == PUBLIC


class Catalog:
    """The reviewed classification of a table's columns."""

    def __init__(self, decisions: Iterable[Decision] = ()) -> None:
        self._decisions: dict[str, Decision] = {}
        for d in decisions:
            self._add(d)

    # --- deciding -----------------------------------------------------------

    def decide(
        self,
        column: str,
        label: str,
        *,
        by: str,
        note: str = "",
        at: datetime | None = None,
        rule_ids: Iterable[str] = (),
    ) -> Decision:
        """Record that ``column`` holds ``label``, replacing any earlier decision.

        Use ``label=colgov.PUBLIC`` to mark a column as reviewed and not
        sensitive.
        """
        decision = Decision(
            column=column,
            label=label,
            decided_by=by,
            decided_at=at or datetime.now(timezone.utc),
            note=note,
            rule_ids=tuple(rule_ids),
        )
        self._add(decision, replace=True)
        return decision

    def accept(
        self, suggestion: Suggestion, *, by: str, note: str = "", at: datetime | None = None
    ) -> Decision:
        """Confirm a machine suggestion as the column's decision."""
        return self.decide(
            suggestion.column,
            suggestion.label,
            by=by,
            note=note,
            at=at,
            rule_ids=suggestion.rule_ids,
        )

    def revoke(self, column: str) -> None:
        """Remove a column's decision. It goes back to pending (and denied)."""
        self._decisions.pop(column, None)

    # --- querying -----------------------------------------------------------

    def get(self, column: str) -> Decision | None:
        return self._decisions.get(column)

    def __contains__(self, column: object) -> bool:
        return column in self._decisions

    def __iter__(self):
        return iter(self._decisions.values())

    def __len__(self) -> int:
        return len(self._decisions)

    def pending(self, columns: Iterable[str]) -> list[str]:
        """Columns from ``columns`` that nobody has decided on yet, in order.

        Pass a table's column names, or the keys of
        :meth:`colgov.RulePack.classify`'s result.
        """
        return [c for c in columns if c not in self._decisions]

    # --- persistence --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        columns: dict[str, Any] = {}
        for column in sorted(self._decisions):
            d = self._decisions[column]
            entry: dict[str, Any] = {
                "label": d.label,
                "decided_by": d.decided_by,
                "decided_at": d.decided_at.isoformat(),
            }
            if d.note:
                entry["note"] = d.note
            if d.rule_ids:
                entry["rule_ids"] = list(d.rule_ids)
            columns[column] = entry
        return {"columns": columns}

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False, allow_unicode=True)

    def save(self, path: str | PathLike[str]) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_yaml())

    @classmethod
    def from_dict(cls, data: Any) -> Catalog:
        if not isinstance(data, dict) or set(data) - {"columns"}:
            raise CatalogError("catalog must be a mapping with a single 'columns' key")
        columns = data.get("columns")
        if columns is None:
            columns = {}
        if not isinstance(columns, Mapping):
            raise CatalogError("'columns' must be a mapping of column name to decision")
        decisions = []
        for column, entry in columns.items():
            where = f"column {column!r}"
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
                    label=entry.get("label"),
                    decided_by=entry.get("decided_by"),
                    decided_at=decided_at,
                    note=str(entry.get("note", "")),
                    rule_ids=tuple(rule_ids),
                )
            )
        return cls(decisions)

    @classmethod
    def from_yaml(cls, text: str) -> Catalog:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise CatalogError(f"catalog is not valid YAML: {exc}") from exc
        return cls.from_dict(data if data is not None else {"columns": {}})

    @classmethod
    def load(cls, path: str | PathLike[str]) -> Catalog:
        with open(path, encoding="utf-8") as f:
            return cls.from_yaml(f.read())

    # --- internals ----------------------------------------------------------

    def _add(self, d: Decision, *, replace: bool = False) -> None:
        if not isinstance(d.column, str) or not d.column:
            raise CatalogError("column must be a non-empty string")
        where = f"column {d.column!r}"
        if not isinstance(d.label, str) or not d.label:
            raise CatalogError(f"{where}: label must be a non-empty string")
        if not isinstance(d.decided_by, str) or not d.decided_by.strip():
            raise CatalogError(f"{where}: a decision needs a named reviewer ('by')")
        if d.decided_at.tzinfo is None:
            raise CatalogError(f"{where}: 'decided_at' must be timezone-aware")
        if not replace and d.column in self._decisions:
            raise CatalogError(f"{where}: decided more than once")
        self._decisions[d.column] = d
