"""Explain access decisions and compare the effective access of two revisions."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from colgov.policy import Policy, Treatment
from colgov.review import Catalog

__all__ = ["AccessChange", "AccessExplanation", "compare_access", "explain_access"]


@dataclass(frozen=True)
class AccessExplanation:
    """The effective view, detokenization right, and reviewed decision."""

    table: str | None
    column: str
    role: str
    view: Treatment
    view_reason: str
    detokenize: bool
    detokenize_reason: str
    label: str | None
    domain: str | None
    decided_by: str | None
    decided_at: str | None


@dataclass(frozen=True)
class AccessChange:
    """A changed effective access decision between two revisions.

    ``kind`` is ``expansion``, ``restriction``, ``mixed`` or ``configuration``.
    A label or token-domain change is reported even if the treatment stays
    the same; token-domain changes can affect joins and token compatibility.
    """

    table: str | None
    column: str
    role: str
    before: AccessExplanation
    after: AccessExplanation
    kind: str


def explain_access(
    policy: Policy, catalog: Catalog, *, role: str, column: str, table: str | None = None
) -> AccessExplanation:
    """Explain one role's view and detokenization decision without reading data."""
    resolution = policy.resolve(role, column, catalog, table=table)
    allowed, detokenize_reason = policy.may_detokenize(role, column, catalog, table=table)
    decision = catalog.get(column, table=table)
    return AccessExplanation(
        table=table,
        column=column,
        role=role,
        view=resolution.treatment,
        view_reason=resolution.reason,
        detokenize=allowed,
        detokenize_reason=detokenize_reason,
        label=decision.label if decision else None,
        domain=decision.token_domain if decision else None,
        decided_by=decision.decided_by if decision else None,
        decided_at=decision.decided_at.isoformat() if decision else None,
    )


def compare_access(
    before_policy: Policy,
    before_catalog: Catalog,
    after_policy: Policy,
    after_catalog: Catalog,
    *,
    schemas: Mapping[str | None, Sequence[str]] | None = None,
) -> list[AccessChange]:
    """Compare effective access for every role and reviewed or supplied column.

    When ``schemas`` is supplied, its columns are included even if neither
    catalog has a decision. Catalog decisions are always included so a
    removed decision cannot disappear from the comparison.
    """
    columns: set[tuple[str | None, str]] = {
        (decision.table, decision.column) for catalog in (before_catalog, after_catalog) for decision in catalog
    }
    if schemas is not None:
        columns.update((table, column) for table, names in schemas.items() for column in names)
    roles = sorted(set(before_policy.roles) | set(after_policy.roles))
    changes = []
    for table, column in sorted(columns, key=lambda item: (item[0] or "", item[1])):
        for role in roles:
            before = explain_access(before_policy, before_catalog, role=role, column=column, table=table)
            after = explain_access(after_policy, after_catalog, role=role, column=column, table=table)
            if _effective(before) == _effective(after):
                continue
            old_rights = _rights(before)
            new_rights = _rights(after)
            gained = bool(new_rights - old_rights)
            lost = bool(old_rights - new_rights)
            kind = "mixed" if gained and lost else "expansion" if gained else "restriction" if lost else "configuration"
            changes.append(AccessChange(table, column, role, before, after, kind))
    return changes


def _effective(explanation: AccessExplanation) -> tuple[Treatment, bool, str | None, str | None]:
    return (explanation.view, explanation.detokenize, explanation.label, explanation.domain)


def _rights(explanation: AccessExplanation) -> set[str]:
    rights: set[str] = set()
    if explanation.view is Treatment.TOKENIZE:
        rights.add("token")
    elif explanation.view is Treatment.CLEAR:
        rights.update(("token", "clear"))
    if explanation.detokenize:
        rights.add("detokenize")
    return rights
