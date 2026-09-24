"""Fail-closed access policy: who sees which labelled columns, and how.

A policy maps each role to the labels it may see and the treatment each one
gets::

    roles:
      analyst:
        email: tokenize
        postal_code: clear
      support:
        email: clear

Treatments are ``clear`` (plaintext), ``tokenize`` (deterministic token) and
``deny`` (column removed). Resolution fails closed at every step:

1. an unknown role sees nothing;
2. a column with no reviewed decision is denied, whatever its suggestions;
3. a label the role doesn't list is denied;
4. columns reviewed as :data:`colgov.PUBLIC` are ``clear`` unless the role
   says otherwise.

Detokenization follows the same rules: a role may turn tokens back into
plaintext only for columns it could already see in ``clear``. Every attempt
is written to an audit log before any plaintext is returned.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from os import PathLike
from typing import Any

import yaml

from colgov.audit import AuditLog, record_event
from colgov.review import Catalog
from colgov.risk import DEFAULT_MIN_DISTINCT
from colgov.rules import PUBLIC
from colgov.tokenization import InvalidToken, Tokenizer

__all__ = ["AccessDenied", "Policy", "PolicyError", "Resolution", "Treatment"]


class Treatment(str, Enum):
    CLEAR = "clear"
    TOKENIZE = "tokenize"
    DENY = "deny"


class PolicyError(ValueError):
    """A policy file is malformed, or a policy cannot be applied safely."""


class AccessDenied(PolicyError):
    """The policy does not allow this role to do what was asked."""


@dataclass(frozen=True)
class Resolution:
    """How one column is shown to one role, and why."""

    column: str
    treatment: Treatment
    reason: str
    label: str | None = None


class Policy:
    def __init__(self, roles: Mapping[str, Mapping[str, Treatment | str]]) -> None:
        self._roles: dict[str, dict[str, Treatment]] = {}
        for role, grants in roles.items():
            if not isinstance(role, str) or not role:
                raise PolicyError("role names must be non-empty strings")
            if not isinstance(grants, Mapping):
                raise PolicyError(f"role {role!r}: must map labels to treatments")
            parsed: dict[str, Treatment] = {}
            for label, treatment in grants.items():
                if not isinstance(label, str) or not label:
                    raise PolicyError(f"role {role!r}: labels must be non-empty strings")
                try:
                    parsed[label] = Treatment(treatment)
                except ValueError:
                    allowed = ", ".join(t.value for t in Treatment)
                    raise PolicyError(
                        f"role {role!r}, label {label!r}: unknown treatment "
                        f"{treatment!r} (expected one of: {allowed})"
                    ) from None
            self._roles[role] = parsed

    @property
    def roles(self) -> list[str]:
        return list(self._roles)

    # --- loading ------------------------------------------------------------

    @classmethod
    def from_dict(cls, data: Any) -> Policy:
        if not isinstance(data, dict) or set(data) != {"roles"}:
            raise PolicyError("policy must be a mapping with a single 'roles' key")
        roles = data["roles"]
        if not isinstance(roles, dict) or not roles:
            raise PolicyError("'roles' must be a non-empty mapping")
        return cls({role: {} if grants is None else grants for role, grants in roles.items()})

    @classmethod
    def from_yaml(cls, text: str) -> Policy:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyError(f"policy is not valid YAML: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def load(cls, path: str | PathLike[str]) -> Policy:
        with open(path, encoding="utf-8") as f:
            return cls.from_yaml(f.read())

    # --- resolution ---------------------------------------------------------

    def resolve(self, role: str, column: str, catalog: Catalog) -> Resolution:
        """Decide how ``column`` is shown to ``role``. Anything unclear is denied."""
        grants = self._roles.get(role)
        if grants is None:
            return Resolution(column, Treatment.DENY, f"unknown role {role!r}")
        decision = catalog.get(column)
        if decision is None:
            return Resolution(column, Treatment.DENY, "column has not been reviewed")
        label = decision.label
        if label in grants:
            return Resolution(
                column, grants[label], f"role {role!r} grants {grants[label].value} on {label!r}", label
            )
        if label == PUBLIC:
            return Resolution(column, Treatment.CLEAR, "column was reviewed as public", label)
        return Resolution(column, Treatment.DENY, f"role {role!r} has no grant for {label!r}", label)

    def plan(self, role: str, columns: Iterable[str], catalog: Catalog) -> list[Resolution]:
        """Resolve every column in ``columns`` for ``role``."""
        return [self.resolve(role, c, catalog) for c in columns]

    def apply(
        self,
        table: Mapping[str, Iterable[Any]],
        *,
        role: str,
        catalog: Catalog,
        tokenizer: Tokenizer | None = None,
        min_distinct: int = DEFAULT_MIN_DISTINCT,
        audit: AuditLog | None = None,
        actor: str | None = None,
    ) -> dict[str, list[Any]]:
        """Return the view of ``table`` (column name -> values) that ``role`` may see.

        Denied columns are left out. Tokenized columns go through
        :meth:`Tokenizer.tokenize_column`, so a low-cardinality column raises
        :class:`colgov.LowCardinalityError` rather than leaking. Nothing is
        returned unless every column resolves cleanly.

        With ``audit``, the view is recorded (``actor`` is then required)
        before it is returned; failures are recorded too.
        """
        if audit is not None:
            _require_text(actor, "actor")
        plan = self.plan(role, table, catalog)
        try:
            view = self._build_view(table, plan, role, tokenizer, min_distinct)
        except Exception as exc:
            if audit is not None:
                record_view(audit, actor, role, plan, "error", str(exc), 0)  # type: ignore[arg-type]
            raise
        if audit is not None:
            n_rows = len(next(iter(view.values()))) if view else 0
            record_view(audit, actor, role, plan, "allowed", summarize(plan), n_rows)  # type: ignore[arg-type]
        return view

    def detokenize(
        self,
        tokens: Iterable[str | None],
        *,
        column: str,
        role: str,
        catalog: Catalog,
        tokenizer: Tokenizer,
        actor: str,
        purpose: str,
        audit: AuditLog,
    ) -> list[str | None]:
        """Turn ``column``'s tokens back into plaintext, if ``role`` may.

        Allowed only when the column resolves to ``clear`` for ``role``.
        ``actor`` (who is asking) and ``purpose`` (why) are required and are
        recorded in ``audit`` with the outcome, before any plaintext is
        returned. Denied requests raise :class:`AccessDenied`; a bad token
        raises :class:`colgov.InvalidToken`. Both are recorded.
        """
        _require_text(actor, "actor")
        _require_text(purpose, "purpose")
        tokens = list(tokens)
        resolution = self.resolve(role, column, catalog)

        def log(outcome: str, reason: str, count: int = 0) -> None:
            record_event(
                audit,
                actor=actor,
                role=role,
                action="detokenize",
                outcome=outcome,
                columns=[column],
                reason=reason,
                purpose=purpose,
                count=count,
            )

        if resolution.treatment is not Treatment.CLEAR:
            reason = f"detokenize needs clear access: {resolution.reason}"
            log("denied", reason)
            raise AccessDenied(f"role {role!r} may not detokenize {column!r}: {resolution.reason}")
        try:
            plaintext = [tokenizer.detokenize(t, column=column) for t in tokens]
        except InvalidToken as exc:
            log("error", str(exc))
            raise
        log("allowed", resolution.reason, len(plaintext))
        return plaintext

    def _build_view(
        self,
        table: Mapping[str, Iterable[Any]],
        plan: list[Resolution],
        role: str,
        tokenizer: Tokenizer | None,
        min_distinct: int,
    ) -> dict[str, list[Any]]:
        if tokenizer is None and any(r.treatment is Treatment.TOKENIZE for r in plan):
            raise PolicyError(f"role {role!r} needs a tokenizer to view this table")
        view: dict[str, list[Any]] = {}
        for r in plan:
            if r.treatment is Treatment.CLEAR:
                view[r.column] = list(table[r.column])
            elif r.treatment is Treatment.TOKENIZE:
                if tokenizer is None:  # unreachable: checked above, kept fail-closed
                    raise PolicyError(f"role {role!r} needs a tokenizer to view this table")
                view[r.column] = tokenizer.tokenize_column(
                    table[r.column], column=r.column, min_distinct=min_distinct
                )
        return view


def summarize(plan: Iterable[Resolution]) -> str:
    """One-line summary of a plan, e.g. ``clear: a, b; tokenize: c; deny: d``."""
    groups: dict[Treatment, list[str]] = {t: [] for t in Treatment}
    for r in plan:
        groups[r.treatment].append(r.column)
    return "; ".join(f"{t.value}: {', '.join(cols)}" for t, cols in groups.items() if cols)


def record_view(
    audit: AuditLog, actor: str, role: str, plan: list[Resolution], outcome: str, reason: str, count: int
) -> None:
    record_event(
        audit,
        actor=actor,
        role=role,
        action="view",
        outcome=outcome,
        columns=[r.column for r in plan if r.treatment is not Treatment.DENY],
        reason=reason,
        count=count,
    )


def _require_text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{name!r} must be a non-empty string")
