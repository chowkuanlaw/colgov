"""Fail-closed access policy: who sees which labelled columns, and how.

A policy maps each role to the labels it may see and the treatment each one
gets::

    roles:
      analyst:
        email: tokenize
        postal_code: clear
      support:
        email: clear
      fraud:
        email: {view: tokenize, detokenize: true}

Treatments are ``clear`` (plaintext), ``tokenize`` (deterministic token) and
``deny`` (column removed). Resolution fails closed at every step:

1. an unknown role sees nothing;
2. a column with no reviewed decision is denied, whatever its suggestions;
3. a label the role doesn't list is denied;
4. columns reviewed as :data:`colgov.PUBLIC` are ``clear`` unless the role
   says otherwise.

Detokenizing is a separate right that must be granted explicitly with the
long form ``{view: ..., detokenize: true}``; seeing a column in ``clear``
does not imply it. It follows the same fail-closed steps (known role,
reviewed column, granted label), and every attempt is written to an audit
log before any plaintext is returned.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from os import PathLike
from typing import Any

import yaml

from colgov.audit import AuditLog, record_event
from colgov.review import Catalog, Decision
from colgov.risk import DEFAULT_MIN_DISTINCT, LowCardinalityError
from colgov.rules import PUBLIC
from colgov.tokenization import InvalidToken, Tokenizer

__all__ = ["AccessDenied", "Grant", "Policy", "PolicyError", "Resolution", "Treatment"]


class Treatment(str, Enum):
    CLEAR = "clear"
    TOKENIZE = "tokenize"
    DENY = "deny"


class PolicyError(ValueError):
    """A policy file is malformed, or a policy cannot be applied safely."""


class AccessDenied(PolicyError):
    """The policy does not allow this role to do what was asked."""


@dataclass(frozen=True)
class Grant:
    """What a role may do with one label."""

    view: Treatment = Treatment.DENY
    detokenize: bool = False


_GRANT_KEYS = {"view", "detokenize"}


@dataclass(frozen=True)
class Resolution:
    """How one column is shown to one role, and why.

    ``domain`` is the token domain to use when ``treatment`` is tokenize.
    """

    column: str
    treatment: Treatment
    reason: str
    label: str | None = None
    table: str | None = None
    domain: str | None = None


class Policy:
    def __init__(self, roles: Mapping[str, Mapping[str, Grant | Treatment | str | Mapping[str, Any]]]) -> None:
        self._roles: dict[str, dict[str, Grant]] = {}
        for role, grants in roles.items():
            if not isinstance(role, str) or not role:
                raise PolicyError("role names must be non-empty strings")
            if not isinstance(grants, Mapping):
                raise PolicyError(f"role {role!r}: must map labels to treatments")
            parsed: dict[str, Grant] = {}
            for label, spec in grants.items():
                if not isinstance(label, str) or not label:
                    raise PolicyError(f"role {role!r}: labels must be non-empty strings")
                parsed[label] = _parse_grant(spec, f"role {role!r}, label {label!r}")
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

    def resolve(self, role: str, column: str, catalog: Catalog, *, table: str | None = None) -> Resolution:
        """Decide how ``column`` (of ``table``) is shown to ``role``.

        Anything unclear is denied.
        """
        found = self._lookup(role, column, catalog, table)
        if isinstance(found, Resolution):
            return found
        grant, decision = found
        label = decision.label
        if label == PUBLIC and label not in self._roles[role]:
            reason = "column was reviewed as public"
        else:
            reason = f"role {role!r} grants {grant.view.value} on {label!r}"
        return Resolution(column, grant.view, reason, label, table, decision.token_domain)

    def plan(
        self, role: str, columns: Iterable[str], catalog: Catalog, *, table: str | None = None
    ) -> list[Resolution]:
        """Resolve every column in ``columns`` for ``role``."""
        return [self.resolve(role, c, catalog, table=table) for c in columns]

    def may_detokenize(self, role: str, column: str, catalog: Catalog, *, table: str | None = None) -> tuple[bool, str]:
        """Whether ``role`` may detokenize ``column``, and why (or why not)."""
        found = self._lookup(role, column, catalog, table)
        if isinstance(found, Resolution):
            return False, found.reason
        grant, decision = found
        label = decision.label
        if not grant.detokenize:
            return False, f"role {role!r} has no detokenize grant for {label!r}"
        return True, f"role {role!r} may detokenize {label!r}"

    def _lookup(
        self, role: str, column: str, catalog: Catalog, table: str | None
    ) -> tuple[Grant, Decision] | Resolution:
        """The role's grant and the column's decision, or a denying Resolution."""
        grants = self._roles.get(role)
        if grants is None:
            return Resolution(column, Treatment.DENY, f"unknown role {role!r}", table=table)
        decision = catalog.get(column, table=table)
        if decision is None:
            return Resolution(column, Treatment.DENY, "column has not been reviewed", table=table)
        label = decision.label
        if label in grants:
            return grants[label], decision
        if label == PUBLIC:
            return Grant(view=Treatment.CLEAR), decision
        return Resolution(column, Treatment.DENY, f"role {role!r} has no grant for {label!r}", label, table)

    def apply(
        self,
        data: Mapping[str, Iterable[Any]],
        *,
        role: str,
        catalog: Catalog,
        table: str | None = None,
        tokenizer: Tokenizer | None = None,
        min_distinct: int = DEFAULT_MIN_DISTINCT,
        audit: AuditLog | None = None,
        actor: str | None = None,
    ) -> dict[str, list[Any]]:
        """Return the view of ``data`` (column name -> values) that ``role`` may see.

        Denied columns are left out. Tokenized columns go through
        :meth:`Tokenizer.tokenize_column`, so a low-cardinality column raises
        :class:`colgov.LowCardinalityError` rather than leaking. Nothing is
        returned unless every column resolves cleanly.

        ``table`` selects which table's decisions in ``catalog`` apply.
        With ``audit``, the view is recorded (``actor`` is then required)
        before it is returned; failures are recorded too.
        """
        if audit is not None:
            _require_text(actor, "actor")
        plan = self.plan(role, data, catalog, table=table)
        try:
            view = self._build_view(data, plan, role, tokenizer, min_distinct)
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
        table: str | None = None,
        role: str,
        catalog: Catalog,
        tokenizer: Tokenizer,
        actor: str,
        purpose: str,
        audit: AuditLog,
    ) -> list[str | None]:
        """Turn ``column``'s tokens back into plaintext, if ``role`` may.

        Needs an explicit ``detokenize: true`` grant on the column's label
        (see :meth:`may_detokenize`); seeing the column in clear is not
        enough. ``actor`` (who is asking) and ``purpose`` (why) are required
        and are recorded in ``audit`` with the outcome, before any plaintext
        is returned. Denied requests raise :class:`AccessDenied`; a bad token
        raises :class:`colgov.InvalidToken`. Both are recorded.
        """
        _require_text(actor, "actor")
        _require_text(purpose, "purpose")
        tokens = list(tokens)
        allowed, reason = self.may_detokenize(role, column, catalog, table=table)
        where = column if table is None else f"{table}.{column}"

        def log(outcome: str, reason: str, count: int = 0) -> None:
            record_event(
                audit,
                actor=actor,
                role=role,
                action="detokenize",
                outcome=outcome,
                columns=[where],
                reason=reason,
                purpose=purpose,
                count=count,
            )

        decision = catalog.get(column, table=table)
        if not allowed or decision is None:
            log("denied", reason)
            raise AccessDenied(f"role {role!r} may not detokenize {where!r}: {reason}")
        try:
            plaintext = [tokenizer.detokenize(t, column=decision.token_domain) for t in tokens]
        except InvalidToken as exc:
            log("error", str(exc))
            raise
        log("allowed", reason, len(plaintext))
        return plaintext

    def _build_view(
        self,
        data: Mapping[str, Iterable[Any]],
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
                view[r.column] = list(data[r.column])
            elif r.treatment is Treatment.TOKENIZE:
                if tokenizer is None:  # unreachable: checked above, kept fail-closed
                    raise PolicyError(f"role {role!r} needs a tokenizer to view this table")
                view[r.column] = _tokenize_column(tokenizer, data[r.column], r, min_distinct)
        return view


def _tokenize_column(
    tokenizer: Tokenizer, values: Iterable[str | None], r: Resolution, min_distinct: int
) -> list[str | None]:
    """Tokenize ``r``'s column in its domain, naming the column (not the domain) on refusal."""
    try:
        return tokenizer.tokenize_column(values, column=r.domain or r.column, min_distinct=min_distinct)
    except LowCardinalityError as exc:
        raise LowCardinalityError(r.column, exc.risk, exc.min_distinct) from None


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


def _parse_grant(spec: object, where: str) -> Grant:
    if isinstance(spec, Grant):
        return spec
    if isinstance(spec, Mapping):
        unknown = set(spec) - _GRANT_KEYS
        if unknown:
            raise PolicyError(f"{where}: unknown keys {sorted(map(str, unknown))} (expected view, detokenize)")
        detokenize = spec.get("detokenize", False)
        if not isinstance(detokenize, bool):
            raise PolicyError(f"{where}: 'detokenize' must be true or false")
        return Grant(view=_parse_treatment(spec.get("view", "deny"), where), detokenize=detokenize)
    return Grant(view=_parse_treatment(spec, where))


def _parse_treatment(value: object, where: str) -> Treatment:
    try:
        return Treatment(value)
    except ValueError:
        allowed = ", ".join(t.value for t in Treatment)
        raise PolicyError(f"{where}: unknown treatment {value!r} (expected one of: {allowed})") from None


def _require_text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{name!r} must be a non-empty string")
