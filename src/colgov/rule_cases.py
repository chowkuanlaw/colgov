"""Run example cases against a rule pack without exposing sample values."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from os import PathLike
from typing import Any

import yaml

from colgov.rules import RulePack

__all__ = ["RuleCase", "RuleCaseError", "RuleCaseResult", "load_rule_cases", "run_rule_cases"]


class RuleCaseError(ValueError):
    """A rule pack example file is malformed."""


@dataclass(frozen=True)
class RuleCase:
    name: str
    column: str
    values: tuple[str | None, ...]
    expected: tuple[str, ...]


@dataclass(frozen=True)
class RuleCaseResult:
    name: str
    column: str
    expected: tuple[str, ...]
    actual: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.expected == self.actual

    @property
    def overlaps(self) -> bool:
        return len(self.actual) > 1


def load_rule_cases(path: str | PathLike[str]) -> list[RuleCase]:
    """Load ``cases: [{name, column, values, expected}]`` from YAML."""
    with open(path, encoding="utf-8") as file:
        try:
            data: Any = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            raise RuleCaseError("invalid cases YAML") from exc
    if not isinstance(data, dict) or set(data) != {"cases"} or not isinstance(data["cases"], list):
        raise RuleCaseError("case file must contain a 'cases' list")
    if not data["cases"]:
        raise RuleCaseError("case file must contain at least one case")
    cases = []
    names: set[str] = set()
    for index, entry in enumerate(data["cases"], start=1):
        if not isinstance(entry, dict) or set(entry) - {"name", "column", "values", "expected"}:
            raise RuleCaseError(f"case {index}: unexpected fields")
        name = entry.get("name", f"case-{index}")
        column = entry.get("column")
        values = entry.get("values")
        expected = entry.get("expected")
        if not isinstance(name, str) or not name or name in names:
            raise RuleCaseError(f"case {index}: name must be unique and non-empty")
        names.add(name)
        if not isinstance(column, str) or not column:
            raise RuleCaseError(f"case {index}: column must be a non-empty string")
        if not isinstance(values, list) or any(value is not None and not isinstance(value, str) for value in values):
            raise RuleCaseError(f"case {index}: values must be strings or null")
        if not isinstance(expected, list) or any(not isinstance(label, str) or not label for label in expected):
            raise RuleCaseError(f"case {index}: expected must be a list of labels")
        if len(set(expected)) != len(expected):
            raise RuleCaseError(f"case {index}: expected labels must be unique")
        cases.append(RuleCase(name, column, tuple(values), tuple(expected)))
    return cases


def run_rule_cases(pack: RulePack, cases: Sequence[RuleCase]) -> list[RuleCaseResult]:
    """Return actual and expected labels for each case, sorted by label."""
    results = []
    for case in cases:
        unknown = set(case.expected) - set(pack.labels)
        if unknown:
            raise RuleCaseError(f"case {case.name!r}: unknown labels: {', '.join(sorted(unknown))}")
        actual = tuple(
            sorted(
                s.label for s in pack.classify_column(case.column, case.values, sample_size=max(1, len(case.values)))
            )
        )
        results.append(RuleCaseResult(case.name, case.column, tuple(sorted(case.expected)), actual))
    return results
