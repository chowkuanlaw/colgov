"""Column classification from portable YAML rule packs.

A rule pack declares labels (``email``, ``national_id``, ...) and rules that
suggest them, by matching a column's name, a sample of its values, or both.
Rules only ever *suggest*: a person turns a suggestion into a decision with
:class:`colgov.Catalog`.

A minimal pack::

    pack: example
    version: 1
    labels:
      email:
        description: Email address
    rules:
      - id: email-by-name
        label: email
        column_name: 'e_?mail'
        confidence: 0.7
      - id: email-by-value
        label: email
        value_pattern: '[^@\\s]+@[^@\\s]+\\.[A-Za-z]{2,}'
        min_match_ratio: 0.9
        confidence: 0.95

``column_name`` is a regex searched, case-insensitively, anywhere in the
column name. ``value_pattern`` is a regex that must match a whole value;
the rule fires when at least ``min_match_ratio`` of the sampled non-null
values match. A rule with both fires only when both match.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from importlib import resources
from os import PathLike
from typing import Any

import yaml

__all__ = [
    "PUBLIC",
    "Label",
    "Rule",
    "RulePack",
    "RulePackError",
    "Suggestion",
]

PUBLIC = "public"
"""Reserved label for a column a person reviewed and found not sensitive."""

DEFAULT_SAMPLE_SIZE = 1000
DEFAULT_MIN_MATCH_RATIO = 0.8

_PACK_KEYS = {"pack", "version", "description", "labels", "rules"}
_LABEL_KEYS = {"description"}
_RULE_KEYS = {"id", "label", "column_name", "value_pattern", "min_match_ratio", "confidence"}


class RulePackError(ValueError):
    """A rule pack is malformed."""


@dataclass(frozen=True)
class Label:
    name: str
    description: str = ""


@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    confidence: float
    column_name: re.Pattern[str] | None = None
    value_pattern: re.Pattern[str] | None = None
    min_match_ratio: float = DEFAULT_MIN_MATCH_RATIO


@dataclass(frozen=True)
class Suggestion:
    """A machine suggestion that ``column`` holds ``label``. Not a decision."""

    column: str
    label: str
    confidence: float
    rule_ids: tuple[str, ...]
    evidence: tuple[str, ...] = field(default=())


@dataclass(frozen=True)
class RulePack:
    name: str
    version: int
    labels: Mapping[str, Label]
    rules: tuple[Rule, ...]
    description: str = ""

    # --- loading ------------------------------------------------------------

    @classmethod
    def builtin(cls, name: str = "core") -> RulePack:
        """Load a pack shipped with colgov. ``core`` covers common PII."""
        try:
            text = resources.files("colgov.packs").joinpath(f"{name}.yaml").read_text("utf-8")
        except FileNotFoundError:
            raise RulePackError(f"no built-in rule pack named {name!r}") from None
        return cls.from_yaml(text)

    @classmethod
    def load(cls, path: str | PathLike[str]) -> RulePack:
        """Load a pack from a YAML file."""
        with open(path, encoding="utf-8") as f:
            return cls.from_yaml(f.read())

    @classmethod
    def from_yaml(cls, text: str) -> RulePack:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise RulePackError(f"rule pack is not valid YAML: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Any) -> RulePack:
        if not isinstance(data, dict):
            raise RulePackError("rule pack must be a mapping")
        _reject_unknown(data, _PACK_KEYS, "rule pack")
        name = _require_str(data, "pack", "rule pack")
        version = data.get("version")
        if not isinstance(version, int) or isinstance(version, bool):
            raise RulePackError(f"pack {name!r}: 'version' must be an integer")

        raw_labels = data.get("labels")
        if not isinstance(raw_labels, dict) or not raw_labels:
            raise RulePackError(f"pack {name!r}: 'labels' must be a non-empty mapping")
        labels: dict[str, Label] = {}
        for label_name, spec in raw_labels.items():
            where = f"pack {name!r}, label {label_name!r}"
            if not isinstance(label_name, str) or not label_name:
                raise RulePackError(f"pack {name!r}: label names must be non-empty strings")
            if label_name == PUBLIC:
                raise RulePackError(f"{where}: {PUBLIC!r} is reserved for review decisions")
            spec = spec or {}
            if not isinstance(spec, dict):
                raise RulePackError(f"{where}: must be a mapping")
            _reject_unknown(spec, _LABEL_KEYS, where)
            labels[label_name] = Label(label_name, str(spec.get("description", "")))

        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise RulePackError(f"pack {name!r}: 'rules' must be a non-empty list")
        rules: list[Rule] = []
        seen_ids: set[str] = set()
        for i, spec in enumerate(raw_rules):
            if not isinstance(spec, dict):
                raise RulePackError(f"pack {name!r}, rule #{i + 1}: must be a mapping")
            rule = _parse_rule(spec, name, i, labels)
            if rule.id in seen_ids:
                raise RulePackError(f"pack {name!r}: duplicate rule id {rule.id!r}")
            seen_ids.add(rule.id)
            rules.append(rule)

        return cls(
            name=name,
            version=version,
            labels=labels,
            rules=tuple(rules),
            description=str(data.get("description", "")),
        )

    # --- classification -----------------------------------------------------

    def classify_column(
        self,
        column: str,
        values: Iterable[Any] = (),
        *,
        sample_size: int = DEFAULT_SAMPLE_SIZE,
    ) -> list[Suggestion]:
        """Suggest labels for one column, most confident first.

        Only the first ``sample_size`` non-null values are examined. Values
        are compared as stripped strings.
        """
        sample = [
            str(v).strip()
            for v in itertools.islice((v for v in values if v is not None), sample_size)
        ]
        best: dict[str, Suggestion] = {}
        for rule in self.rules:
            evidence = _match(rule, column, sample)
            if evidence is None:
                continue
            prev = best.get(rule.label)
            if prev is None:
                best[rule.label] = Suggestion(
                    column, rule.label, rule.confidence, (rule.id,), evidence
                )
            else:
                best[rule.label] = Suggestion(
                    column,
                    rule.label,
                    max(prev.confidence, rule.confidence),
                    prev.rule_ids + (rule.id,),
                    prev.evidence + evidence,
                )
        return sorted(best.values(), key=lambda s: (-s.confidence, s.label))

    def classify(
        self,
        table: Mapping[str, Iterable[Any]],
        *,
        sample_size: int = DEFAULT_SAMPLE_SIZE,
    ) -> dict[str, list[Suggestion]]:
        """Suggest labels for every column of ``table`` (column name -> values)."""
        return {
            column: self.classify_column(column, values, sample_size=sample_size)
            for column, values in table.items()
        }


def _parse_rule(spec: dict[str, Any], pack: str, index: int, labels: Mapping[str, Label]) -> Rule:
    where = f"pack {pack!r}, rule #{index + 1}"
    _reject_unknown(spec, _RULE_KEYS, where)
    rule_id = _require_str(spec, "id", where)
    where = f"pack {pack!r}, rule {rule_id!r}"

    label = _require_str(spec, "label", where)
    if label not in labels:
        raise RulePackError(f"{where}: label {label!r} is not declared under 'labels'")

    column_name = _compile(spec, "column_name", where, re.IGNORECASE)
    value_pattern = _compile(spec, "value_pattern", where, 0)
    if column_name is None and value_pattern is None:
        raise RulePackError(f"{where}: needs 'column_name', 'value_pattern', or both")

    confidence = _ratio(spec, "confidence", where, required=True)
    min_match_ratio = _ratio(spec, "min_match_ratio", where, required=False)
    if min_match_ratio is not None and value_pattern is None:
        raise RulePackError(f"{where}: 'min_match_ratio' needs 'value_pattern'")

    return Rule(
        id=rule_id,
        label=label,
        confidence=confidence,
        column_name=column_name,
        value_pattern=value_pattern,
        min_match_ratio=(
            DEFAULT_MIN_MATCH_RATIO if min_match_ratio is None else min_match_ratio
        ),
    )


def _match(rule: Rule, column: str, sample: list[str]) -> tuple[str, ...] | None:
    evidence: list[str] = []
    if rule.column_name is not None:
        if not rule.column_name.search(column):
            return None
        evidence.append(f"{rule.id}: column name matches /{rule.column_name.pattern}/")
    if rule.value_pattern is not None:
        if not sample:
            return None
        hits = sum(1 for v in sample if rule.value_pattern.fullmatch(v))
        ratio = hits / len(sample)
        if ratio < rule.min_match_ratio:
            return None
        evidence.append(f"{rule.id}: {hits}/{len(sample)} sampled values match")
    return tuple(evidence)


def _reject_unknown(spec: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = set(spec) - allowed
    if unknown:
        raise RulePackError(f"{where}: unknown keys {sorted(map(str, unknown))}")


def _require_str(spec: dict[str, Any], key: str, where: str) -> str:
    value = spec.get(key)
    if not isinstance(value, str) or not value:
        raise RulePackError(f"{where}: {key!r} must be a non-empty string")
    return value


def _compile(spec: dict[str, Any], key: str, where: str, flags: int) -> re.Pattern[str] | None:
    if key not in spec:
        return None
    pattern = spec[key]
    if not isinstance(pattern, str) or not pattern:
        raise RulePackError(f"{where}: {key!r} must be a non-empty regex string")
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise RulePackError(f"{where}: {key!r} is not a valid regex: {exc}") from exc


def _ratio(spec: dict[str, Any], key: str, where: str, *, required: bool) -> float | None:
    if key not in spec:
        if required:
            raise RulePackError(f"{where}: {key!r} is required")
        return None
    value = spec[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 1:
        raise RulePackError(f"{where}: {key!r} must be a number in (0, 1]")
    return float(value)
