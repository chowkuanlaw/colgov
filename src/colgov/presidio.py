"""Optional Presidio adapter that turns whole-value detections into suggestions.

No Presidio dependency is imported until :meth:`PresidioBridge.create` is
called. Suggestions still need a human decision in :class:`colgov.Catalog`.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Protocol

from colgov.rules import DEFAULT_MIN_MATCH_RATIO, DEFAULT_SAMPLE_SIZE, Suggestion

__all__ = ["PresidioBridge", "PresidioError"]

DEFAULT_ENTITY_LABELS: Mapping[str, str] = {
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone_number",
    "PERSON": "person_name",
    "CREDIT_CARD": "payment_card",
    "IP_ADDRESS": "ip_address",
}


class PresidioError(ValueError):
    """Presidio is unavailable or its bridge configuration is invalid."""


class _Result(Protocol):
    entity_type: str
    start: int
    end: int
    score: float


class _Analyzer(Protocol):
    def analyze(self, *, text: str, language: str, entities: list[str]) -> Sequence[_Result]: ...


class PresidioBridge:
    """Suggest colgov labels from a configured Presidio analyzer.

    Only detections spanning the full stripped value count. This detects
    column value shapes; it does not inspect PII embedded in prose. The
    analyzer may be a real ``presidio_analyzer.AnalyzerEngine`` or another
    object implementing its ``analyze`` method.
    """

    def __init__(
        self,
        analyzer: _Analyzer,
        *,
        language: str = "en",
        entity_labels: Mapping[str, str] | None = None,
        min_match_ratio: float = DEFAULT_MIN_MATCH_RATIO,
    ) -> None:
        labels = dict(DEFAULT_ENTITY_LABELS if entity_labels is None else entity_labels)
        if not language:
            raise PresidioError("language must be non-empty")
        if not labels or any(
            not isinstance(entity, str) or not entity or not isinstance(label, str) or not label
            for entity, label in labels.items()
        ):
            raise PresidioError("entity_labels must map entity names to non-empty labels")
        if not 0 < min_match_ratio <= 1:
            raise PresidioError("min_match_ratio must be between 0 and 1")
        self.analyzer = analyzer
        self.language = language
        self.entity_labels = labels
        self.min_match_ratio = min_match_ratio

    @classmethod
    def create(cls, **kwargs: Any) -> PresidioBridge:
        """Use Presidio's default analyzer; install ``colgov[presidio]`` first.

        Presidio's default NLP engine also needs its language model installed.
        Pass an analyzer to the constructor for custom recognizers or models.
        """
        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError:
            raise PresidioError('Presidio is not installed: pip install "colgov[presidio]"') from None
        try:
            analyzer = AnalyzerEngine()
        except Exception as exc:
            raise PresidioError(f"Presidio analyzer could not start: {exc}") from exc
        return cls(analyzer, **kwargs)

    def classify_column(
        self, column: str, values: Iterable[Any], *, sample_size: int = DEFAULT_SAMPLE_SIZE
    ) -> list[Suggestion]:
        """Return suggestions from the first ``sample_size`` non-null values."""
        if sample_size < 1:
            raise PresidioError("sample_size must be positive")
        sample = [str(value).strip() for value in itertools.islice((v for v in values if v is not None), sample_size)]
        if not sample:
            return []
        hits = dict.fromkeys(self.entity_labels, 0)
        scores = dict.fromkeys(self.entity_labels, 0.0)
        for value in sample:
            best: dict[str, float] = {}
            results = self.analyzer.analyze(text=value, language=self.language, entities=list(self.entity_labels))
            for result in results:
                entity = result.entity_type
                if entity not in self.entity_labels or result.start != 0 or result.end != len(value):
                    continue
                score = float(result.score)
                if not 0 <= score <= 1:
                    continue
                best[entity] = max(best.get(entity, 0.0), score)
            for entity, score in best.items():
                hits[entity] += 1
                scores[entity] += score
        suggestions = []
        for entity, label in self.entity_labels.items():
            count = hits[entity]
            ratio = count / len(sample)
            if ratio < self.min_match_ratio:
                continue
            suggestions.append(
                Suggestion(
                    column=column,
                    label=label,
                    confidence=(scores[entity] / count) * ratio,
                    rule_ids=(f"presidio:{entity}",),
                    evidence=(f"presidio:{entity}: {count}/{len(sample)} sampled values match the full value",),
                )
            )
        return sorted(suggestions, key=lambda suggestion: (-suggestion.confidence, suggestion.label))

    def classify(
        self, table: Mapping[str, Iterable[Any]], *, sample_size: int = DEFAULT_SAMPLE_SIZE
    ) -> dict[str, list[Suggestion]]:
        """Classify a table in the same shape as :meth:`RulePack.classify`."""
        return {
            column: self.classify_column(column, values, sample_size=sample_size) for column, values in table.items()
        }
