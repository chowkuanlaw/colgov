from dataclasses import dataclass
from types import ModuleType

import pytest

from colgov import Catalog, Policy, PresidioBridge, PresidioError


@dataclass
class Detection:
    entity_type: str
    start: int
    end: int
    score: float


class FakeAnalyzer:
    def analyze(self, *, text, language, entities):
        assert language == "en"
        assert "EMAIL_ADDRESS" in entities
        if " " not in text and text.endswith("@example.com"):
            return [Detection("EMAIL_ADDRESS", 0, len(text), 0.9)]
        if "@example.com" in text:
            start = text.index("person@example.com")
            return [Detection("EMAIL_ADDRESS", start, start + len("person@example.com"), 0.9)]
        return []


def test_bridge_suggests_full_values_without_exposing_evidence():
    bridge = PresidioBridge(FakeAnalyzer(), min_match_ratio=0.5)
    [suggestion] = bridge.classify_column("contact", ["a@example.com", "b@example.com", "plain", None])
    assert (suggestion.column, suggestion.label, suggestion.rule_ids) == (
        "contact",
        "email",
        ("presidio:EMAIL_ADDRESS",),
    )
    assert suggestion.confidence == pytest.approx(0.6)
    assert "2/3" in suggestion.evidence[0]
    assert "a@example.com" not in str(suggestion)

    catalog = Catalog()
    policy = Policy({"analyst": {"email": "tokenize"}})
    assert policy.resolve("analyst", "contact", catalog).treatment.value == "deny"
    catalog.accept(suggestion, by="alice")
    assert policy.resolve("analyst", "contact", catalog).treatment.value == "tokenize"


def test_bridge_ignores_embedded_text_and_requires_consistent_values():
    bridge = PresidioBridge(FakeAnalyzer())
    assert bridge.classify_column("notes", ["call person@example.com"]) == []
    assert bridge.classify_column("contact", ["a@example.com", "plain", "other"]) == []
    assert bridge.classify_column("contact", [None]) == []


def test_bridge_supports_custom_entity_mapping():
    class IdAnalyzer:
        def analyze(self, *, text, language, entities):
            assert entities == ["CUSTOM_ID"]
            return [Detection("CUSTOM_ID", 0, len(text), 0.7)]

    bridge = PresidioBridge(IdAnalyzer(), entity_labels={"CUSTOM_ID": "national_id"})
    assert bridge.classify({"id": ["ABC123"]})["id"][0].label == "national_id"


def test_create_uses_optional_analyzer_when_available(monkeypatch):
    import sys

    module = ModuleType("presidio_analyzer")
    module.AnalyzerEngine = FakeAnalyzer  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "presidio_analyzer", module)
    assert PresidioBridge.create().classify_column("email", ["a@example.com"])[0].label == "email"


def test_create_explains_missing_optional_dependency(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "presidio_analyzer", None)
    with pytest.raises(PresidioError, match="colgov\\[presidio\\]"):
        PresidioBridge.create()


@pytest.mark.parametrize("kwargs", [{"language": ""}, {"entity_labels": {}}, {"min_match_ratio": 0}])
def test_bridge_rejects_invalid_configuration(kwargs):
    with pytest.raises(PresidioError):
        PresidioBridge(FakeAnalyzer(), **kwargs)
