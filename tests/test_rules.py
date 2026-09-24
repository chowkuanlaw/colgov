import textwrap

import pytest

from colgov import PUBLIC, RulePack, RulePackError

PACK = textwrap.dedent(
    r"""
    pack: test
    version: 1
    labels:
      email:
        description: Email address
      code: {}
    rules:
      - id: email-name
        label: email
        column_name: 'e_?mail'
        confidence: 0.7
      - id: email-value
        label: email
        value_pattern: '[^@\s]+@[^@\s]+\.[a-z]+'
        min_match_ratio: 0.5
        confidence: 0.95
      - id: code-both
        label: code
        column_name: 'code'
        value_pattern: '[A-Z]{3}'
        confidence: 0.6
    """
)


@pytest.fixture
def pack() -> RulePack:
    return RulePack.from_yaml(PACK)


def test_load(pack):
    assert pack.name == "test"
    assert pack.version == 1
    assert set(pack.labels) == {"email", "code"}
    assert pack.labels["email"].description == "Email address"
    assert [r.id for r in pack.rules] == ["email-name", "email-value", "code-both"]
    assert pack.rules[0].min_match_ratio == 0.8  # default


def test_load_from_file(tmp_path):
    path = tmp_path / "pack.yaml"
    path.write_text(PACK, encoding="utf-8")
    assert RulePack.load(path).name == "test"


def test_name_match_is_case_insensitive_search(pack):
    [s] = pack.classify_column("Customer_EMail")
    assert (s.column, s.label, s.rule_ids) == ("Customer_EMail", "email", ("email-name",))


def test_value_match_by_ratio(pack):
    [s] = pack.classify_column("contact", ["a@b.com", "nope", None, None])
    assert s.rule_ids == ("email-value",)
    assert s.confidence == 0.95
    assert "1/2 sampled values match" in s.evidence[0]


def test_value_match_below_ratio(pack):
    assert pack.classify_column("contact", ["a@b.com", "x", "y"]) == []


def test_value_match_needs_values(pack):
    assert pack.classify_column("contact", []) == []
    assert pack.classify_column("contact", [None]) == []


def test_value_pattern_must_match_whole_value(pack):
    assert pack.classify_column("contact", ["see a@b.com today"]) == []


def test_matching_rules_combine_per_label(pack):
    [s] = pack.classify_column("email", ["a@b.com"])
    assert s.confidence == 0.95
    assert s.rule_ids == ("email-name", "email-value")
    assert len(s.evidence) == 2


def test_rule_with_name_and_value_needs_both(pack):
    assert pack.classify_column("code", ["abc"]) == []
    assert pack.classify_column("other", ["ABC"]) == []
    assert [s.label for s in pack.classify_column("code", ["ABC"])] == ["code"]


def test_suggestions_sorted_by_confidence(pack):
    labels = [s.label for s in pack.classify_column("email_code", ["ABC"])]
    assert labels == ["email", "code"]


def test_sample_size_limits_values_examined(pack):
    values = ["a@b.com"] * 3 + ["x"] * 10
    assert pack.classify_column("c", values, sample_size=3)
    assert not pack.classify_column("c", values)


def test_values_are_stripped_and_stringified(pack):
    assert pack.classify_column("code", ["  ABC  "])
    assert not pack.classify_column("c", [12345])


def test_classify_table(pack):
    result = pack.classify({"email": [], "amount": ["1"]})
    assert [s.label for s in result["email"]] == ["email"]
    assert result["amount"] == []


# --- validation ---------------------------------------------------------------


def _pack(**overrides):
    data = {
        "pack": "p",
        "version": 1,
        "labels": {"email": {}},
        "rules": [{"id": "r", "label": "email", "column_name": "mail", "confidence": 0.5}],
    }
    data.update(overrides)
    return data


def _rule(**fields):
    rule = {"id": "r", "label": "email", "column_name": "mail", "confidence": 0.5}
    rule.update(fields)
    return _pack(rules=[{k: v for k, v in rule.items() if v is not None}])


@pytest.mark.parametrize(
    "data, message",
    [
        ("not a mapping", "must be a mapping"),
        (_pack(extra=1), "unknown keys"),
        (_pack(pack=""), "'pack'"),
        (_pack(version="1"), "'version'"),
        (_pack(version=True), "'version'"),
        (_pack(labels={}), "'labels'"),
        (_pack(labels={PUBLIC: {}}), "reserved"),
        (_pack(labels={"email": {"colour": "red"}}), "unknown keys"),
        (_pack(rules=[]), "'rules'"),
        (_pack(rules=["x"]), "must be a mapping"),
        (_rule(label="phone"), "not declared"),
        (_rule(column_name=None), "needs 'column_name'"),
        (_rule(column_name="("), "not a valid regex"),
        (_rule(confidence=None), "'confidence' is required"),
        (_rule(confidence=0), "(0, 1]"),
        (_rule(confidence=1.5), "(0, 1]"),
        (_rule(min_match_ratio=0.5), "needs 'value_pattern'"),
        (_rule(typo=1), "unknown keys"),
        (_pack(rules=[_rule()["rules"][0]] * 2), "duplicate rule id"),
    ],
)
def test_invalid_packs_rejected(data, message):
    with pytest.raises(
        RulePackError, match=message.replace("(", r"\(").replace(")", r"\)").replace("[", r"\[").replace("]", r"\]")
    ):
        RulePack.from_dict(data)


def test_invalid_yaml_rejected():
    with pytest.raises(RulePackError, match="YAML"):
        RulePack.from_yaml("pack: [unclosed")


# --- built-in core pack -------------------------------------------------------


def test_builtin_unknown():
    with pytest.raises(RulePackError, match="no built-in"):
        RulePack.builtin("nope")


@pytest.mark.parametrize(
    "column, values, label",
    [
        ("email_address", ["ada@example.com"], "email"),
        ("contact", ["ada@example.com", "bob@example.org"], "email"),
        ("mobile_no", [], "phone_number"),
        ("first_name", [], "person_name"),
        ("name", [], "person_name"),
        ("nric", [], "national_id"),
        ("passport_number", [], "national_id"),
        ("dob", [], "date_of_birth"),
        ("postcode", [], "postal_code"),
        ("shipping_zip", [], "postal_code"),
        ("home_address", [], "street_address"),
        ("client_ip", [], "ip_address"),
        ("src", ["10.0.0.1", "192.168.1.20"], "ip_address"),
        ("card_number", [], "payment_card"),
        ("x", ["4111 1111 1111 1111"], "payment_card"),
    ],
)
def test_core_pack_suggests(column, values, label):
    suggestions = RulePack.builtin().classify_column(column, values)
    assert suggestions and suggestions[0].label == label


@pytest.mark.parametrize(
    "column, values",
    [
        ("amount", ["12.50", "3.00"]),
        ("company", ["Acme"]),
        ("zip_file", []),
        ("email_address", []),  # must not also be suggested as street_address
        ("ip_address", []),
        ("country", ["MY", "SG"]),
    ],
)
def test_core_pack_avoids_false_positives(column, values):
    labels = {s.label for s in RulePack.builtin().classify_column(column, values)}
    assert "street_address" not in labels
    assert "postal_code" not in labels
    if column in ("amount", "company", "country"):
        assert labels == set()
