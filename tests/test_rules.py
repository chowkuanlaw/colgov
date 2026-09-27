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
        (_rule(validator="luhn"), "'validator' needs 'value_pattern'"),
        (_rule(value_pattern="[0-9]+", validator="nope"), "unknown validator 'nope'"),
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
    with pytest.raises(RulePackError, match=r"no built-in rule pack named 'nope' \(built-in packs: core, sea\)"):
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
        ("x", ["4111-1111-1111-1111", "5500 0000 0000 0004"], "payment_card"),
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


def test_core_pack_card_numbers_need_a_valid_check_digit():
    # 16 digits in groups of four, but the Luhn check digit is wrong.
    labels = {s.label for s in RulePack.builtin().classify_column("x", ["4111 1111 1111 1112"] * 5)}
    assert "payment_card" not in labels


# --- validators ---------------------------------------------------------------


@pytest.mark.parametrize(
    "name, value, valid",
    [
        ("luhn", "4111 1111 1111 1111", True),
        ("luhn", "5500-0000-0000-0004", True),
        ("luhn", "4111111111111112", False),
        ("luhn", "0000", False),  # too short to be a card number
        ("my_nric", "900101-14-5678", True),
        ("my_nric", "900101145678", True),
        ("my_nric", "000229-10-1234", True),  # 29 Feb 2000
        ("my_nric", "010229-10-1234", False),  # no 29 Feb in 2001 or 1901
        ("my_nric", "901301-14-5678", False),  # month 13
        ("my_nric", "900132-14-5678", False),  # 32 January
        ("my_nric", "900101-00-5678", False),  # place code 00 is unassigned
        ("my_nric", "900101-19-5678", False),  # so are 17-20
        ("my_nric", "900101-71-5678", True),  # born abroad
        ("my_nric", "90010114567", False),  # 11 digits
        ("sg_nric", "S1234567D", True),
        ("sg_nric", "s1234567d", True),
        ("sg_nric", "T1234567J", True),
        ("sg_nric", "F1234567N", True),
        ("sg_nric", "G1234567X", True),
        ("sg_nric", "S1234567A", False),  # wrong check letter
        ("sg_nric", "M1234567K", True),  # M series: shape only
        ("sg_nric", "X1234567D", False),
        ("sg_nric", "S123456D", False),
        ("id_nik", "3174051501900001", True),
        ("id_nik", "3174055501900001", True),  # women: day + 40
        ("id_nik", "3174059901900001", False),  # day 59 after subtracting 40
        ("id_nik", "3174051513900001", False),  # month 13
        ("id_nik", "0074051501900001", False),  # no province 00
        ("id_nik", "3174051501900000", False),  # serial 0000
        ("id_nik", "317405150190001", False),  # 15 digits
    ],
)
def test_validators(name, value, valid):
    from colgov.rules import VALIDATORS

    assert VALIDATORS[name](value) is valid


def test_validator_filters_pattern_matches():
    pack = RulePack.from_dict(_rule(column_name=None, value_pattern="[0-9 -]+", validator="luhn", min_match_ratio=0.5))
    [suggestion] = pack.classify_column("c", ["4111 1111 1111 1111", "4111 1111 1111 1112"])
    assert suggestion.evidence == ("r: 1/2 sampled values match and pass luhn",)
    assert pack.classify_column("c", ["4111 1111 1111 1112"] * 2) == []


# --- built-in sea pack, and combining packs ------------------------------------


@pytest.fixture(scope="module")
def core_sea() -> RulePack:
    return RulePack.combine(RulePack.builtin("core"), RulePack.builtin("sea"))


def test_sea_pack_reuses_core_labels():
    core, sea = RulePack.builtin("core"), RulePack.builtin("sea")
    assert set(sea.labels) <= set(core.labels)


@pytest.mark.parametrize(
    "column, values, label",
    [
        # national IDs, recognised from their values alone
        ("x", ["900101-14-5678", "850615-10-1234", "770330-08-4321"], "national_id"),
        ("x", ["900101145678", "850615101234"], "national_id"),
        ("x", ["S1234567D", "T1234567J", "F1234567N", "G1234567X"], "national_id"),
        ("x", ["3174051501900001", "3174055501900001"], "national_id"),
        # national IDs, by Malay / Indonesian / regional column names
        ("no_kp", [], "national_id"),
        ("kad_pengenalan", [], "national_id"),
        ("mykad_no", [], "national_id"),
        ("ic", [], "national_id"),
        ("nik", [], "national_id"),
        ("no_ktp", [], "national_id"),
        ("fin_no", [], "national_id"),
        ("no_paspor", [], "national_id"),
        # phone numbers
        ("x", ["012-345 6789", "+60 12-345 6789", "0193456789", "03-2345 6789"], "phone_number"),
        ("x", ["+62 812-3456-7890", "081234567890"], "phone_number"),
        ("no_telefon", [], "phone_number"),
        ("no_hp", [], "phone_number"),
        ("handphone", [], "phone_number"),
        ("telepon", [], "phone_number"),
        # other Malay / Indonesian names
        ("nama", [], "person_name"),
        ("nama_penuh", [], "person_name"),
        ("nama_lengkap", [], "person_name"),
        ("emel", [], "email"),
        ("tarikh_lahir", [], "date_of_birth"),
        ("tgl_lahir", [], "date_of_birth"),
        ("poskod", [], "postal_code"),
        ("kode_pos", [], "postal_code"),
        ("alamat_rumah", [], "street_address"),
    ],
)
def test_sea_pack_suggests(core_sea, column, values, label):
    suggestions = core_sea.classify_column(column, values)
    assert suggestions and suggestions[0].label == label


@pytest.mark.parametrize(
    "column, values",
    [
        ("x", ["901301-14-5678", "900132-14-5678"]),  # MyKad-shaped, impossible dates
        ("x", ["S1234567A", "T1234567B"]),  # NRIC-shaped, wrong check letters
        ("x", ["4111111111111111", "5500000000000004"]),  # card numbers, not NIKs
        ("kpi", []),
        ("finance", []),
        ("picture", []),
        ("namespace", []),
    ],
)
def test_sea_pack_avoids_false_positives(core_sea, column, values):
    assert "national_id" not in {s.label for s in core_sea.classify_column(column, values)}


def test_combine(core_sea):
    core, sea = RulePack.builtin("core"), RulePack.builtin("sea")
    assert core_sea.name == "core+sea"
    assert len(core_sea.rules) == len(core.rules) + len(sea.rules)
    assert set(core_sea.labels) == set(core.labels) | set(sea.labels)
    assert core_sea.labels["national_id"] == core.labels["national_id"]  # first pack wins
    assert RulePack.combine(core) is core


def test_combine_rejects_duplicate_rule_ids():
    core = RulePack.builtin("core")
    with pytest.raises(RulePackError, match="appears in more than one pack"):
        RulePack.combine(core, core)
    with pytest.raises(ValueError, match="at least one pack"):
        RulePack.combine()
