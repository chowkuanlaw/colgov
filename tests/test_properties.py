"""Property-based tests and parser fuzzing (Hypothesis)."""

import contextlib

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from colgov import (  # noqa: E402
    Catalog,
    CatalogError,
    InvalidToken,
    Keyring,
    Policy,
    PolicyError,
    RulePack,
    RulePackError,
    Tokenizer,
    column_risk,
    k_anonymity,
)

KEY = bytes(range(32))
OLD = bytes(range(1, 33))
TOK = Tokenizer(KEY)
ROTATED = Tokenizer(Keyring(KEY, previous=[OLD]))

text = st.text(max_size=200)
domain = st.text(min_size=1, max_size=40)
FAST = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@FAST
@given(value=text, column=domain)
def test_round_trip(value, column):
    assert TOK.detokenize(TOK.tokenize(value, column=column), column=column) == value


@FAST
@given(value=text, column=domain)
def test_deterministic_and_current(value, column):
    token = TOK.tokenize(value, column=column)
    assert token == Tokenizer(KEY).tokenize(value, column=column)
    assert TOK.is_current(token)
    assert set(token) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


@FAST
@given(a=text, b=text, column=domain)
def test_distinct_values_distinct_tokens(a, b, column):
    if a != b:
        assert TOK.tokenize(a, column=column) != TOK.tokenize(b, column=column)


@FAST
@given(value=text, c1=domain, c2=domain)
def test_domains_separate(value, c1, c2):
    if c1 != c2:
        token = TOK.tokenize(value, column=c1)
        assert token != TOK.tokenize(value, column=c2)
        with pytest.raises(InvalidToken):
            TOK.detokenize(token, column=c2)


@FAST
@given(value=text, column=domain)
def test_rotation_reads_old_and_retokenizes(value, column):
    old_token = Tokenizer(OLD).tokenize(value, column=column)
    assert ROTATED.detokenize(old_token, column=column) == value
    new_token = ROTATED.retokenize(old_token, column=column)
    assert new_token == TOK.tokenize(value, column=column)
    assert ROTATED.retokenize(new_token, column=column) == new_token


@FAST
@given(garbage=st.text(max_size=120), column=domain)
def test_detokenize_garbage_only_raises_invalid_token(garbage, column):
    with contextlib.suppress(InvalidToken):
        TOK.detokenize(garbage, column=column)


@FAST
@given(raw=st.binary(max_size=120), column=domain)
def test_detokenize_random_bytes_only_raises_invalid_token(raw, column):
    import base64

    token = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    with contextlib.suppress(InvalidToken):
        TOK.detokenize(token, column=column)


@FAST
@given(values=st.lists(st.one_of(st.none(), st.text(max_size=5)), max_size=60))
def test_column_risk_invariants(values):
    risk = column_risk(values)
    non_null = [v for v in values if v is not None]
    assert risk.n_rows == len(values)
    assert risk.n_null == len(values) - len(non_null)
    assert risk.n_distinct == len(set(non_null))
    assert 0.0 <= risk.top_share <= 1.0
    assert (risk.min_frequency == 0) == (not non_null)


@FAST
@given(rows=st.lists(st.fixed_dictionaries({"a": st.integers(0, 3), "b": st.sampled_from("xy")}), max_size=40))
def test_k_anonymity_invariants(rows):
    result = k_anonymity(rows, ["a", "b"])
    assert result.n_rows == len(rows)
    assert sum(result.class_sizes) == len(rows)
    assert result.k == (min(result.class_sizes) if rows else 0)
    assert result.rows_below(result.k) == 0


# --- parser fuzzing: malformed input must raise the documented error type only ---

yaml_scalars = st.one_of(st.none(), st.booleans(), st.integers(-3, 3), st.floats(allow_nan=False), st.text(max_size=12))
yaml_values = st.recursive(
    yaml_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4), st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=25,
)
FUZZ = settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])

KEYS = {
    "pack": [
        "pack",
        "version",
        "labels",
        "rules",
        "description",
        "id",
        "label",
        "column_name",
        "value_pattern",
        "confidence",
        "min_match_ratio",
    ],
    "catalog": ["version", "columns", "tables", "label", "decided_by", "decided_at", "note", "rule_ids", "domain"],
    "policy": ["roles", "view", "detokenize", "email"],
}


def structured(kind):
    keys = st.sampled_from(KEYS[kind])
    return st.recursive(
        yaml_scalars,
        lambda children: st.one_of(st.lists(children, max_size=3), st.dictionaries(keys, children, max_size=5)),
        max_leaves=30,
    )


@FUZZ
@given(data=st.one_of(yaml_values, structured("pack")))
def test_fuzz_rule_pack(data):
    with contextlib.suppress(RulePackError):
        RulePack.from_dict(data)


@FUZZ
@given(data=st.one_of(yaml_values, structured("catalog")))
def test_fuzz_catalog(data):
    with contextlib.suppress(CatalogError):
        Catalog.from_dict(data)


@FUZZ
@given(data=st.one_of(yaml_values, structured("policy")))
def test_fuzz_policy(data):
    with contextlib.suppress(PolicyError):
        Policy.from_dict(data)


@FUZZ
@given(text=st.text(max_size=300))
def test_fuzz_yaml_text(text):
    for parse, error in (
        (RulePack.from_yaml, RulePackError),
        (Catalog.from_yaml, CatalogError),
        (Policy.from_yaml, PolicyError),
    ):
        with contextlib.suppress(error):
            parse(text)
