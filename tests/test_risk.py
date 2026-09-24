import pytest

from colgov import (
    DEFAULT_MIN_DISTINCT,
    LowCardinalityError,
    Tokenizer,
    column_risk,
    k_anonymity,
)

KEY = bytes(range(32))


# --- column_risk ------------------------------------------------------------


def test_column_risk_profile():
    risk = column_risk(["a", "a", "a", "b", None])
    assert risk.n_rows == 5
    assert risk.n_null == 1
    assert risk.n_non_null == 4
    assert risk.n_distinct == 2
    assert risk.min_frequency == 1
    assert risk.top_share == 0.75


def test_column_risk_empty():
    risk = column_risk([])
    assert (risk.n_rows, risk.n_distinct, risk.min_frequency, risk.top_share) == (0, 0, 0, 0.0)
    assert not risk.is_low_cardinality()


def test_column_risk_all_null_is_not_low_cardinality():
    risk = column_risk([None, None])
    assert risk.n_distinct == 0
    assert risk.top_share == 0.0
    assert not risk.is_low_cardinality()


def test_column_risk_accepts_generators():
    assert column_risk(str(i) for i in range(3)).n_distinct == 3


def test_is_low_cardinality_threshold():
    values = [str(i) for i in range(DEFAULT_MIN_DISTINCT)]
    assert not column_risk(values).is_low_cardinality()
    assert column_risk(values[:-1]).is_low_cardinality()
    assert not column_risk(["M", "F"]).is_low_cardinality(min_distinct=2)


# --- k_anonymity ------------------------------------------------------------


def test_k_anonymity():
    rows = [
        {"age": 30, "zip": "111", "name": "a"},
        {"age": 30, "zip": "111", "name": "b"},
        {"age": 30, "zip": "111", "name": "c"},
        {"age": 41, "zip": "222", "name": "d"},
        {"age": 41, "zip": "222", "name": "e"},
        {"age": 52, "zip": "333", "name": "f"},
    ]
    result = k_anonymity(rows, ["age", "zip"])
    assert result.k == 1
    assert result.n_rows == 6
    assert result.n_classes == 3
    assert result.class_sizes == (1, 2, 3)
    assert result.rows_below(2) == 1
    assert result.rows_below(3) == 3
    assert result.rows_below(1) == 0


def test_k_anonymity_fewer_quasi_identifiers_raises_k():
    rows = [{"age": 30, "zip": "1"}, {"age": 30, "zip": "2"}]
    assert k_anonymity(rows, ["age", "zip"]).k == 1
    assert k_anonymity(rows, ["age"]).k == 2


def test_k_anonymity_groups_nulls():
    rows = [{"age": None}, {"age": None}, {"age": 5}]
    assert k_anonymity(rows, ["age"]).class_sizes == (1, 2)


def test_k_anonymity_empty_table():
    result = k_anonymity([], ["age"])
    assert (result.k, result.n_rows, result.n_classes) == (0, 0, 0)


def test_k_anonymity_missing_column_raises():
    with pytest.raises(KeyError):
        k_anonymity([{"age": 1}], ["zip"])


@pytest.mark.parametrize("qi", [[], (), "age"])
def test_k_anonymity_rejects_bad_quasi_identifiers(qi):
    with pytest.raises(ValueError):
        k_anonymity([{"age": 1}], qi)


# --- Tokenizer.tokenize_column ----------------------------------------------


def test_tokenize_column_refuses_low_cardinality():
    with pytest.raises(LowCardinalityError) as exc_info:
        Tokenizer(KEY).tokenize_column(["M", "F", "F", None], column="gender")
    err = exc_info.value
    assert err.column == "gender"
    assert err.risk.n_distinct == 2
    assert err.min_distinct == DEFAULT_MIN_DISTINCT
    assert "gender" in str(err)
    assert isinstance(err, ValueError)


def test_tokenize_column_override():
    t = Tokenizer(KEY)
    tokens = t.tokenize_column(["M", "F", None], column="gender", allow_low_cardinality=True)
    assert tokens[2] is None
    assert [t.detokenize(x, column="gender") for x in tokens] == ["M", "F", None]


def test_tokenize_column_custom_threshold():
    t = Tokenizer(KEY)
    assert len(t.tokenize_column(["a", "b"], column="c", min_distinct=2)) == 2
    with pytest.raises(LowCardinalityError):
        t.tokenize_column(["a", "b"], column="c", min_distinct=3)


def test_tokenize_column_matches_tokenize():
    t = Tokenizer(KEY)
    values = [f"user{i}@example.com" for i in range(20)] + [None]
    tokens = t.tokenize_column(iter(values), column="email")
    assert tokens == [t.tokenize(v, column="email") for v in values]


def test_tokenize_column_all_null_and_empty():
    t = Tokenizer(KEY)
    assert t.tokenize_column([None, None], column="c") == [None, None]
    assert t.tokenize_column([], column="c") == []
