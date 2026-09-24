import pytest

pd = pytest.importorskip("pandas")

from colgov import (  # noqa: E402
    PUBLIC,
    AccessDenied,
    Catalog,
    LowCardinalityError,
    MemoryAuditLog,
    Policy,
    PolicyError,
    Tokenizer,
)
from colgov import pandas as cpd  # noqa: E402

KEY = bytes(range(32))


@pytest.fixture
def df():
    return pd.DataFrame(
        {
            "customer_email": [f"user{i}@example.com" for i in range(12)],
            "amount": [float(i) for i in range(12)],
            "notes": ["n/a"] * 12,
        },
        index=[f"r{i}" for i in range(12)],
    )


@pytest.fixture
def catalog():
    cat = Catalog()
    cat.decide("customer_email", "email", by="alice")
    cat.decide("amount", PUBLIC, by="alice")
    return cat


@pytest.fixture
def policy():
    return Policy({"analyst": {"email": "tokenize"}, "support": {"email": {"view": "clear", "detokenize": True}}})


@pytest.fixture
def tok():
    return Tokenizer(KEY)


def test_classify(df):
    suggestions = cpd.classify(df)
    assert suggestions["customer_email"][0].label == "email"
    assert suggestions["amount"] == []


def test_apply_tokenizes_keeps_index_and_dtypes(df, policy, catalog, tok):
    out = cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)
    assert list(out.columns) == ["customer_email", "amount"]
    assert list(out.index) == list(df.index)
    assert out["amount"].dtype == df["amount"].dtype
    assert out["customer_email"].tolist() == [tok.tokenize(v, column="customer_email") for v in df["customer_email"]]


def test_apply_does_not_modify_input(df, policy, catalog, tok):
    before = df.copy()
    cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)
    pd.testing.assert_frame_equal(df, before)


@pytest.mark.parametrize("missing", [None, float("nan"), pd.NA])
def test_apply_missing_values_become_none(df, policy, catalog, tok, missing):
    df = df.astype({"customer_email": object})
    df.loc["r0", "customer_email"] = missing
    out = cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)
    assert out.loc["r0", "customer_email"] is None


def test_apply_string_dtype_column(df, policy, catalog, tok):
    df["customer_email"] = df["customer_email"].astype("string")
    out = cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)
    assert out["customer_email"].iloc[0] == tok.tokenize("user0@example.com", column="customer_email")


def test_apply_refuses_low_cardinality(policy, catalog, tok):
    df = pd.DataFrame({"customer_email": ["a@x.com", "b@x.com"] * 6})
    with pytest.raises(LowCardinalityError):
        cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)


def test_apply_non_string_tokenized_column_rejected(policy, tok):
    cat = Catalog()
    cat.decide("id", "email", by="alice")
    df = pd.DataFrame({"id": range(20)})
    with pytest.raises(TypeError):
        cpd.apply(df, policy, role="analyst", catalog=cat, tokenizer=tok)


def test_apply_needs_tokenizer(df, policy, catalog):
    with pytest.raises(PolicyError, match="tokenizer"):
        cpd.apply(df, policy, role="analyst", catalog=catalog)


def test_apply_unknown_role_gets_empty_frame(df, policy, catalog):
    out = cpd.apply(df, policy, role="intern", catalog=catalog)
    assert list(out.columns) == []
    assert list(out.index) == list(df.index)


def test_apply_audit(df, policy, catalog, tok):
    audit = MemoryAuditLog()
    cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok, audit=audit, actor="bob")
    [event] = audit.events
    assert (event.action, event.outcome, event.count) == ("view", "allowed", 12)
    with pytest.raises(PolicyError, match="actor"):
        cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok, audit=audit)


def test_apply_audit_records_errors(policy, catalog, tok):
    audit = MemoryAuditLog()
    df = pd.DataFrame({"customer_email": ["a@x.com"] * 5})
    with pytest.raises(LowCardinalityError):
        cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok, audit=audit, actor="bob")
    assert [e.outcome for e in audit.events] == ["error"]


def test_apply_rejects_bad_columns(policy, catalog):
    with pytest.raises(ValueError, match="unique"):
        cpd.apply(pd.DataFrame([[1, 2]], columns=["a", "a"]), policy, role="analyst", catalog=catalog)
    with pytest.raises(TypeError, match="strings"):
        cpd.apply(pd.DataFrame([[1]], columns=[0]), policy, role="analyst", catalog=catalog)


def test_detokenize_round_trip(df, policy, catalog, tok):
    tokens = cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)["customer_email"]
    audit = MemoryAuditLog()
    plain = cpd.detokenize(
        tokens,
        policy,
        role="support",
        catalog=catalog,
        tokenizer=tok,
        actor="carol",
        purpose="TICKET-9",
        audit=audit,
    )
    pd.testing.assert_series_equal(plain, df["customer_email"].astype(object))
    assert audit.events[0].count == 12


def test_detokenize_denied(df, policy, catalog, tok):
    tokens = cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)["customer_email"]
    with pytest.raises(AccessDenied):
        cpd.detokenize(
            tokens,
            policy,
            role="analyst",
            catalog=catalog,
            tokenizer=tok,
            actor="bob",
            purpose="curious",
            audit=MemoryAuditLog(),
        )


def test_detokenize_needs_column_name(policy, catalog, tok):
    with pytest.raises(ValueError, match="column"):
        cpd.detokenize(
            pd.Series(["x"]),
            policy,
            role="support",
            catalog=catalog,
            tokenizer=tok,
            actor="a",
            purpose="b",
            audit=MemoryAuditLog(),
        )


def test_apply_and_detokenize_with_table_and_domain(tok):
    cat = Catalog()
    cat.decide("buyer_email", "email", by="alice", table="orders", domain="email")
    policy = Policy({"fraud": {"email": {"view": "tokenize", "detokenize": True}}})
    df = pd.DataFrame({"buyer_email": [f"u{i}@x.com" for i in range(12)]})
    out = cpd.apply(df, policy, role="fraud", catalog=cat, table="orders", tokenizer=tok)
    assert out["buyer_email"].iloc[0] == tok.tokenize("u0@x.com", column="email")
    back = cpd.detokenize(
        out["buyer_email"],
        policy,
        role="fraud",
        catalog=cat,
        table="orders",
        tokenizer=tok,
        actor="c",
        purpose="p",
        audit=MemoryAuditLog(),
    )
    assert back.tolist() == df["buyer_email"].tolist()
