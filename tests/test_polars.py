import pytest

pl = pytest.importorskip("polars")

from colgov import (  # noqa: E402
    PUBLIC,
    AccessDenied,
    Catalog,
    LowCardinalityError,
    MemoryAuditLog,
    Policy,
    PolicyError,
    RulePack,
    Tokenizer,
)
from colgov import polars as cpl  # noqa: E402

KEY = bytes(range(32))


@pytest.fixture
def df():
    return pl.DataFrame(
        {
            "customer_email": [f"user{i}@example.com" for i in range(12)],
            "amount": [float(i) for i in range(12)],
            "notes": ["n/a"] * 12,
        }
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
    suggestions = cpl.classify(df)
    assert suggestions["customer_email"][0].label == "email"
    assert suggestions["amount"] == []


def test_classify_with_pack_and_sample_size():
    frame = pl.DataFrame({"x": ["900101-14-5678"] * 3 + ["not an id"] * 10})
    pack = RulePack.combine(RulePack.builtin("core"), RulePack.builtin("sea"))
    assert cpl.classify(frame, pack, sample_size=3)["x"][0].label == "national_id"
    assert cpl.classify(frame, pack)["x"] == []


def test_apply_tokenizes_and_keeps_dtypes(df, policy, catalog, tok):
    out = cpl.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)
    assert out.columns == ["customer_email", "amount"]
    assert out.schema["amount"] == pl.Float64
    assert out.schema["customer_email"] == pl.String
    assert out["customer_email"].to_list() == [
        tok.tokenize(v, column="customer_email") for v in df["customer_email"].to_list()
    ]


def test_apply_does_not_modify_input(df, policy, catalog, tok):
    before = df.clone()
    cpl.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)
    assert df.equals(before)


def test_apply_nulls_stay_null(df, policy, catalog, tok):
    df = df.with_columns(
        pl.when(pl.int_range(pl.len()) == 0).then(None).otherwise(pl.col("customer_email")).alias("customer_email")
    )
    out = cpl.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)
    assert out["customer_email"][0] is None
    assert out["customer_email"][1] == tok.tokenize("user1@example.com", column="customer_email")


def test_apply_categorical_and_all_null_columns(df, policy, catalog, tok):
    categorical = df.with_columns(pl.col("customer_email").cast(pl.Categorical))
    out = cpl.apply(categorical, policy, role="analyst", catalog=catalog, tokenizer=tok)
    assert out["customer_email"][0] == tok.tokenize("user0@example.com", column="customer_email")
    all_null = df.with_columns(pl.lit(None).alias("customer_email"))
    assert (
        cpl.apply(all_null, policy, role="analyst", catalog=catalog, tokenizer=tok)["customer_email"].null_count() == 12
    )


def test_apply_refuses_low_cardinality(policy, catalog, tok):
    frame = pl.DataFrame({"customer_email": ["a@x.com", "b@x.com"] * 6})
    with pytest.raises(LowCardinalityError):
        cpl.apply(frame, policy, role="analyst", catalog=catalog, tokenizer=tok)


def test_low_cardinality_error_names_the_column_not_its_domain(policy, tok):
    cat = Catalog()
    cat.decide("customer_email", "email", by="alice", domain="person_email")
    frame = pl.DataFrame({"customer_email": ["a@x.com", "b@x.com"] * 6})
    with pytest.raises(LowCardinalityError) as exc_info:
        cpl.apply(frame, policy, role="analyst", catalog=cat, tokenizer=tok)
    assert exc_info.value.column == "customer_email"


def test_apply_non_string_tokenized_column_rejected(policy, tok):
    cat = Catalog()
    cat.decide("id", "email", by="alice")
    frame = pl.DataFrame({"id": list(range(20))})
    with pytest.raises(TypeError, match="column 'id' is Int64, not String"):
        cpl.apply(frame, policy, role="analyst", catalog=cat, tokenizer=tok)


def test_apply_needs_tokenizer(df, policy, catalog):
    with pytest.raises(PolicyError, match="tokenizer"):
        cpl.apply(df, policy, role="analyst", catalog=catalog)


def test_apply_unknown_role_gets_empty_frame(df, policy, catalog):
    assert cpl.apply(df, policy, role="intern", catalog=catalog).width == 0


def test_apply_audit(df, policy, catalog, tok):
    audit = MemoryAuditLog()
    cpl.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok, audit=audit, actor="bob")
    [event] = audit.events
    assert (event.action, event.outcome, event.count) == ("view", "allowed", 12)
    with pytest.raises(PolicyError, match="actor"):
        cpl.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok, audit=audit)


def test_apply_audit_records_errors(policy, catalog, tok):
    audit = MemoryAuditLog()
    frame = pl.DataFrame({"customer_email": ["a@x.com"] * 5})
    with pytest.raises(LowCardinalityError):
        cpl.apply(frame, policy, role="analyst", catalog=catalog, tokenizer=tok, audit=audit, actor="bob")
    assert [e.outcome for e in audit.events] == ["error"]


def test_detokenize_round_trip(df, policy, catalog, tok):
    view = cpl.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)
    audit = MemoryAuditLog()
    tokens = view["customer_email"]
    back = cpl.detokenize(
        tokens, policy, role="support", catalog=catalog, tokenizer=tok, actor="carol", purpose="ticket 7", audit=audit
    )
    assert back.name == "customer_email"
    assert back.to_list() == df["customer_email"].to_list()
    assert [e.outcome for e in audit.events] == ["allowed"]


def test_detokenize_denied(df, policy, catalog, tok):
    tokens = cpl.apply(df, policy, role="analyst", catalog=catalog, tokenizer=tok)["customer_email"]
    audit = MemoryAuditLog()
    with pytest.raises(AccessDenied):
        cpl.detokenize(
            tokens, policy, role="analyst", catalog=catalog, tokenizer=tok, actor="bob", purpose="x", audit=audit
        )
    assert [e.outcome for e in audit.events] == ["denied"]


def test_detokenize_needs_column_name(policy, catalog, tok):
    with pytest.raises(ValueError, match="column"):
        cpl.detokenize(
            pl.Series([None]), policy, role="support", catalog=catalog, tokenizer=tok, actor="c", purpose="p",
            audit=MemoryAuditLog(),
        )  # fmt: skip


def test_apply_and_detokenize_with_table_and_domain(tok):
    cat = Catalog()
    cat.decide("email", "email", by="alice", table="crm", domain="person_email")
    policy = Policy({"support": {"email": {"view": "tokenize", "detokenize": True}}})
    frame = pl.DataFrame({"email": [f"u{i}@x.com" for i in range(12)]})
    out = cpl.apply(frame, policy, role="support", catalog=cat, table="crm", tokenizer=tok)
    assert out["email"][0] == tok.tokenize("u0@x.com", column="person_email")
    back = cpl.detokenize(
        out["email"], policy, role="support", catalog=cat, table="crm", tokenizer=tok, actor="c", purpose="p",
        audit=MemoryAuditLog(),
    )  # fmt: skip
    assert back.to_list() == frame["email"].to_list()
