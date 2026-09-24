import os
import sys

import pytest

pytest.importorskip("pyspark")

from pyspark.sql import SparkSession  # noqa: E402

from colgov import (  # noqa: E402
    PUBLIC,
    Catalog,
    LowCardinalityError,
    MemoryAuditLog,
    Policy,
    PolicyError,
    Tokenizer,
)
from colgov import spark as cspark  # noqa: E402

KEY = bytes(range(32))


@pytest.fixture(scope="module")
def spark():
    # Executors must import colgov too: run them on this interpreter.
    os.environ["PYSPARK_PYTHON"] = sys.executable
    session = (
        SparkSession.builder.master("local[1]")
        .appName("colgov-tests")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.shuffle.partitions", "1")
        .getOrCreate()
    )
    yield session
    session.stop()


@pytest.fixture
def sdf(spark):
    rows = [(f"user{i}@example.com", float(i), "n/a") for i in range(12)] + [(None, 99.0, "n/a")]
    return spark.createDataFrame(rows, "customer_email string, amount double, notes string")


@pytest.fixture
def catalog():
    cat = Catalog()
    cat.decide("customer_email", "email", by="alice")
    cat.decide("amount", PUBLIC, by="alice")
    return cat


@pytest.fixture
def policy():
    return Policy({"analyst": {"email": "tokenize"}})


@pytest.fixture
def tok():
    return Tokenizer(KEY)


def test_classify(sdf):
    suggestions = cspark.classify(sdf)
    assert suggestions["customer_email"][0].label == "email"
    assert suggestions["amount"] == []


def test_apply_matches_core_tokenizer(sdf, policy, catalog, tok):
    out = cspark.apply(sdf, policy, role="analyst", catalog=catalog, tokenizer=tok)
    assert out.columns == ["customer_email", "amount"]
    rows = out.collect()
    expected = [tok.tokenize(f"user{i}@example.com", column="customer_email") for i in range(12)] + [None]
    assert [r.customer_email for r in rows] == expected
    assert [r.amount for r in rows] == [float(i) for i in range(12)] + [99.0]
    assert dict(out.dtypes)["amount"] == "double"


def test_apply_refuses_low_cardinality(spark, policy, catalog, tok):
    sdf = spark.createDataFrame([("a@x.com",), ("b@x.com",), ("a@x.com",), (None,)], "customer_email string")
    with pytest.raises(LowCardinalityError) as exc_info:
        cspark.apply(sdf, policy, role="analyst", catalog=catalog, tokenizer=tok)
    risk = exc_info.value.risk
    assert (risk.n_rows, risk.n_null, risk.n_distinct, risk.min_frequency) == (4, 1, 2, 1)
    assert risk.top_share == pytest.approx(2 / 3)


def test_apply_all_null_column_allowed(spark, policy, catalog, tok):
    sdf = spark.createDataFrame([(None,), (None,)], "customer_email string")
    out = cspark.apply(sdf, policy, role="analyst", catalog=catalog, tokenizer=tok)
    assert [r.customer_email for r in out.collect()] == [None, None]


def test_apply_rejects_non_string_tokenized_column(spark, policy, tok):
    cat = Catalog()
    cat.decide("id", "email", by="alice")
    sdf = spark.createDataFrame([(i,) for i in range(20)], "id int")
    with pytest.raises(TypeError, match="cast it"):
        cspark.apply(sdf, policy, role="analyst", catalog=cat, tokenizer=tok)


def test_apply_needs_tokenizer(sdf, policy, catalog):
    with pytest.raises(PolicyError, match="tokenizer"):
        cspark.apply(sdf, policy, role="analyst", catalog=catalog)


def test_apply_unusual_column_names(spark, tok):
    cat = Catalog()
    cat.decide("e.mail`x", "email", by="alice")
    sdf = spark.createDataFrame([(f"u{i}@x.com",) for i in range(12)], ["e.mail`x"])
    out = cspark.apply(sdf, Policy({"a": {"email": "tokenize"}}), role="a", catalog=cat, tokenizer=tok)
    assert out.columns == ["e.mail`x"]
    assert out.first()[0] == tok.tokenize("u0@x.com", column="e.mail`x")


def test_apply_audit(sdf, policy, catalog, tok):
    audit = MemoryAuditLog()
    cspark.apply(sdf, policy, role="analyst", catalog=catalog, tokenizer=tok, audit=audit, actor="bob")
    [event] = audit.events
    assert (event.action, event.outcome) == ("view", "allowed")
    assert event.columns == ("customer_email", "amount")
    with pytest.raises(PolicyError, match="actor"):
        cspark.apply(sdf, policy, role="analyst", catalog=catalog, tokenizer=tok, audit=audit)


def test_apply_uses_table_and_domain(spark, tok):
    cat = Catalog()
    cat.decide("buyer_email", "email", by="alice", table="orders", domain="email")
    sdf = spark.createDataFrame([(f"u{i}@x.com",) for i in range(12)], "buyer_email string")
    policy = Policy({"a": {"email": "tokenize"}})
    out = cspark.apply(sdf, policy, role="a", catalog=cat, table="orders", tokenizer=tok)
    assert out.first()[0] == tok.tokenize("u0@x.com", column="email")
    assert cspark.apply(sdf, policy, role="a", catalog=cat, tokenizer=tok).columns == []
