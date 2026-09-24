import pytest

from colgov import (
    PUBLIC,
    Catalog,
    LowCardinalityError,
    Policy,
    PolicyError,
    RulePack,
    Tokenizer,
    Treatment,
)

POLICY = """
roles:
  analyst:
    email: tokenize
    postal_code: clear
  support:
    email: clear
  restricted:
    public: deny
  nobody:
"""

TABLE = {
    "email": [f"user{i}@example.com" for i in range(12)],
    "postal_code": [f"{50000 + i}" for i in range(12)],
    "amount": [str(i) for i in range(12)],
    "notes": ["free text"] * 12,
}


@pytest.fixture
def policy() -> Policy:
    return Policy.from_yaml(POLICY)


@pytest.fixture
def catalog() -> Catalog:
    cat = Catalog()
    cat.decide("email", "email", by="alice")
    cat.decide("postal_code", "postal_code", by="alice")
    cat.decide("amount", PUBLIC, by="alice")
    # "notes" is deliberately left unreviewed.
    return cat


@pytest.fixture
def tokenizer() -> Tokenizer:
    return Tokenizer(bytes(range(32)))


# --- resolve ------------------------------------------------------------------


def test_granted_label(policy, catalog):
    r = policy.resolve("analyst", "email", catalog)
    assert (r.treatment, r.label) == (Treatment.TOKENIZE, "email")
    assert policy.resolve("support", "email", catalog).treatment is Treatment.CLEAR


def test_unreviewed_column_is_denied(policy, catalog):
    r = policy.resolve("analyst", "notes", catalog)
    assert r.treatment is Treatment.DENY
    assert "not been reviewed" in r.reason
    assert r.label is None


def test_ungranted_label_is_denied(policy, catalog):
    r = policy.resolve("support", "postal_code", catalog)
    assert r.treatment is Treatment.DENY
    assert "no grant" in r.reason


def test_unknown_role_sees_nothing(policy, catalog):
    for column in TABLE:
        assert policy.resolve("intern", column, catalog).treatment is Treatment.DENY


def test_role_with_no_grants_sees_only_public(policy, catalog):
    plan = {r.column: r.treatment for r in policy.plan("nobody", TABLE, catalog)}
    assert plan == {
        "email": Treatment.DENY,
        "postal_code": Treatment.DENY,
        "amount": Treatment.CLEAR,
        "notes": Treatment.DENY,
    }


def test_public_can_be_overridden(policy, catalog):
    assert policy.resolve("restricted", "amount", catalog).treatment is Treatment.DENY


def test_label_typo_in_catalog_fails_closed(policy):
    cat = Catalog()
    cat.decide("email", "e-mail", by="alice")
    assert policy.resolve("support", "email", cat).treatment is Treatment.DENY


# --- apply --------------------------------------------------------------------


def test_apply_builds_role_view(policy, catalog, tokenizer):
    view = policy.apply(TABLE, role="analyst", catalog=catalog, tokenizer=tokenizer)
    assert list(view) == ["email", "postal_code", "amount"]
    assert view["postal_code"] == TABLE["postal_code"]
    assert view["amount"] == TABLE["amount"]
    assert view["email"] == [tokenizer.tokenize(v, column="email") for v in TABLE["email"]]


def test_apply_clear_needs_no_tokenizer(policy, catalog):
    view = policy.apply(TABLE, role="support", catalog=catalog)
    assert view == {"email": TABLE["email"], "amount": TABLE["amount"]}


def test_apply_tokenize_without_tokenizer_fails(policy, catalog):
    with pytest.raises(PolicyError, match="needs a tokenizer"):
        policy.apply(TABLE, role="analyst", catalog=catalog)


def test_apply_unknown_role_returns_nothing(policy, catalog):
    assert policy.apply(TABLE, role="intern", catalog=catalog) == {}


def test_apply_refuses_low_cardinality_tokenization(policy, tokenizer):
    cat = Catalog()
    cat.decide("email", "email", by="alice")
    table = {"email": ["a@x.com", "b@x.com"] * 6}
    with pytest.raises(LowCardinalityError):
        policy.apply(table, role="analyst", catalog=cat, tokenizer=tokenizer)
    view = policy.apply(table, role="analyst", catalog=cat, tokenizer=tokenizer, min_distinct=2)
    assert len(view["email"]) == 12


def test_apply_accepts_iterators(policy, catalog, tokenizer):
    table = {k: iter(v) for k, v in TABLE.items()}
    view = policy.apply(table, role="analyst", catalog=catalog, tokenizer=tokenizer)
    assert len(view["email"]) == 12


# --- loading ------------------------------------------------------------------


def test_load_from_file(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY, encoding="utf-8")
    assert Policy.load(path).roles == ["analyst", "support", "restricted", "nobody"]


def test_treatment_accepts_enum():
    p = Policy({"r": {"email": Treatment.CLEAR}})
    cat = Catalog()
    cat.decide("c", "email", by="a")
    assert p.resolve("r", "c", cat).treatment is Treatment.CLEAR


@pytest.mark.parametrize(
    "text, message",
    [
        ("[]", "single 'roles' key"),
        ("roles: {}", "non-empty"),
        ("roles: {a: {}}\nextra: 1", "single 'roles' key"),
        ("roles: {a: [email]}", "must map labels"),
        ("roles: {a: {email: show}}", "unknown treatment"),
        ("roles: {a: {'': clear}}", "non-empty"),
        ("roles: {a: {email: clear}", "YAML"),
    ],
)
def test_invalid_policies_rejected(text, message):
    with pytest.raises(PolicyError, match=message):
        Policy.from_yaml(text)


# --- end to end ---------------------------------------------------------------


def test_suggest_review_resolve_end_to_end(tokenizer):
    table = {
        "customer_email": [f"user{i}@example.com" for i in range(20)],
        "mobile_no": [f"+60 12-{1000000 + i}" for i in range(20)],
        "order_total": [f"{i}.00" for i in range(20)],
        "comments": ["n/a"] * 20,
    }
    suggestions = RulePack.builtin().classify(table)

    catalog = Catalog()
    for column in ("customer_email", "mobile_no"):
        catalog.accept(suggestions[column][0], by="alice")
    catalog.decide("order_total", PUBLIC, by="alice", note="no personal data")
    assert catalog.pending(table) == ["comments"]

    policy = Policy({"analyst": {"email": "tokenize", "phone_number": "deny"}})
    view = policy.apply(table, role="analyst", catalog=catalog, tokenizer=tokenizer)

    assert list(view) == ["customer_email", "order_total"]
    assert view["order_total"] == table["order_total"]
    assert all(t != v for t, v in zip(view["customer_email"], table["customer_email"]))
