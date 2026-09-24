from datetime import datetime, timezone

import pytest

from colgov import PUBLIC, Catalog, CatalogError, Suggestion

AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def test_decide_and_get():
    cat = Catalog()
    d = cat.decide("email", "email", by="alice", note="checked sample", at=AT)
    assert cat.get("email") == d
    assert (d.label, d.decided_by, d.decided_at, d.note) == ("email", "alice", AT, "checked sample")
    assert "email" in cat and len(cat) == 1
    assert not d.is_public


def test_decide_defaults_to_now_utc():
    d = Catalog().decide("c", "email", by="alice")
    assert d.decided_at.tzinfo is not None
    assert abs((datetime.now(timezone.utc) - d.decided_at).total_seconds()) < 5


def test_accept_suggestion_keeps_rule_ids():
    s = Suggestion("contact", "email", 0.95, ("email-value",), ("evidence",))
    d = Catalog().accept(s, by="alice", at=AT)
    assert (d.column, d.label, d.rule_ids) == ("contact", "email", ("email-value",))


def test_public_decision():
    assert Catalog().decide("amount", PUBLIC, by="alice").is_public


def test_redeciding_replaces():
    cat = Catalog()
    cat.decide("c", "email", by="alice", at=AT)
    cat.decide("c", PUBLIC, by="bob", at=AT)
    assert cat.get("c").label == PUBLIC
    assert len(cat) == 1


def test_revoke_returns_column_to_pending():
    cat = Catalog()
    cat.decide("c", "email", by="alice")
    cat.revoke("c")
    cat.revoke("never-decided")
    assert cat.pending(["c"]) == ["c"]


def test_pending_preserves_order():
    cat = Catalog()
    cat.decide("b", PUBLIC, by="alice")
    assert cat.pending(["c", "b", "a"]) == ["c", "a"]
    assert cat.pending({"a": [], "b": []}) == ["a"]


@pytest.mark.parametrize("by", ["", "   ", None])
def test_decision_needs_a_reviewer(by):
    with pytest.raises(CatalogError, match="named reviewer"):
        Catalog().decide("c", "email", by=by)


@pytest.mark.parametrize("column, label", [("", "email"), ("c", ""), ("c", None)])
def test_decision_needs_column_and_label(column, label):
    with pytest.raises(CatalogError):
        Catalog().decide(column, label, by="alice")


def test_naive_timestamp_rejected():
    with pytest.raises(CatalogError, match="timezone"):
        Catalog().decide("c", "email", by="alice", at=datetime(2026, 1, 1))


def test_yaml_round_trip(tmp_path):
    cat = Catalog()
    cat.decide("email", "email", by="alice", note="ok", at=AT, rule_ids=["email-name"])
    cat.decide("amount", PUBLIC, by="bob", at=AT)
    path = tmp_path / "catalog.yaml"
    cat.save(path)

    loaded = Catalog.load(path)
    assert sorted(loaded, key=lambda d: d.column) == sorted(cat, key=lambda d: d.column)
    assert "email:" in path.read_text(encoding="utf-8")


def test_yaml_is_stable_and_readable():
    cat = Catalog()
    cat.decide("b", PUBLIC, by="bob", at=AT)
    cat.decide("a", "email", by="alice", at=AT)
    assert cat.to_yaml() == (
        "version: 2\n"
        "columns:\n"
        "  a:\n"
        "    label: email\n"
        "    decided_by: alice\n"
        "    decided_at: '2026-01-02T03:04:05+00:00'\n"
        "  b:\n"
        "    label: public\n"
        "    decided_by: bob\n"
        "    decided_at: '2026-01-02T03:04:05+00:00'\n"
    )


def test_empty_yaml_is_empty_catalog():
    assert len(Catalog.from_yaml("")) == 0
    assert len(Catalog.from_yaml("columns: {}")) == 0


def test_yaml_unquoted_timestamp_accepted():
    cat = Catalog.from_yaml(
        "columns:\n  c:\n    label: email\n    decided_by: a\n    decided_at: 2026-01-02 03:04:05+00:00\n"
    )
    assert cat.get("c").decided_at == AT


@pytest.mark.parametrize(
    "text, message",
    [
        ("[]", "'columns' and/or 'tables'"),
        ("columns: {}\nextra: 1", "'columns' and/or 'tables'"),
        ("columns: []", "must be a mapping"),
        ("columns: {c: x}", "must be a mapping"),
        ("columns: {c: {label: email, decided_by: a, decided_at: '2026-01-01T00:00:00+00:00', x: 1}}", "unknown keys"),
        ("columns: {c: {label: email, decided_by: a}}", "'decided_at' is required"),
        ("columns: {c: {label: email, decided_by: a, decided_at: 'soon'}}", "ISO 8601"),
        ("columns: {c: {label: email, decided_by: a, decided_at: '2026-01-01T00:00:00'}}", "timezone"),
        ("columns: {c: {label: email, decided_at: '2026-01-01T00:00:00+00:00'}}", "named reviewer"),
        ("columns: {c: {label: email, decided_by: a, decided_at: '2026-01-01T00:00:00+00:00', rule_ids: x}}", "rule_ids"),
        ("columns: {c: [unclosed", "YAML"),
    ],
)
def test_invalid_catalogs_rejected(text, message):
    with pytest.raises(CatalogError, match=message):
        Catalog.from_yaml(text)


# --- tables and token domains (0.3) ----------------------------------------------


def test_tables_are_independent():
    cat = Catalog()
    cat.decide("id", "national_id", by="alice", table="customers", at=AT)
    cat.decide("id", PUBLIC, by="alice", table="orders", at=AT)
    assert cat.get("id", table="customers").label == "national_id"
    assert cat.get("id", table="orders").label == PUBLIC
    assert cat.get("id") is None  # no fallback from a table to table-less
    assert ("customers", "id") in cat and "id" not in cat
    assert cat.tables == ["customers", "orders"]
    assert cat.pending(["id", "name"], table="customers") == ["name"]
    cat.revoke("id", table="orders")
    assert cat.get("id", table="orders") is None


def test_tableless_decision_does_not_cover_tables():
    cat = Catalog()
    cat.decide("email", "email", by="alice")
    assert cat.get("email", table="customers") is None


def test_token_domain_defaults_to_column():
    cat = Catalog()
    d1 = cat.decide("email", "email", by="a")
    d2 = cat.decide("buyer_email", "email", by="a", table="orders", domain="email")
    assert d1.token_domain == "email"
    assert d2.token_domain == "email" and d2.domain == "email"


def test_accept_with_table_and_domain():
    s = Suggestion("contact", "email", 0.9, ("email-value",))
    d = Catalog().accept(s, by="alice", table="leads", domain="email")
    assert (d.table, d.column, d.domain) == ("leads", "contact", "email")


def test_yaml_round_trip_with_tables(tmp_path):
    cat = Catalog()
    cat.decide("amount", PUBLIC, by="bob", at=AT)
    cat.decide("email", "email", by="alice", table="customers", at=AT)
    cat.decide("buyer_email", "email", by="alice", table="orders", domain="email", at=AT)
    text = cat.to_yaml()
    assert text.startswith("version: 2\n")
    assert "tables:" in text and "domain: email" in text
    loaded = Catalog.from_yaml(text)
    order = lambda d: (d.table or "", d.column)  # noqa: E731
    assert sorted(loaded, key=order) == sorted(cat, key=order)


def test_tables_only_catalog_omits_columns_key():
    cat = Catalog()
    cat.decide("email", "email", by="a", table="t", at=AT)
    assert set(cat.to_dict()) == {"version", "tables"}


def test_reads_v1_catalog_files():
    cat = Catalog.from_yaml(
        "columns:\n  c:\n    label: email\n    decided_by: a\n    decided_at: '2026-01-02T03:04:05+00:00'\n"
    )
    assert cat.get("c").label == "email"


@pytest.mark.parametrize(
    "text, message",
    [
        ("version: 3\ncolumns: {}", "unsupported catalog version"),
        ("tables: []", "'tables' must be a mapping"),
        ("tables: {t: []}", "must be a mapping with a 'columns' key"),
        ("tables: {t: {rows: {}}}", "must be a mapping with a 'columns' key"),
        ("tables: {'': {columns: {}}}", "table names"),
        ("columns: {c: {label: email, decided_by: a, decided_at: '2026-01-01T00:00:00+00:00', domain: ''}}", "domain"),
    ],
)
def test_invalid_table_catalogs_rejected(text, message):
    with pytest.raises(CatalogError, match=message):
        Catalog.from_yaml(text)


def test_empty_table_name_rejected():
    with pytest.raises(CatalogError, match="table"):
        Catalog().decide("c", "email", by="a", table="")
