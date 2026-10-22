import sqlite3

import pytest

from colgov import Catalog, Policy
from colgov.sql import SqlViewError, generate_view_sql


def _governance():
    catalog = Catalog()
    catalog.decide("email", "email", by="alice", table="customers")
    catalog.decide("amount", "public", by="alice", table="customers")
    catalog.decide("secret", "national_id", by="alice", table="customers")
    policy = Policy.from_yaml("roles:\n  analyst:\n    email: tokenize\n    national_id: deny\n")
    return policy, catalog


def test_generated_view_selects_tokens_and_omits_denied_columns():
    policy, catalog = _governance()
    sql = generate_view_sql(
        policy,
        catalog,
        role="analyst",
        table="customers",
        columns=["email", "email_token", "amount", "secret", "unreviewed"],
        source="raw_customers",
        view="analyst_customers",
        token_columns={"email": "email_token"},
    )
    assert '"email_token" AS "email"' in sql
    assert '"secret"' not in sql and '"unreviewed"' not in sql
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE raw_customers (email TEXT, email_token TEXT, amount TEXT, secret TEXT, unreviewed TEXT)")
    db.execute("INSERT INTO raw_customers VALUES ('raw@example.com', 'opaque-token', '10', 'secret', 'hidden')")
    db.execute(sql)
    assert db.execute("SELECT * FROM analyst_customers").fetchone() == ("opaque-token", "10")


def test_tokenized_treatment_needs_distinct_companion():
    policy, catalog = _governance()
    kwargs = dict(role="analyst", table="customers", columns=["email", "amount"], source="raw", view="analyst")
    with pytest.raises(SqlViewError, match="needs a pretokenized"):
        generate_view_sql(policy, catalog, token_columns={}, **kwargs)
    with pytest.raises(SqlViewError, match="must differ"):
        generate_view_sql(policy, catalog, token_columns={"email": "email"}, **kwargs)
    with pytest.raises(SqlViewError, match="must name source columns"):
        generate_view_sql(policy, catalog, token_columns={"email": "missing"}, **kwargs)


def test_identifiers_are_quoted_and_unknown_role_fails_closed():
    policy, catalog = _governance()
    sql = generate_view_sql(
        policy,
        catalog,
        role="analyst",
        table="customers",
        columns=["email", 'tok"en', "amount"],
        source='main.raw"data',
        view='main.analyst"view',
        token_columns={"email": 'tok"en'},
    )
    assert 'FROM "main"."raw""data";' in sql
    assert '"tok""en" AS "email"' in sql
    with pytest.raises(SqlViewError, match="no visible columns"):
        generate_view_sql(
            policy,
            catalog,
            role="unknown",
            table="customers",
            columns=["email", "email_token"],
            source="raw",
            view="view",
            token_columns={"email": "email_token"},
        )
