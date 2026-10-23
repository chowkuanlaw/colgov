import json
from datetime import datetime, timezone

import pytest

from colgov import (
    AuditEvent,
    Catalog,
    JsonlAuditLog,
    Keyring,
    Policy,
    Tokenizer,
    Treatment,
)
from colgov.access import compare_access, explain_access
from colgov.checkpoint import CheckpointError, load_checkpoint, save_checkpoint
from colgov.dbt import DbtError, generate_dbt_views, load_dbt_relations
from colgov.risk_gate import RiskThresholds, profile_columns, risk_violations
from colgov.rotation import RotationError, preview_rotation
from colgov.rule_cases import RuleCaseError, load_rule_cases, run_rule_cases
from colgov.rules import RulePack
from colgov.sql import SqlViewError, generate_view_sql


def _catalog(label="email", domain=None, table=None):
    catalog = Catalog()
    catalog.decide("email", label, by="alice", table=table, domain=domain)
    return catalog


def test_policy_explain_and_diff_catch_access_expansion_and_revocation():
    before = Policy.from_dict({"roles": {"analyst": {"email": "tokenize"}}})
    after = Policy.from_dict({"roles": {"analyst": {"email": {"view": "clear", "detokenize": True}}}})
    catalog = _catalog()
    detail = explain_access(before, catalog, role="analyst", column="email")
    assert detail.view is Treatment.TOKENIZE
    assert detail.label == "email" and detail.decided_by == "alice"
    assert not detail.detokenize
    changes = compare_access(before, catalog, after, catalog)
    assert len(changes) == 1 and changes[0].kind == "expansion"
    assert changes[0].after.detokenize
    revoked = compare_access(after, catalog, before, Catalog())
    assert revoked[0].kind == "restriction"
    assert revoked[0].after.view is Treatment.DENY


def test_policy_diff_reports_domain_change_and_unknown_role():
    policy = Policy.from_dict({"roles": {"analyst": {"email": "tokenize"}}})
    changes = compare_access(policy, _catalog(domain="a"), policy, _catalog(domain="b"))
    assert len(changes) == 1 and changes[0].kind == "configuration"
    assert changes[0].before.domain == "a" and changes[0].after.domain == "b"
    denied = explain_access(policy, _catalog(), role="unknown", column="email")
    assert denied.view is Treatment.DENY and "unknown role" in denied.view_reason
    assert compare_access(policy, Catalog(), policy, Catalog(), schemas={None: ["new"]}) == []


def test_sql_dialects_quote_identifiers_and_reject_unknown():
    policy = Policy.from_dict({"roles": {"analyst": {"email": "tokenize"}}})
    catalog = _catalog()
    kwargs = dict(
        role="analyst",
        columns=["email", "email_token"],
        source="project.raw.people",
        view="project.safe.people",
        token_columns={"email": "email_token"},
    )
    assert "`email_token` AS `email`" in generate_view_sql(policy, catalog, **kwargs, dialect="bigquery")
    assert '"email_token" AS "email"' in generate_view_sql(policy, catalog, **kwargs, dialect="postgres")
    assert '"email_token" AS "email"' in generate_view_sql(policy, catalog, **kwargs, dialect="snowflake")
    with pytest.raises(SqlViewError, match="unsupported SQL dialect"):
        generate_view_sql(policy, catalog, **kwargs, dialect="mysql")
    with pytest.raises(SqlViewError, match="source and view must differ"):
        generate_view_sql(policy, catalog, **{**kwargs, "view": kwargs["source"]})


def _dbt_artifacts(tmp_path, *, catalog_columns=None):
    manifest = {
        "metadata": {"dbt_schema_version": "https://schemas.getdbt.com/dbt/manifest/v12.json"},
        "nodes": {
            "model.shop.customers": {
                "name": "customers",
                "database": "warehouse",
                "schema": "raw",
                "alias": "customer_data",
            }
        },
    }
    physical = {
        "metadata": {"dbt_schema_version": "https://schemas.getdbt.com/dbt/catalog/v1.json"},
        "nodes": {
            "model.shop.customers": {
                "columns": catalog_columns or {"email": {"name": "email"}, "email_token": {"name": "email_token"}}
            }
        },
    }
    manifest_path = tmp_path / "manifest.json"
    catalog_path = tmp_path / "catalog.json"
    manifest_path.write_text(json.dumps(manifest))
    catalog_path.write_text(json.dumps(physical))
    return manifest_path, catalog_path


def test_dbt_views_need_complete_catalog_and_reviews(tmp_path):
    manifest, physical = _dbt_artifacts(tmp_path)
    relations = load_dbt_relations(manifest, physical)
    assert len(relations) == 1 and relations[0].source == "warehouse.raw.customer_data"
    policy = Policy.from_dict({"roles": {"analyst": {"email": "tokenize"}}})
    with pytest.raises(DbtError, match="unreviewed columns"):
        generate_dbt_views(relations, policy, Catalog(), role="analyst", view_schema="safe")
    governed = _catalog(table="customers")
    views = generate_dbt_views(
        relations,
        policy,
        governed,
        role="analyst",
        view_schema="safe",
        token_columns={"customers": {"email": "email_token"}},
        dialect="bigquery",
    )
    assert "`email_token` AS `email`" in views["customers"]
    assert "`warehouse`.`safe`.`customer_data`" in views["customers"]
    with pytest.raises(DbtError, match="unknown dbt tables"):
        generate_dbt_views(relations, policy, governed, role="analyst", view_schema="safe", token_columns={"other": {}})
    physical.write_text(json.dumps({"metadata": {"dbt_schema_version": "x/catalog/y"}, "nodes": {}}))
    with pytest.raises(DbtError, match="missing complete catalog"):
        load_dbt_relations(manifest, physical)


def test_dbt_views_reject_malformed_artifacts(tmp_path):
    manifest_path, catalog_path = _dbt_artifacts(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    catalog = json.loads(catalog_path.read_text())

    manifest["metadata"] = []
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(DbtError, match="not a dbt manifest"):
        load_dbt_relations(manifest_path, catalog_path)

    manifest["metadata"] = {"dbt_schema_version": "https://schemas.getdbt.com/dbt/manifest/v12.json"}
    manifest["nodes"]["model.shop.customers"]["name"] = ""
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(DbtError, match="name must be"):
        load_dbt_relations(manifest_path, catalog_path)

    manifest["nodes"]["model.shop.customers"]["name"] = "customers"
    manifest_path.write_text(json.dumps(manifest))
    catalog["nodes"]["model.shop.customers"]["columns"]["email"]["name"] = ["bad"]
    catalog_path.write_text(json.dumps(catalog))
    with pytest.raises(DbtError, match="column names must be"):
        load_dbt_relations(manifest_path, catalog_path)

    catalog["nodes"]["model.shop.customers"]["columns"]["email"]["name"] = "email"
    catalog_path.write_text(json.dumps(catalog))
    manifest["nodes"] = {}
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(DbtError, match="no materialized relations"):
        load_dbt_relations(manifest_path, catalog_path)


def test_risk_profiles_and_thresholds_are_exact():
    rows = [["A", None], ["A", None], ["B", None], ["C", None]]
    risks = profile_columns(rows, ["code", "empty"])
    assert risks["code"].n_distinct == 3
    assert risks["code"].top_share == 0.5
    assert risks["code"].min_frequency == 1
    assert risks["empty"].n_null == 4
    assert risk_violations(risks["empty"], RiskThresholds(10)) == []
    assert len(risk_violations(risks["code"], RiskThresholds(4, 0.4, 2))) == 3
    assert risk_violations(risks["code"], RiskThresholds(3, 0.5, 1)) == []
    with pytest.raises(ValueError, match="row length"):
        profile_columns([["only one"]], ["a", "b"])
    with pytest.raises(ValueError, match="non-string"):
        profile_columns([[4]], ["a"])
    with pytest.raises(ValueError, match="max_top_share"):
        RiskThresholds(1, 1.1)


def test_rotation_preview_authenticates_every_token():
    old = Tokenizer(bytes(range(32)))
    new = Tokenizer(Keyring(bytes(range(32, 64)), previous=[bytes(range(32))]))
    rows = [
        {"email": old.tokenize("a@example.com", column="contact")},
        {"email": new.tokenize("b@example.com", column="contact")},
        {"email": None},
    ]
    impact = preview_rotation(rows, {"email": "contact"}, new)[0]
    assert (impact.total, impact.reissue, impact.current, impact.null) == (3, 1, 1, 1)
    with pytest.raises(RotationError, match="invalid token"):
        preview_rotation(rows, {"email": "wrong-domain"}, new)
    with pytest.raises(RotationError, match="missing column"):
        preview_rotation([{}], {"email": "contact"}, new)


def test_rule_cases_report_mismatch_and_overlap(tmp_path):
    path = tmp_path / "cases.yaml"
    path.write_text(
        "cases:\n"
        "  - {name: email, column: email, values: [a@example.com], expected: [email]}\n"
        "  - {name: miss, column: other, values: [none], expected: [email]}\n"
    )
    cases = load_rule_cases(path)
    results = run_rule_cases(RulePack.builtin("core"), cases)
    assert results[0].passed and not results[1].passed
    assert "a@example.com" not in repr(results)
    path.write_text("cases: [{name: x, column: c, values: [a], expected: [unknown]}]\n")
    with pytest.raises(RuleCaseError, match="unknown labels"):
        run_rule_cases(RulePack.builtin("core"), load_rule_cases(path))
    path.write_text("cases: [{name: x, column: c, values: not-a-list, expected: []}]\n")
    with pytest.raises(RuleCaseError, match="values"):
        load_rule_cases(path)
    path.write_text("cases: [\n  - values: [private@example.com\n")
    with pytest.raises(RuleCaseError, match="invalid cases YAML") as error:
        load_rule_cases(path)
    assert "private@example.com" not in str(error.value)


def _log(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = JsonlAuditLog(path)
    log.record(
        AuditEvent("alice", "support", "detokenize", "allowed", ("email",), "test", at=datetime.now(timezone.utc))
    )
    return path


def test_audit_checkpoint_local_and_s3(tmp_path):
    path = _log(tmp_path)
    destination = tmp_path / "checkpoint.json"
    checkpoint = save_checkpoint(path, destination)
    assert checkpoint.count == 1 and load_checkpoint(destination) == checkpoint
    with pytest.raises(FileExistsError):
        save_checkpoint(path, destination)
    assert destination.stat().st_mode & 0o777 == 0o600

    class S3:
        def __init__(self):
            self.object = None
            self.options = None

        def put_object(self, **kwargs):
            self.object = kwargs["Body"]
            self.options = kwargs

        def get_object(self, **kwargs):
            from io import BytesIO

            return {"Body": BytesIO(self.object)}

    fake = S3()
    saved = save_checkpoint(path, "s3://bucket/checkpoint.json", retention_days=3, s3_client=fake)
    assert fake.options["IfNoneMatch"] == "*"
    assert fake.options["ObjectLockMode"] == "COMPLIANCE"
    assert fake.options["ChecksumAlgorithm"] == "SHA256"
    assert load_checkpoint("s3://bucket/checkpoint.json", s3_client=fake) == saved
    with pytest.raises(CheckpointError, match="requires an S3"):
        save_checkpoint(path, tmp_path / "other.json", retention_days=3)
    destination.write_text("{}")
    with pytest.raises(CheckpointError, match="checkpoint must have"):
        load_checkpoint(destination)
