import argparse
import base64
import csv
import io
import json

import pytest

import colgov
from colgov import Catalog, Tokenizer, verify_audit_log
from colgov.cli import KEY_ENV, cmd_review, main

KEY = bytes(range(32))
KEY_B64 = base64.b64encode(KEY).decode()

POLICY = """
roles:
  analyst:
    email: tokenize
    phone_number: deny
  support:
    email: {view: clear, detokenize: true}
"""


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(KEY_ENV, KEY_B64)
    with open("data.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["customer_email", "mobile_no", "gender", "comments"])
        for i in range(20):
            w.writerow([f"user{i}@example.com", f"+60 12-{1000000 + i}", "MF"[i % 2], "" if i % 3 else "vip"])
    (tmp_path / "policy.yaml").write_text(POLICY)
    cat = Catalog()
    cat.decide("customer_email", "email", by="alice")
    cat.decide("mobile_no", "phone_number", by="alice")
    cat.decide("gender", "public", by="alice")
    cat.save(tmp_path / "catalog.yaml")
    return tmp_path


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


POLICY_ARGS = ("-p", "policy.yaml", "-c", "catalog.yaml")


def test_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert f"colgov {colgov.__version__}" in capsys.readouterr().out


def test_no_command_is_usage_error(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code == 2


def test_keygen(capsys):
    code, out, _ = run(capsys, "keygen")
    assert code == 0
    assert len(base64.b64decode(out.strip(), validate=True)) == 32


def test_classify(workdir, capsys):
    code, out, _ = run(capsys, "classify", "data.csv")
    assert code == 0
    assert "customer_email: email (0.95) [email-name, email-value]" in out
    assert "mobile_no: phone_number" in out
    assert "comments: (no suggestion)" in out


def test_classify_custom_pack(workdir, capsys):
    (workdir / "pack.yaml").write_text(
        "pack: t\nversion: 1\nlabels: {flag: {}}\nrules:\n"
        "  - {id: g, label: flag, column_name: gender, confidence: 0.5}\n"
    )
    code, out, _ = run(capsys, "classify", "data.csv", "--pack", "pack.yaml")
    assert code == 0
    assert "gender: flag (0.50)" in out


def test_plan(workdir, capsys):
    code, out, _ = run(capsys, "plan", "data.csv", *POLICY_ARGS, "--role", "analyst")
    assert code == 0
    lines = out.splitlines()
    assert lines[0].split()[:2] == ["customer_email", "tokenize"]
    assert lines[1].split()[:2] == ["mobile_no", "deny"]
    assert lines[2].split()[:2] == ["gender", "clear"]
    assert lines[3].split()[:2] == ["comments", "deny"]
    assert "not been reviewed" in lines[3]


def test_apply_to_file(workdir, capsys):
    code, _, err = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst", "-o", "out.csv")
    assert code == 0
    assert "left out 2 column(s): mobile_no, comments" in err
    rows = list(csv.DictReader(open("out.csv", newline="")))
    assert list(rows[0]) == ["customer_email", "gender"]
    assert rows[0]["customer_email"] == Tokenizer(KEY).tokenize("user0@example.com", column="customer_email")
    assert rows[0]["gender"] == "M"


def test_apply_to_stdout_with_audit(workdir, capsys):
    code, out, _ = run(
        capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "support", "--audit", "audit.jsonl", "--actor", "carol"
    )
    assert code == 0
    assert out.splitlines()[1] == "user0@example.com,M"
    assert verify_audit_log("audit.jsonl") == 1
    event = json.loads(open("audit.jsonl").readline())
    assert (event["action"], event["actor"], event["count"]) == ("view", "carol", 20)


def test_apply_empty_cells_stay_empty(workdir, capsys):
    cat = Catalog.load("catalog.yaml")
    cat.decide("comments", "public", by="alice")
    cat.save("catalog.yaml")
    code, out, _ = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "support")
    rows = list(csv.DictReader(io.StringIO(out)))
    assert [r["comments"] for r in rows[:3]] == ["vip", "", ""]


def test_apply_clear_only_needs_no_key(workdir, capsys, monkeypatch):
    monkeypatch.delenv(KEY_ENV)
    code, _, _ = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "support")
    assert code == 0


def test_apply_missing_key(workdir, capsys, monkeypatch):
    monkeypatch.delenv(KEY_ENV)
    code, _, err = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst")
    assert code == 1
    assert "no master key" in err and "colgov keygen" in err


@pytest.mark.parametrize(
    "bad, message", [("%%%", "not valid base64"), (base64.b64encode(b"short").decode(), "at least 32")]
)
def test_apply_bad_key(workdir, capsys, monkeypatch, bad, message):
    monkeypatch.setenv(KEY_ENV, bad)
    code, _, err = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst")
    assert code == 1 and message in err


def test_apply_key_file(workdir, capsys, monkeypatch):
    monkeypatch.delenv(KEY_ENV)
    (workdir / "key.txt").write_text(KEY_B64 + "\n")
    code, _, _ = run(
        capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst", "--key-file", "key.txt", "-o", "out.csv"
    )
    assert code == 0


def test_apply_low_cardinality_is_clean_error(workdir, capsys):
    cat = Catalog.load("catalog.yaml")
    cat.decide("gender", "email", by="alice")
    cat.save("catalog.yaml")
    code, out, err = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst")
    assert code == 1
    assert "colgov: error: column 'gender' has 2 distinct values" in err
    assert "pass --min-distinct 2" in err and "allow_low_cardinality" not in err
    assert out == ""
    code, _, _ = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst", "--min-distinct", "2")
    assert code == 0


def test_apply_audit_needs_actor(workdir, capsys):
    code, _, err = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst", "--audit", "a.jsonl")
    assert code == 1 and "--actor" in err


@pytest.mark.parametrize(
    "content, message",
    [("", "no header row"), ("a,a\n1,2\n", "unique"), ("a,b\n1\n", "line 2: expected 2 fields")],
)
def test_bad_csv(workdir, capsys, content, message):
    (workdir / "bad.csv").write_text(content)
    code, _, err = run(capsys, "classify", "bad.csv")
    assert code == 1 and message in err


def test_missing_file_is_clean_error(workdir, capsys):
    code, _, err = run(capsys, "classify", "nope.csv")
    assert code == 1 and err.startswith("colgov: error:")


def _tokens_file(workdir):
    tok = Tokenizer(KEY)
    (workdir / "tokens.txt").write_text(
        tok.tokenize("user0@example.com", column="customer_email")
        + "\n\n"
        + tok.tokenize("user1@example.com", column="customer_email")
        + "\n"
    )


DETOK = ("--column", "customer_email", "--actor", "carol", "--purpose", "TICKET-7", "--audit", "audit.jsonl")


def test_detokenize_allowed(workdir, capsys):
    _tokens_file(workdir)
    code, out, _ = run(capsys, "detokenize", *POLICY_ARGS, "--role", "support", *DETOK, "tokens.txt")
    assert code == 0
    assert out.splitlines() == ["user0@example.com", "", "user1@example.com"]
    event = json.loads(open("audit.jsonl").readline())
    assert (event["outcome"], event["purpose"], event["count"]) == ("allowed", "TICKET-7", 3)


def test_detokenize_from_stdin(workdir, capsys, monkeypatch):
    _tokens_file(workdir)
    monkeypatch.setattr("sys.stdin", open("tokens.txt"))
    code, out, _ = run(capsys, "detokenize", *POLICY_ARGS, "--role", "support", *DETOK)
    assert code == 0 and out.splitlines()[0] == "user0@example.com"


def test_detokenize_denied(workdir, capsys):
    _tokens_file(workdir)
    code, out, err = run(capsys, "detokenize", *POLICY_ARGS, "--role", "analyst", *DETOK, "tokens.txt")
    assert code == 1
    assert out == ""
    assert "may not detokenize" in err
    assert json.loads(open("audit.jsonl").readline())["outcome"] == "denied"


def test_detokenize_requires_purpose(workdir, capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["detokenize", *POLICY_ARGS, "--role", "support", "--column", "c", "--actor", "a", "--audit", "a.jsonl"])
    assert exc_info.value.code == 2


def test_audit_verify(workdir, capsys):
    _tokens_file(workdir)
    run(capsys, "detokenize", *POLICY_ARGS, "--role", "support", *DETOK, "tokens.txt")
    code, out, _ = run(capsys, "audit", "verify", "audit.jsonl")
    assert code == 0 and "OK: 1 event(s)" in out

    text = open("audit.jsonl").read().replace("carol", "mallory")
    open("audit.jsonl", "w").write(text)
    code, _, err = run(capsys, "audit", "verify", "audit.jsonl")
    assert code == 1 and "hash mismatch" in err


# --- review -------------------------------------------------------------------------


def _review(workdir, answers, catalog="new.yaml", by="alice"):
    args = argparse.Namespace(data="data.csv", catalog=catalog, by=by, pack="core", sample_size=1000, table=None)
    feed = iter(answers)

    def ask(prompt):
        try:
            return next(feed)
        except StopIteration:
            raise EOFError from None

    out = io.StringIO()
    code = cmd_review(args, ask=ask, out=out)
    return code, out.getvalue()


def test_review_accept_public_custom_and_skip(workdir):
    code, out = _review(workdir, ["1", "junk", "l phone_number", "p", "s"])
    assert code == 0
    cat = Catalog.load("new.yaml")
    assert cat.get("customer_email").label == "email"
    assert cat.get("customer_email").rule_ids == ("email-name", "email-value")
    assert cat.get("mobile_no").label == "phone_number"
    assert cat.get("gender").label == "public"
    assert cat.get("comments") is None
    assert all(d.decided_by == "alice" for d in cat)
    assert "labels in this pack" in out  # after "junk"
    assert "1 column(s) still pending" in out


def test_review_quit_keeps_earlier_decisions(workdir):
    _review(workdir, ["1", "q"])
    cat = Catalog.load("new.yaml")
    assert len(cat) == 1
    # Resuming only asks about what's still pending.
    code, out = _review(workdir, ["q"])
    assert "[1/3] mobile_no" in out


def test_review_eof_saves_and_exits(workdir):
    code, _ = _review(workdir, ["1"])
    assert code == 0
    assert len(Catalog.load("new.yaml")) == 1


def test_review_unknown_custom_label_reprompts(workdir):
    _review(workdir, ["l not_a_label", "l email", "q"])
    assert Catalog.load("new.yaml").get("customer_email").label == "email"


def test_review_nothing_pending(workdir):
    code, out = _review(workdir, [], catalog="catalog.yaml")
    assert "[1/1] comments" in out
    _review(workdir, ["p"], catalog="catalog.yaml")
    code, out = _review(workdir, [], catalog="catalog.yaml")
    assert "Nothing to review" in out


def test_review_does_not_print_values(workdir):
    _, out = _review(workdir, ["q"])
    assert "user0@example.com" not in out


def test_review_needs_reviewer_name(workdir, capsys):
    code, _, err = run(capsys, "review", "data.csv", "-c", "new.yaml", "--by", " ")
    assert code == 1 and "--by" in err


# --- key rotation, KMS, tables (0.3) ------------------------------------------------

NEW_KEY = bytes(range(1, 33))
NEW_B64 = base64.b64encode(NEW_KEY).decode()


def test_rotation_via_key_file_and_retokenize(workdir, capsys, monkeypatch):
    monkeypatch.delenv(KEY_ENV)
    (workdir / "old.keys").write_text(KEY_B64 + "\n")
    (workdir / "new.keys").write_text(f"# primary first\n{NEW_B64}\n{KEY_B64}\n")
    run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst", "--key-file", "old.keys", "-o", "old.csv")

    code, _, err = run(
        capsys, "retokenize", "old.csv", "--columns", "customer_email", "--key-file", "new.keys", "-o", "new.csv"
    )
    assert code == 0 and "re-issued 20 token(s)" in err
    rows = list(csv.DictReader(open("new.csv", newline="")))
    new = Tokenizer(NEW_KEY)
    assert rows[0]["customer_email"] == new.tokenize("user0@example.com", column="customer_email")
    assert rows[0]["gender"] == "M"  # untouched columns pass through

    # A second run is a no-op.
    code, _, err = run(
        capsys, "retokenize", "new.csv", "--columns", "customer_email", "--key-file", "new.keys", "-o", "-"
    )
    assert "re-issued 0 token(s)" in err


def test_retokenize_bad_columns(workdir, capsys):
    code, _, err = run(capsys, "retokenize", "data.csv", "--columns", "nope")
    assert code == 1 and "not found: nope" in err


def test_env_keyring_comma_separated(workdir, capsys, monkeypatch):
    old_token = Tokenizer(KEY).tokenize("user0@example.com", column="customer_email")
    (workdir / "t.txt").write_text(old_token + "\n")
    monkeypatch.setenv(KEY_ENV, f"{NEW_B64},{KEY_B64}")
    code, out, _ = run(capsys, "detokenize", *POLICY_ARGS, "--role", "support", *DETOK, "t.txt")
    assert code == 0 and out.strip() == "user0@example.com"


def test_keygen_aws_kms(capsys, monkeypatch):
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with moto.mock_aws():
        key_id = boto3.client("kms").create_key()["KeyMetadata"]["KeyId"]
        code, out, _ = run(capsys, "keygen", "--aws-kms-key-id", key_id)
        spec = out.strip()
        assert code == 0 and spec.startswith("aws-kms:")
        from colgov import load_key

        assert len(load_key(spec)) == 32


def test_table_option(workdir, capsys):
    cat = Catalog()
    cat.decide("customer_email", "email", by="alice", table="customers")
    cat.save("tables.yaml")
    args = ("-p", "policy.yaml", "-c", "tables.yaml", "--role", "analyst")
    code, out, _ = run(capsys, "plan", "data.csv", *args, "--table", "customers")
    assert out.splitlines()[0].split()[:2] == ["customer_email", "tokenize"]
    code, out, _ = run(capsys, "plan", "data.csv", *args)
    assert out.splitlines()[0].split()[:2] == ["customer_email", "deny"]


def test_plan_shows_detokenize_grants(workdir, capsys):
    code, out, _ = run(capsys, "plan", "data.csv", *POLICY_ARGS, "--role", "support")
    assert "(may detokenize)" in out.splitlines()[0]
    code, out, _ = run(capsys, "plan", "data.csv", *POLICY_ARGS, "--role", "analyst")
    assert "(may detokenize)" not in out


def test_review_with_table(workdir):
    args = argparse.Namespace(
        data="data.csv", catalog="t.yaml", by="alice", pack="core", sample_size=1000, table="customers"
    )
    answers = iter(["1", "q"])
    cmd_review(args, ask=lambda prompt: next(answers), out=io.StringIO())
    cat = Catalog.load("t.yaml")
    assert cat.get("customer_email", table="customers").label == "email"
    assert cat.get("customer_email") is None


# --- streaming (0.4) -------------------------------------------------------------------


def test_apply_bad_row_writes_nothing(workdir, capsys):
    with open("data.csv", "a", newline="") as f:
        f.write("only,three,fields\n")
    code, _, err = run(
        capsys,
        "apply",
        "data.csv",
        *POLICY_ARGS,
        "--role",
        "analyst",
        "-o",
        "out.csv",
        "--audit",
        "audit.jsonl",
        "--actor",
        "bob",
    )
    assert code == 1 and "line 22: expected 4 fields" in err
    assert not (workdir / "out.csv").exists()
    assert not list(workdir.glob(".colgov-*"))  # no temp file left behind
    assert json.loads(open("audit.jsonl").readline())["outcome"] == "error"


def test_apply_replaces_output_atomically(workdir, capsys):
    (workdir / "out.csv").write_text("old contents\n")
    code, _, _ = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst", "-o", "out.csv")
    assert code == 0
    assert open("out.csv").readline().strip() == "customer_email,gender"
    assert not list(workdir.glob(".colgov-*"))


def test_apply_audit_counts_rows_before_output(workdir, capsys):
    code, _, _ = run(
        capsys,
        "apply",
        "data.csv",
        *POLICY_ARGS,
        "--role",
        "analyst",
        "-o",
        "out.csv",
        "--audit",
        "audit.jsonl",
        "--actor",
        "bob",
    )
    event = json.loads(open("audit.jsonl").readline())
    assert (code, event["outcome"], event["count"]) == (0, "allowed", 20)


def test_classify_reads_only_the_sample(workdir, capsys):
    with open("data.csv", "a", newline="") as f:
        f.write("broken,row\n")
    code, out, _ = run(capsys, "classify", "data.csv", "--sample-size", "5")
    assert code == 0 and "customer_email: email" in out
    code, _, err = run(capsys, "classify", "data.csv")
    assert code == 1 and "expected 4 fields" in err


def test_cardinality_scan_is_exact_for_refused_columns(tmp_path):
    from colgov import LowCardinalityError
    from colgov.cli import _check_rows_and_cardinality

    path = tmp_path / "d.csv"
    path.write_text("a,b\n" + "".join(f"x{i % 2},{i}\n" for i in range(9)) + ",99\n")
    with pytest.raises(LowCardinalityError) as exc_info:
        _check_rows_and_cardinality(str(path), ["a", "b"], ["a"], 3)
    risk = exc_info.value.risk
    assert (risk.n_rows, risk.n_null, risk.n_distinct, risk.min_frequency) == (10, 1, 2, 4)
    assert _check_rows_and_cardinality(str(path), ["a", "b"], ["b"], 3) == 10


# --- rule packs on the command line ------------------------------------------------


def test_classify_with_combined_packs(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with open("my.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id_no", "customer_email"])
        for i in range(5):
            w.writerow([f"90010{i + 1}-14-567{i}", f"user{i}@example.com"])
    code, out, _ = run(capsys, "classify", "my.csv", "--pack", "core,sea")
    assert code == 0
    assert "id_no: national_id (0.90) [sea-mykad-value]" in out
    assert "customer_email: email" in out
    code, out, _ = run(capsys, "classify", "my.csv")
    assert "id_no: national_id" not in out  # core alone doesn't check MyKad values
    code, _, err = run(capsys, "classify", "my.csv", "--pack", " , ")
    assert code == 1 and "--pack must name at least one rule pack" in err
    code, _, err = run(capsys, "classify", "my.csv", "--pack", "core,nope")
    assert code == 1 and "built-in packs: core, sea" in err


# --- check ------------------------------------------------------------------------


def test_check_passes_when_every_column_is_reviewed(workdir, capsys):
    cat = Catalog.load("catalog.yaml")
    cat.decide("comments", "public", by="alice")
    cat.save("catalog.yaml")
    code, out, _ = run(capsys, "check", "data.csv", "-c", "catalog.yaml")
    assert code == 0
    assert out.strip() == "colgov check: 0 error(s), 0 warning(s) in 1 table(s), 4 column(s)"


def test_check_fails_on_unreviewed_columns(workdir, capsys):
    code, out, _ = run(capsys, "check", "data.csv", "-c", "catalog.yaml")
    assert code == 1
    assert "error: comments: not reviewed" in out
    assert "1 error(s)" in out


def test_check_uses_table(workdir, capsys):
    code, out, _ = run(capsys, "check", "data.csv", "-c", "catalog.yaml", "--table", "crm")
    assert code == 1
    assert out.count("not reviewed") == 4  # no fallback to table-less decisions
    assert "error: crm.customer_email: not reviewed" in out


def test_check_warns_about_stale_decisions_and_ungranted_labels(workdir, capsys):
    cat = Catalog.load("catalog.yaml")
    cat.decide("comments", "public", by="alice")
    cat.decide("old_column", "email", by="alice")
    cat.save("catalog.yaml")
    code, out, _ = run(capsys, "check", "data.csv", *POLICY_ARGS)
    assert code == 0  # warnings only
    assert "warning: old_column: has a decision but is not in the schema" in out
    # phone_number is denied to every role in POLICY
    assert "warning: mobile_no: label 'phone_number' is not granted to any role" in out
    assert "0 error(s), 2 warning(s)" in out
    code, _, _ = run(capsys, "check", "data.csv", *POLICY_ARGS, "--strict")
    assert code == 1


def test_check_github_format(workdir, capsys):
    code, out, _ = run(capsys, "check", "data.csv", "-c", "catalog.yaml", "--format", "github")
    assert code == 1
    assert "::error title=Unreviewed column::comments: not reviewed" in out


def test_check_merges_several_files_of_one_table(workdir, capsys):
    with open("more.csv", "w", newline="") as f:
        csv.writer(f).writerow(["customer_email", "signup_ip"])
    code, out, _ = run(capsys, "check", "data.csv", "more.csv", "-c", "catalog.yaml")
    assert code == 1
    assert "error: signup_ip: not reviewed" in out
    assert "1 table(s), 5 column(s)" in out


def _dbt(path, kind, nodes, sources=None):
    data = {
        "metadata": {"dbt_schema_version": f"https://schemas.getdbt.com/dbt/{kind}/v12.json"},
        "nodes": nodes,
        "sources": sources or {},
    }
    path.write_text(json.dumps(data))


def test_check_dbt_manifest(tmp_path, capsys):
    _dbt(
        tmp_path / "manifest.json",
        "manifest",
        {
            "model.shop.customers": {"name": "customers", "columns": {"email": {"name": "email"}, "id": {}}},
            "model.shop.orders": {"name": "orders", "columns": {}},  # undocumented: nothing to check
            "test.shop.not_null": {"name": "not_null", "columns": {"x": {"name": "x"}}},
        },
        {"source.shop.raw.users": {"name": "users", "columns": {"phone": {"name": "phone"}}}},
    )
    cat = Catalog()
    cat.decide("email", "email", by="alice", table="customers")
    cat.save(tmp_path / "catalog.yaml")
    code, out, _ = run(capsys, "check", str(tmp_path / "manifest.json"), "-c", str(tmp_path / "catalog.yaml"))
    assert code == 1
    assert "error: customers.id: not reviewed" in out
    assert "error: raw.users.phone: not reviewed" in out
    assert "not_null" not in out
    assert "2 error(s), 0 warning(s) in 2 table(s), 3 column(s)" in out


def test_check_dbt_catalog(tmp_path, capsys):
    _dbt(
        tmp_path / "catalog.json",
        "catalog",
        {"model.shop.customers": {"metadata": {"name": "CUSTOMERS"}, "columns": {"EMAIL": {"name": "EMAIL"}}}},
        {"source.shop.raw.users": {"metadata": {"name": "users"}, "columns": {"PHONE": {"name": "PHONE"}}}},
    )
    Catalog().save(tmp_path / "colgov.yaml")
    code, out, _ = run(capsys, "check", str(tmp_path / "catalog.json"), "-c", str(tmp_path / "colgov.yaml"))
    assert code == 1
    assert "error: customers.EMAIL: not reviewed" in out
    assert "error: raw.users.PHONE: not reviewed" in out


@pytest.mark.parametrize(
    "content, message",
    [
        ("{not json", "not valid JSON"),
        ('{"nodes": {}}', "not a dbt manifest.json or catalog.json"),
        ("[]", "not a dbt manifest.json or catalog.json"),
    ],
)
def test_check_rejects_other_json(tmp_path, capsys, content, message):
    (tmp_path / "x.json").write_text(content)
    Catalog().save(tmp_path / "c.yaml")
    code, _, err = run(capsys, "check", str(tmp_path / "x.json"), "-c", str(tmp_path / "c.yaml"))
    assert code == 1 and message in err


def test_check_dbt_with_table_is_an_error(tmp_path, capsys):
    _dbt(tmp_path / "manifest.json", "manifest", {})
    Catalog().save(tmp_path / "c.yaml")
    code, _, err = run(capsys, "check", str(tmp_path / "manifest.json"), "-c", str(tmp_path / "c.yaml"), "--table", "t")
    assert code == 1 and "--table can't be used with a dbt file" in err


# --- Parquet ----------------------------------------------------------------------


@pytest.fixture
def parquet_workdir(workdir):
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    table = pa.table(
        {
            "customer_email": pa.array([f"user{i}@example.com" for i in range(19)] + [None], pa.string()),
            "mobile_no": [f"+60 12-{1000000 + i}" for i in range(20)],
            "gender": pa.array(["MF"[i % 2] for i in range(20)]).dictionary_encode(),
            "age": pa.array(range(20, 40), pa.int32()),
        }
    )
    pq.write_table(table, "data.parquet")
    cat = Catalog.load("catalog.yaml")
    cat.decide("age", "public", by="alice")
    cat.save("catalog.yaml")
    return workdir


def test_apply_parquet_to_parquet_keeps_types(parquet_workdir, capsys):
    import pyarrow as pa
    import pyarrow.parquet as pq

    code, _, err = run(capsys, "apply", "data.parquet", *POLICY_ARGS, "--role", "analyst", "-o", "out.parquet")
    assert code == 0, err
    assert "left out 1 column(s): mobile_no" in err
    out = pq.read_table("out.parquet")
    assert out.column_names == ["customer_email", "gender", "age"]
    assert out.schema.field("age").type == pa.int32()
    assert out.schema.field("gender").type == pa.string()
    t = Tokenizer(KEY)
    emails = out.column("customer_email").to_pylist()
    assert emails[0] == t.tokenize("user0@example.com", column="customer_email")
    assert emails[-1] is None
    assert out.column("age").to_pylist() == list(range(20, 40))


def test_apply_parquet_to_csv_and_back(parquet_workdir, capsys):
    import pyarrow.parquet as pq

    code, _, _ = run(capsys, "apply", "data.parquet", *POLICY_ARGS, "--role", "analyst", "-o", "out.csv")
    assert code == 0
    rows = list(csv.reader(open("out.csv")))
    assert rows[0] == ["customer_email", "gender", "age"]
    assert rows[1][2] == "20" and rows[-1][0] == ""
    code, _, _ = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst", "-o", "fromcsv.parquet")
    assert code == 0
    assert pq.read_table("fromcsv.parquet").column_names == ["customer_email", "gender"]


def test_apply_parquet_in_batches(parquet_workdir, capsys, monkeypatch):
    import pyarrow as pa
    import pyarrow.parquet as pq

    from colgov import _tabular

    monkeypatch.setattr(_tabular, "BATCH_ROWS", 3)
    pq.write_table(pa.table({"customer_email": [f"u{i}@x.com" for i in range(20)]}), "data.parquet", row_group_size=4)
    code, _, _ = run(capsys, "apply", "data.parquet", *POLICY_ARGS, "--role", "analyst", "-o", "out.parquet")
    assert code == 0
    out = pq.read_table("out.parquet").column("customer_email").to_pylist()
    t = Tokenizer(KEY)
    assert out == [t.tokenize(f"u{i}@x.com", column="customer_email") for i in range(20)]


def test_apply_parquet_empty_view(parquet_workdir, capsys):
    import pyarrow.parquet as pq

    code, _, _ = run(capsys, "apply", "data.parquet", *POLICY_ARGS, "--role", "nobody", "-o", "out.parquet")
    assert code == 0
    assert pq.read_table("out.parquet").num_columns == 0


def test_apply_parquet_refuses_non_string_tokenized_columns(parquet_workdir, capsys):
    cat = Catalog.load("catalog.yaml")
    cat.decide("age", "email", by="alice")
    cat.save("catalog.yaml")
    code, _, err = run(capsys, "apply", "data.parquet", *POLICY_ARGS, "--role", "analyst", "-o", "out.parquet")
    assert code == 1
    assert "column 'age' is int32, not a string; cast it to string before tokenizing" in err
    assert not (parquet_workdir / "out.parquet").exists()


def test_apply_parquet_low_cardinality(parquet_workdir, capsys):
    cat = Catalog.load("catalog.yaml")
    cat.decide("gender", "email", by="alice")  # dictionary-encoded strings, 2 values
    cat.save("catalog.yaml")
    code, _, err = run(
        capsys, "apply", "data.parquet", *POLICY_ARGS, "--role", "analyst", "-o", "out.parquet",
        "--audit", "a.jsonl", "--actor", "bob",
    )  # fmt: skip
    assert code == 1 and "column 'gender' has 2 distinct values" in err
    assert not (parquet_workdir / "out.parquet").exists()
    assert json.loads(open("a.jsonl").read())["outcome"] == "error"


def test_parquet_classify_plan_check_and_retokenize(parquet_workdir, capsys):
    import pyarrow.parquet as pq

    code, out, _ = run(capsys, "classify", "data.parquet")
    assert code == 0 and "customer_email: email" in out
    code, out, _ = run(capsys, "plan", "data.parquet", *POLICY_ARGS, "--role", "analyst")
    assert code == 0 and "age" in out
    code, out, _ = run(capsys, "check", "data.parquet", "-c", "catalog.yaml")
    assert code == 0, out

    run(capsys, "apply", "data.parquet", *POLICY_ARGS, "--role", "analyst", "-o", "old.parquet")
    new_key = base64.b64encode(bytes(range(1, 33))).decode()
    (parquet_workdir / "keys.txt").write_text(f"{new_key}\n{KEY_B64}\n")
    code, _, err = run(capsys, "retokenize", "old.parquet", "--columns", "customer_email", "--key-file", "keys.txt", "-o", "new.parquet")  # fmt: skip
    assert code == 0 and "re-issued 19 token(s)" in err
    new = pq.read_table("new.parquet")
    assert new.column_names == ["customer_email", "gender", "age"]
    t = Tokenizer(bytes(range(1, 33)))
    assert new.column("customer_email").to_pylist()[0] == t.tokenize("user0@example.com", column="customer_email")
    code, _, err = run(capsys, "retokenize", "old.parquet", "--columns", "age", "-o", "x.parquet")
    assert code == 1 and "column 'age' is int32, not a string" in err


def test_unreadable_parquet(workdir, capsys):
    pytest.importorskip("pyarrow")
    (workdir / "bad.parquet").write_bytes(b"not parquet")
    code, _, err = run(capsys, "classify", "bad.parquet")
    assert code == 1 and "bad.parquet: not a readable Parquet file" in err


def test_parquet_needs_pyarrow(workdir, capsys, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_pyarrow(name, *args, **kwargs):
        if name.startswith("pyarrow"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_pyarrow)
    code, _, err = run(capsys, "classify", "data.parquet")
    assert code == 1 and 'pip install "colgov[parquet]"' in err


@pytest.mark.parametrize("suffix", [".csv", ".parquet"])
def test_output_is_not_left_behind_when_writing_fails(workdir, capsys, suffix):
    if suffix == ".parquet":
        pytest.importorskip("pyarrow")
    t = Tokenizer(KEY)
    good = t.tokenize("user0@example.com", column="customer_email")
    with open("tokens.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["customer_email"])
        w.writerow([good])
        w.writerow([good[:-2] + "xx"])  # tampered: fails on the second row, after writing began
    # A new primary key, so every token is decrypted and re-issued.
    new_key = base64.b64encode(bytes(range(1, 33))).decode()
    (workdir / "keys.txt").write_text(f"{new_key}\n{KEY_B64}\n")
    code, _, err = run(
        capsys,
        "retokenize",
        "tokens.csv",
        "--columns",
        "customer_email",
        "--key-file",
        "keys.txt",
        "-o",
        f"out{suffix}",
    )
    assert code == 1 and "failed authentication" in err
    assert sorted(p.name for p in workdir.iterdir() if p.name.startswith(("out", ".colgov-"))) == []


def test_parquet_large_string_columns_are_strings(workdir, capsys):
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    emails = [f"user{i}@example.com" for i in range(12)]
    pq.write_table(pa.table({"customer_email": pa.array(emails, pa.large_string())}), "big.parquet")
    code, _, err = run(capsys, "apply", "big.parquet", *POLICY_ARGS, "--role", "analyst", "-o", "out.parquet")
    assert code == 0, err
    t = Tokenizer(KEY)
    assert pq.read_table("out.parquet").column(0).to_pylist()[0] == t.tokenize(emails[0], column="customer_email")


def test_parquet_string_view_columns_are_strings(workdir, capsys):
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    if not hasattr(pa, "string_view"):
        pytest.skip("pyarrow < 16 has no string_view")
    emails = [f"user{i}@example.com" for i in range(12)]
    pq.write_table(pa.table({"customer_email": pa.array(emails, pa.string_view())}), "view.parquet")
    code, _, err = run(capsys, "apply", "view.parquet", *POLICY_ARGS, "--role", "analyst", "-o", "out.csv")
    assert code == 0, err
    t = Tokenizer(KEY)
    assert list(csv.reader(open("out.csv")))[1] == [t.tokenize(emails[0], column="customer_email")]
