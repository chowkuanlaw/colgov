import argparse
import base64
import csv
import io
import json

import pytest

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
    email: clear
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
    assert "colgov 0.2.0" in capsys.readouterr().out


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
    code, out, _ = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "support",
                       "--audit", "audit.jsonl", "--actor", "carol")
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


@pytest.mark.parametrize("bad, message", [("%%%", "not valid base64"), (base64.b64encode(b"short").decode(), "at least 32")])
def test_apply_bad_key(workdir, capsys, monkeypatch, bad, message):
    monkeypatch.setenv(KEY_ENV, bad)
    code, _, err = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst")
    assert code == 1 and message in err


def test_apply_key_file(workdir, capsys, monkeypatch):
    monkeypatch.delenv(KEY_ENV)
    (workdir / "key.txt").write_text(KEY_B64 + "\n")
    code, _, _ = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst", "--key-file", "key.txt", "-o", "out.csv")
    assert code == 0


def test_apply_low_cardinality_is_clean_error(workdir, capsys):
    cat = Catalog.load("catalog.yaml")
    cat.decide("gender", "email", by="alice")
    cat.save("catalog.yaml")
    code, out, err = run(capsys, "apply", "data.csv", *POLICY_ARGS, "--role", "analyst")
    assert code == 1
    assert "colgov: error: column 'gender' has 2 distinct values" in err
    assert out == ""


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
        tok.tokenize("user0@example.com", column="customer_email") + "\n\n"
        + tok.tokenize("user1@example.com", column="customer_email") + "\n"
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
    args = argparse.Namespace(data="data.csv", catalog=catalog, by=by, pack="core", sample_size=1000)
    feed = iter(answers)

    def ask(prompt):
        try:
            return next(feed)
        except StopIteration:
            raise EOFError

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
