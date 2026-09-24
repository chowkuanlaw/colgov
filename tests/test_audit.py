import json

import pytest

from colgov import (
    PUBLIC,
    AccessDenied,
    AuditEvent,
    AuditLogError,
    Catalog,
    InvalidToken,
    JsonlAuditLog,
    LowCardinalityError,
    MemoryAuditLog,
    Policy,
    PolicyError,
    Tokenizer,
    verify_audit_log,
)

KEY = bytes(range(32))


def _event(**overrides):
    fields = dict(
        actor="alice",
        role="support",
        action="detokenize",
        outcome="allowed",
        columns=("email",),
        reason="ok",
        purpose="TICKET-1",
        count=1,
    )
    fields.update(overrides)
    return AuditEvent(**fields)


# --- JsonlAuditLog ------------------------------------------------------------


def test_jsonl_log_chains_and_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = JsonlAuditLog(path)
    log.record(_event())
    log.record(_event(outcome="denied"))
    assert verify_audit_log(path) == 2

    first, second = (json.loads(line) for line in path.read_text().splitlines())
    assert first["prev"] == "0" * 64
    assert second["prev"] == first["hash"]
    assert first["actor"] == "alice" and first["purpose"] == "TICKET-1"


def test_jsonl_log_resumes_chain_across_instances(tmp_path):
    path = tmp_path / "audit.jsonl"
    JsonlAuditLog(path).record(_event())
    JsonlAuditLog(path).record(_event())
    JsonlAuditLog(path).record(_event())
    assert verify_audit_log(path) == 3


def test_empty_log_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    assert verify_audit_log(path) == 0
    JsonlAuditLog(path).record(_event())
    assert verify_audit_log(path) == 1


def _three_line_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = JsonlAuditLog(path)
    for actor in ("a", "b", "c"):
        log.record(_event(actor=actor))
    return path, path.read_text().splitlines()


def test_modified_line_detected(tmp_path):
    path, lines = _three_line_log(tmp_path)
    lines[1] = lines[1].replace('"b"', '"mallory"')
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditLogError, match="line 2: hash mismatch"):
        verify_audit_log(path)


def test_deleted_line_detected(tmp_path):
    path, lines = _three_line_log(tmp_path)
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    with pytest.raises(AuditLogError, match="line 2: chain broken"):
        verify_audit_log(path)


def test_reordered_lines_detected(tmp_path):
    path, lines = _three_line_log(tmp_path)
    path.write_text("\n".join([lines[1], lines[0], lines[2]]) + "\n")
    with pytest.raises(AuditLogError, match="line 1: chain broken"):
        verify_audit_log(path)


@pytest.mark.parametrize(
    "content, message",
    [("not json\n", "not valid JSON"), ("{}\n", "missing hash chain"), ("\n", "blank line")],
)
def test_malformed_log_detected(tmp_path, content, message):
    path = tmp_path / "audit.jsonl"
    path.write_text(content)
    with pytest.raises(AuditLogError, match=message):
        verify_audit_log(path)


def test_refuses_to_append_to_corrupt_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"partial": ')
    with pytest.raises(AuditLogError, match="incomplete"):
        JsonlAuditLog(path)
    path.write_text("garbage\n")
    with pytest.raises(AuditLogError, match="not a valid audit entry"):
        JsonlAuditLog(path)


def test_events_never_contain_data(tmp_path):
    tok = Tokenizer(KEY)
    token = tok.tokenize("ada@example.com", column="email")
    policy, catalog = _setup()
    path = tmp_path / "audit.jsonl"
    policy.detokenize(
        [token], column="email", role="support", catalog=catalog, tokenizer=tok,
        actor="alice", purpose="TICKET-1", audit=JsonlAuditLog(path),
    )
    text = path.read_text()
    assert "ada@example.com" not in text
    assert token not in text


# --- Policy.detokenize ----------------------------------------------------------


def _setup():
    policy = Policy({"support": {"email": "clear"}, "analyst": {"email": "tokenize"}})
    catalog = Catalog()
    catalog.decide("email", "email", by="reviewer")
    catalog.decide("amount", PUBLIC, by="reviewer")
    return policy, catalog


def _detok(tokens, role="support", column="email", audit=None, **overrides):
    policy, catalog = _setup()
    kwargs = dict(
        column=column, role=role, catalog=catalog, tokenizer=Tokenizer(KEY),
        actor="alice", purpose="TICKET-1", audit=audit if audit is not None else MemoryAuditLog(),
    )
    kwargs.update(overrides)
    return policy.detokenize(tokens, **kwargs)


def test_detokenize_allowed_for_clear_role():
    tok = Tokenizer(KEY)
    tokens = [tok.tokenize("a@x.com", column="email"), None]
    audit = MemoryAuditLog()
    assert _detok(iter(tokens), audit=audit) == ["a@x.com", None]
    [event] = audit.events
    assert (event.outcome, event.action, event.count) == ("allowed", "detokenize", 2)
    assert (event.actor, event.role, event.columns, event.purpose) == (
        "alice", "support", ("email",), "TICKET-1",
    )


@pytest.mark.parametrize(
    "role, column, reason",
    [
        ("analyst", "email", "grants tokenize"),
        ("intern", "email", "unknown role"),
        ("support", "notes", "not been reviewed"),
    ],
)
def test_detokenize_denied_and_audited(role, column, reason):
    audit = MemoryAuditLog()
    with pytest.raises(AccessDenied, match=reason):
        _detok(["x"], role=role, column=column, audit=audit)
    [event] = audit.events
    assert event.outcome == "denied"
    assert reason in event.reason
    assert event.count == 0


def test_access_denied_is_a_policy_error():
    assert issubclass(AccessDenied, PolicyError)


def test_detokenize_bad_token_is_audited_as_error():
    audit = MemoryAuditLog()
    with pytest.raises(InvalidToken):
        _detok(["not-a-token"], audit=audit)
    assert [e.outcome for e in audit.events] == ["error"]


@pytest.mark.parametrize("field", ["actor", "purpose"])
@pytest.mark.parametrize("value", ["", "  ", None])
def test_detokenize_needs_actor_and_purpose(field, value):
    audit = MemoryAuditLog()
    with pytest.raises(PolicyError, match=field):
        _detok(["x"], audit=audit, **{field: value})
    assert audit.events == []


def test_detokenize_withholds_plaintext_if_audit_fails():
    class BrokenLog:
        def record(self, event):
            raise OSError("disk full")

    tok = Tokenizer(KEY)
    with pytest.raises(OSError):
        _detok([tok.tokenize("a@x.com", column="email")], audit=BrokenLog())


# --- Policy.apply with audit ------------------------------------------------------


def test_apply_records_view():
    policy, catalog = _setup()
    audit = MemoryAuditLog()
    table = {"email": [f"u{i}@x.com" for i in range(12)], "amount": ["1"] * 12, "notes": ["n"] * 12}
    view = policy.apply(table, role="analyst", catalog=catalog, tokenizer=Tokenizer(KEY), audit=audit, actor="bob")
    assert list(view) == ["email", "amount"]
    [event] = audit.events
    assert (event.action, event.outcome, event.actor, event.count) == ("view", "allowed", "bob", 12)
    assert event.columns == ("email", "amount")
    assert event.reason == "clear: amount; tokenize: email; deny: notes"


def test_apply_records_failures():
    policy, catalog = _setup()
    audit = MemoryAuditLog()
    with pytest.raises(LowCardinalityError):
        policy.apply({"email": ["a", "b"]}, role="analyst", catalog=catalog,
                     tokenizer=Tokenizer(KEY), audit=audit, actor="bob")
    assert [e.outcome for e in audit.events] == ["error"]


def test_apply_with_audit_needs_actor():
    policy, catalog = _setup()
    with pytest.raises(PolicyError, match="actor"):
        policy.apply({}, role="analyst", catalog=catalog, audit=MemoryAuditLog())


def test_apply_without_audit_unchanged():
    policy, catalog = _setup()
    assert policy.apply({"amount": ["1"]}, role="analyst", catalog=catalog) == {"amount": ["1"]}


# --- Tokenizer pickling (needed for Spark executors) -------------------------------


def test_tokenizer_pickles_without_cipher_cache():
    import pickle

    tok = Tokenizer(KEY)
    token = tok.tokenize("x", column="c")  # populates the cache
    clone = pickle.loads(pickle.dumps(tok))
    assert clone.tokenize("x", column="c") == token
    assert "master key hidden" in repr(tok)
    assert KEY.hex() not in repr(tok)
