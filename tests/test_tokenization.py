import pytest

from colgov import MIN_MASTER_KEY_BYTES, InvalidToken, Tokenizer

KEY = bytes(range(32))


@pytest.fixture
def tok() -> Tokenizer:
    return Tokenizer(KEY)


def test_same_value_same_column_gives_same_token(tok):
    assert tok.tokenize("ada@example.com", column="email") == tok.tokenize(
        "ada@example.com", column="email"
    )


def test_tokens_stable_across_instances():
    a = Tokenizer(KEY).tokenize("ada@example.com", column="email")
    b = Tokenizer(KEY).tokenize("ada@example.com", column="email")
    assert a == b


def test_known_answer_vectors(tok):
    # Pins the token format: HKDF info label, AES-SIV, v1 header, base64url.
    # If this fails, previously stored tokens would no longer join.
    assert tok.tokenize("ada@example.com", column="email") == (
        "dEmr4UrbAT3YC8v2o0S4Uuf_L06ueUs51KdWaw0Y8YQ"
    )
    assert tok.tokenize("", column="email") == "CSkCe6Fq2YiboG1Blv4dhrw"


@pytest.mark.parametrize(
    "value", ["ada@example.com", "", " ", "Zoë Ñúñez", "李小龍", "a" * 10_000, "x\x00y"]
)
def test_round_trip(tok, value):
    token = tok.tokenize(value, column="name")
    assert tok.detokenize(token, column="name") == value


def test_different_values_give_different_tokens(tok):
    assert tok.tokenize("a", column="c") != tok.tokenize("b", column="c")


def test_same_value_different_columns_give_unrelated_tokens(tok):
    assert tok.tokenize("12345", column="phone") != tok.tokenize("12345", column="postcode")


def test_different_master_keys_give_different_tokens():
    other = Tokenizer(bytes(32))
    assert Tokenizer(KEY).tokenize("x", column="c") != other.tokenize("x", column="c")


def test_token_is_url_and_sql_safe(tok):
    token = tok.tokenize("ada@example.com?&=/+", column="email")
    assert set(token) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )


def test_none_passes_through(tok):
    assert tok.tokenize(None, column="email") is None
    assert tok.detokenize(None, column="email") is None


def test_detokenize_with_wrong_column_fails(tok):
    token = tok.tokenize("ada@example.com", column="email")
    with pytest.raises(InvalidToken):
        tok.detokenize(token, column="phone")


def test_detokenize_with_wrong_key_fails(tok):
    token = tok.tokenize("ada@example.com", column="email")
    with pytest.raises(InvalidToken):
        Tokenizer(bytes(32)).detokenize(token, column="email")


def test_tampered_token_fails(tok):
    token = tok.tokenize("ada@example.com", column="email")
    flipped = ("A" if token[5] != "A" else "B")
    tampered = token[:5] + flipped + token[6:]
    with pytest.raises(InvalidToken):
        tok.detokenize(tampered, column="email")


@pytest.mark.parametrize("bad", ["", "!!!", "abc", "A" * 10])
def test_malformed_token_fails(tok, bad):
    with pytest.raises(InvalidToken):
        tok.detokenize(bad, column="email")


def test_invalid_token_is_a_value_error():
    assert issubclass(InvalidToken, ValueError)


def test_short_master_key_rejected():
    with pytest.raises(ValueError):
        Tokenizer(b"\x00" * (MIN_MASTER_KEY_BYTES - 1))


def test_master_key_must_be_bytes():
    with pytest.raises(TypeError):
        Tokenizer("not-bytes" * 8)  # type: ignore[arg-type]


def test_longer_master_key_accepted():
    Tokenizer(b"\x01" * 64).tokenize("x", column="c")


def test_generate_key():
    k1, k2 = Tokenizer.generate_key(), Tokenizer.generate_key()
    assert len(k1) == MIN_MASTER_KEY_BYTES
    assert k1 != k2


@pytest.mark.parametrize("value", [123, 1.5, b"bytes"])
def test_non_string_values_rejected(tok, value):
    with pytest.raises(TypeError):
        tok.tokenize(value, column="c")  # type: ignore[arg-type]


@pytest.mark.parametrize("column", ["", None, 1])
def test_invalid_column_rejected(tok, column):
    with pytest.raises(ValueError):
        tok.tokenize("x", column=column)  # type: ignore[arg-type]
