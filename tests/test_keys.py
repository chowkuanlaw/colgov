import base64
import pickle

import pytest

from colgov import InvalidToken, Keyring, KeySpecError, Tokenizer, load_key, load_keyring

OLD = bytes(range(32))
NEW = bytes(range(1, 33))


def b64(key: bytes) -> str:
    return base64.b64encode(key).decode()


# --- Keyring ------------------------------------------------------------------


def test_key_id_is_stable_hex():
    kid = Keyring.key_id(OLD)
    assert kid == Keyring.key_id(OLD)
    assert len(kid) == 8 and int(kid, 16) >= 0
    assert kid != Keyring.key_id(NEW)


def test_keyring_ids_primary_first():
    ring = Keyring(NEW, previous=[OLD])
    assert ring.primary_id == Keyring.key_id(NEW)
    assert ring.key_ids == [Keyring.key_id(NEW), Keyring.key_id(OLD)]
    assert len(ring) == 2
    assert "keys=2" in repr(ring)


def test_keyring_ignores_duplicate_keys():
    assert len(Keyring(OLD, previous=[OLD])) == 1


@pytest.mark.parametrize("bad", [b"short", "not-bytes"])
def test_keyring_rejects_bad_keys(bad):
    with pytest.raises((ValueError, TypeError)):
        Keyring(OLD, previous=[bad])


def test_token_header_carries_key_id():
    token = Tokenizer(OLD).tokenize("x", column="c")
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    assert raw[0] == 2
    assert raw[1:5].hex() == Keyring.key_id(OLD)


# --- rotation -----------------------------------------------------------------


def test_rotated_tokenizer_reads_old_tokens_and_writes_new():
    old_token = Tokenizer(OLD).tokenize("ada@example.com", column="email")
    rotated = Tokenizer(Keyring(NEW, previous=[OLD]))
    assert rotated.detokenize(old_token, column="email") == "ada@example.com"
    new_token = rotated.tokenize("ada@example.com", column="email")
    assert new_token != old_token
    assert new_token == Tokenizer(NEW).tokenize("ada@example.com", column="email")


def test_dropped_key_can_no_longer_read():
    old_token = Tokenizer(OLD).tokenize("x", column="c")
    with pytest.raises(InvalidToken):
        Tokenizer(NEW).detokenize(old_token, column="c")


def test_retokenize_and_is_current():
    rotated = Tokenizer(Keyring(NEW, previous=[OLD]))
    old_token = Tokenizer(OLD).tokenize("ada", column="c")
    assert not rotated.is_current(old_token)
    new_token = rotated.retokenize(old_token, column="c")
    assert rotated.is_current(new_token)
    assert rotated.retokenize(new_token, column="c") == new_token
    assert rotated.retokenize(None, column="c") is None
    assert not rotated.is_current("!!!")


def test_retokenize_upgrades_v1_tokens():
    v1 = "dEmr4UrbAT3YC8v2o0S4Uuf_L06ueUs51KdWaw0Y8YQ"  # colgov 0.2, key OLD
    rotated = Tokenizer(Keyring(NEW, previous=[OLD]))
    assert not rotated.is_current(v1)
    upgraded = rotated.retokenize(v1, column="email")
    assert rotated.detokenize(upgraded, column="email") == "ada@example.com"
    assert rotated.is_current(upgraded)


def test_tampered_header_is_rejected():
    tok = Tokenizer(Keyring(NEW, previous=[OLD]))
    token = tok.tokenize("x", column="c")
    raw = bytearray(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
    raw[1:5] = bytes.fromhex(Keyring.key_id(OLD))  # claim the other key
    forged = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    with pytest.raises(InvalidToken):
        tok.detokenize(forged, column="c")


def test_rotated_tokenizer_pickles():
    tok = Tokenizer(Keyring(NEW, previous=[OLD]))
    old_token = Tokenizer(OLD).tokenize("x", column="c")
    clone = pickle.loads(pickle.dumps(tok))
    assert clone.keyring.key_ids == tok.keyring.key_ids
    assert clone.detokenize(old_token, column="c") == "x"
    assert clone.tokenize("x", column="c") == tok.tokenize("x", column="c")


def test_repr_hides_keys():
    text = repr(Tokenizer(Keyring(NEW, previous=[OLD])))
    assert NEW.hex() not in text and b64(NEW) not in text


# --- key specs ------------------------------------------------------------------


def test_load_key_base64():
    assert load_key(b64(OLD)) == OLD
    assert load_key(f"  {b64(OLD)}\n") == OLD


@pytest.mark.parametrize("spec, message", [("", "empty"), ("%%%", "not valid base64"), (b64(b"short"), "at least 32")])
def test_load_key_errors(spec, message):
    with pytest.raises(KeySpecError, match=message):
        load_key(spec)


def test_load_keyring_lines_commas_and_comments():
    text = f"# rotated 2026-09\n{b64(NEW)}\n\n{b64(OLD)}\n"
    ring = load_keyring(text)
    assert ring.key_ids == [Keyring.key_id(NEW), Keyring.key_id(OLD)]
    assert load_keyring(f"{b64(NEW)},{b64(OLD)}").key_ids == ring.key_ids


def test_load_keyring_empty():
    with pytest.raises(KeySpecError, match="no keys"):
        load_keyring("# nothing\n\n")


# --- AWS KMS (via moto) ---------------------------------------------------------


@pytest.fixture
def kms(monkeypatch):
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with moto.mock_aws():
        client = boto3.client("kms")
        key_id = client.create_key()["KeyMetadata"]["KeyId"]
        yield client, key_id


def test_aws_kms_round_trip(kms):
    from colgov.keys import generate_aws_kms_key

    client, key_id = kms
    key, spec = generate_aws_kms_key(key_id, kms_client=client)
    assert spec.startswith("aws-kms:")
    assert len(key) == 32
    assert load_key(spec, kms_client=client) == key
    assert load_key(spec) == key  # default client, same mocked region
    ring = load_keyring(f"{spec}\n{b64(OLD)}", kms_client=client)
    assert ring.primary_id == Keyring.key_id(key)


def test_aws_kms_bad_blob(kms):
    client, _ = kms
    with pytest.raises(KeySpecError, match="AWS KMS could not decrypt"):
        load_key("aws-kms:" + b64(b"not a real ciphertext blob"), kms_client=client)


def test_aws_kms_blob_not_base64():
    with pytest.raises(KeySpecError, match="not valid base64"):
        load_key("aws-kms:%%%")
