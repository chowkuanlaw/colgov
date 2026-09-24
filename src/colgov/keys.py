"""Loading master keys: plain base64, environment, files, and AWS KMS.

A *key spec* is a one-line string naming where a master key comes from:

``<base64>``
    The key itself, base64-encoded (what ``colgov keygen`` prints).
``aws-kms:<base64 ciphertext blob>``
    A data key encrypted under an AWS KMS key (envelope encryption). The
    plaintext key is fetched with ``kms:Decrypt`` when loaded and never
    stored. Create one with :func:`generate_aws_kms_key` or
    ``colgov keygen --aws-kms-key-id ...``. Needs ``pip install "colgov[aws]"``.

A *keyring spec* is several key specs, one per line (or separated by
commas): the first is the primary key, the rest are older keys kept for
reading existing tokens. Blank lines and ``#`` comments are ignored.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from colgov.tokenization import MIN_MASTER_KEY_BYTES, Keyring

__all__ = [
    "KeySpecError",
    "generate_aws_kms_key",
    "load_key",
    "load_keyring",
]

AWS_KMS_PREFIX = "aws-kms:"
# Bound into every KMS call, so a blob made for colgov can't be decrypted
# as something else (and vice versa) without the caller noticing.
AWS_KMS_ENCRYPTION_CONTEXT = {"purpose": "colgov-master-key"}


class KeySpecError(ValueError):
    """A key spec is malformed or could not be resolved."""


def load_key(spec: str, *, kms_client: Any = None) -> bytes:
    """Resolve one key spec to master key bytes."""
    spec = spec.strip()
    if not spec:
        raise KeySpecError("empty key spec")
    if spec.startswith(AWS_KMS_PREFIX):
        return _decrypt_aws_kms(_b64(spec[len(AWS_KMS_PREFIX) :], "aws-kms blob"), kms_client)
    key = _b64(spec, "key")
    if len(key) < MIN_MASTER_KEY_BYTES:
        raise KeySpecError(f"key is {len(key)} bytes; at least {MIN_MASTER_KEY_BYTES} are required")
    return key


def load_keyring(text: str, *, kms_client: Any = None) -> Keyring:
    """Resolve a keyring spec: primary key first, then older keys."""
    specs = [
        part.strip()
        for line in text.splitlines()
        if not line.strip().startswith("#")
        for part in line.split(",")
        if part.strip()
    ]
    if not specs:
        raise KeySpecError("no keys found")
    keys = [load_key(s, kms_client=kms_client) for s in specs]
    try:
        return Keyring(keys[0], previous=keys[1:])
    except ValueError as exc:
        raise KeySpecError(str(exc)) from exc


def generate_aws_kms_key(kms_key_id: str, *, kms_client: Any = None) -> tuple[bytes, str]:
    """Create a new master key protected by an AWS KMS key.

    Returns ``(key, spec)``: use ``key`` now if you need it, and store
    ``spec`` (``aws-kms:...``). The spec is safe to keep in config; it is
    useless without ``kms:Decrypt`` on ``kms_key_id``.
    """
    client = kms_client or _kms_client()
    response = client.generate_data_key(
        KeyId=kms_key_id,
        NumberOfBytes=MIN_MASTER_KEY_BYTES,
        EncryptionContext=AWS_KMS_ENCRYPTION_CONTEXT,
    )
    blob = base64.b64encode(response["CiphertextBlob"]).decode("ascii")
    return response["Plaintext"], AWS_KMS_PREFIX + blob


def _decrypt_aws_kms(blob: bytes, kms_client: Any) -> bytes:
    client = kms_client or _kms_client()
    try:
        response = client.decrypt(CiphertextBlob=blob, EncryptionContext=AWS_KMS_ENCRYPTION_CONTEXT)
    except Exception as exc:  # botocore raises many client error types
        raise KeySpecError(f"AWS KMS could not decrypt the key: {exc}") from exc
    key: bytes = response["Plaintext"]
    if len(key) < MIN_MASTER_KEY_BYTES:
        raise KeySpecError(f"AWS KMS returned a {len(key)}-byte key; at least {MIN_MASTER_KEY_BYTES} are required")
    return key


def _kms_client() -> Any:
    try:
        import boto3
    except ImportError as exc:
        raise KeySpecError('AWS KMS keys need boto3: pip install "colgov[aws]"') from exc
    return boto3.client("kms")


def _b64(text: str, what: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise KeySpecError(f"{what} is not valid base64") from None
