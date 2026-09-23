"""Deterministic, reversible column tokenization with AES-SIV (RFC 5297).

Each column gets its own AES-256-SIV key, derived from a single master key
with HKDF-SHA256. The same plaintext in the same column always produces the
same token, so joins and aggregates keep working on tokenized data, while the
same plaintext in two different columns produces unrelated tokens.
"""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ["InvalidToken", "Tokenizer", "MIN_MASTER_KEY_BYTES"]

MIN_MASTER_KEY_BYTES = 32
"""Smallest master key accepted, in bytes (256 bits)."""

# AES-256-SIV takes a 512-bit key: one half for S2V, one half for CTR.
_COLUMN_KEY_BYTES = 64

# Prepended to the plaintext before encryption. It versions the token format
# under authentication, and makes the empty string encryptable (AES-SIV
# rejects zero-length input).
_FORMAT_V1 = b"\x01"

_HKDF_INFO_PREFIX = b"colgov/v1/column-key/"


class InvalidToken(ValueError):
    """A token could not be detokenized.

    Raised when the token is malformed, was tampered with, or was produced
    under a different master key or for a different column.
    """


class Tokenizer:
    """Tokenizes and detokenizes string values, one key per column.

    >>> key = Tokenizer.generate_key()
    >>> t = Tokenizer(key)
    >>> tok = t.tokenize("ada@example.com", column="email")
    >>> tok == t.tokenize("ada@example.com", column="email")
    True
    >>> t.detokenize(tok, column="email")
    'ada@example.com'

    ``None`` passes through unchanged in both directions, so SQL ``NULL``
    stays ``NULL``.
    """

    def __init__(self, master_key: bytes) -> None:
        if not isinstance(master_key, (bytes, bytearray)):
            raise TypeError("master_key must be bytes")
        if len(master_key) < MIN_MASTER_KEY_BYTES:
            raise ValueError(
                f"master_key must be at least {MIN_MASTER_KEY_BYTES} bytes, "
                f"got {len(master_key)}"
            )
        self._master_key = bytes(master_key)
        self._ciphers: dict[str, AESSIV] = {}

    @staticmethod
    def generate_key() -> bytes:
        """Return a new random master key from the OS CSPRNG."""
        return os.urandom(MIN_MASTER_KEY_BYTES)

    def tokenize(self, value: str | None, *, column: str) -> str | None:
        """Return the deterministic token for ``value`` in ``column``."""
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError(f"value must be str or None, got {type(value).__name__}")
        ciphertext = self._cipher(column).encrypt(_FORMAT_V1 + value.encode("utf-8"), None)
        return base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii")

    def detokenize(self, token: str | None, *, column: str) -> str | None:
        """Recover the plaintext of a token produced by :meth:`tokenize`."""
        if token is None:
            return None
        if not isinstance(token, str):
            raise TypeError(f"token must be str or None, got {type(token).__name__}")
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        except (binascii.Error, ValueError) as exc:
            raise InvalidToken("token is not valid base64") from exc
        try:
            plaintext = self._cipher(column).decrypt(raw, None)
        except (InvalidTag, ValueError) as exc:
            raise InvalidToken(
                "token failed authentication for this column and key"
            ) from exc
        if not plaintext.startswith(_FORMAT_V1):
            raise InvalidToken("unsupported token format")
        return plaintext[len(_FORMAT_V1):].decode("utf-8")

    def _cipher(self, column: str) -> AESSIV:
        if not isinstance(column, str) or not column:
            raise ValueError("column must be a non-empty str")
        cipher = self._ciphers.get(column)
        if cipher is None:
            cipher = AESSIV(self._derive_column_key(column))
            self._ciphers[column] = cipher
        return cipher

    def _derive_column_key(self, column: str) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=_COLUMN_KEY_BYTES,
            salt=None,
            info=_HKDF_INFO_PREFIX + column.encode("utf-8"),
        ).derive(self._master_key)
