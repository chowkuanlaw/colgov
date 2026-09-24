"""Deterministic, reversible column tokenization with AES-SIV (RFC 5297).

Each column (more precisely, each *token domain*, usually the column name)
gets its own AES-256-SIV key, derived from a master key with HKDF-SHA256.
The same plaintext in the same domain always produces the same token, so
joins and aggregates keep working on tokenized data, while the same
plaintext in two different domains produces unrelated tokens.

Token format (v2)::

    base64url( 0x02 || key_id[4] || AES-SIV(domain_key, 0x00 || utf8(value), ad=header) )

``key_id`` identifies the master key that made the token, so keys can be
rotated: a :class:`Keyring` tokenizes with its primary key and still reads
tokens made with older keys. The header is authenticated, so it cannot be
altered without detection. Tokens from colgov 0.1-0.2 (format v1, no
header) are still accepted by :meth:`Tokenizer.detokenize`; convert them
with :meth:`Tokenizer.retokenize`.
"""

from __future__ import annotations

import base64
import binascii
import os
from collections.abc import Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from colgov.risk import DEFAULT_MIN_DISTINCT, LowCardinalityError, column_risk

__all__ = ["MIN_MASTER_KEY_BYTES", "InvalidToken", "Keyring", "Tokenizer"]

MIN_MASTER_KEY_BYTES = 32
"""Smallest master key accepted, in bytes (256 bits)."""

# AES-256-SIV takes a 512-bit key: one half for S2V, one half for CTR.
_DOMAIN_KEY_BYTES = 64
_KEY_ID_BYTES = 4
_SIV_TAG_BYTES = 16

_V2 = b"\x02"
_V2_HEADER_BYTES = 1 + _KEY_ID_BYTES
# AES-SIV rejects zero-length plaintext; a constant pad byte makes "" valid.
_V2_PAD = b"\x00"
_V2_HKDF_INFO = b"colgov/v2/domain-key/"
_KEY_ID_HKDF_INFO = b"colgov/v2/key-id"

# Format v1 (colgov 0.1-0.2): no header; 0x01 prefixed inside the ciphertext.
_V1_MARKER = b"\x01"
_V1_HKDF_INFO = b"colgov/v1/column-key/"


class InvalidToken(ValueError):
    """A token could not be detokenized.

    Raised when the token is malformed, was tampered with, or was produced
    under a key not in the keyring or for a different column.
    """


def _hkdf(key: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(key)


def _check_key(key: object) -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("master keys must be bytes")
    if len(key) < MIN_MASTER_KEY_BYTES:
        raise ValueError(f"master keys must be at least {MIN_MASTER_KEY_BYTES} bytes, got {len(key)}")
    return bytes(key)


class Keyring:
    """A primary master key plus older keys that can still read tokens.

    >>> old, new = Tokenizer.generate_key(), Tokenizer.generate_key()
    >>> ring = Keyring(new, previous=[old])
    >>> ring.primary_id == Keyring.key_id(new)
    True

    Rotate by making a new key primary and moving the old one to
    ``previous``. Tokens are per key: after rotation the same value gets a
    new token, so migrate stored tokens with :meth:`Tokenizer.retokenize`
    before joining old data with new.
    """

    def __init__(self, primary: bytes, *, previous: Iterable[bytes] = ()) -> None:
        keys = [_check_key(primary), *(_check_key(k) for k in previous)]
        self._keys: dict[bytes, bytes] = {}
        for key in keys:
            kid = self._raw_id(key)
            existing = self._keys.get(kid)
            if existing is not None and existing != key:
                raise ValueError("two different keys share a key id; generate a new key")
            self._keys.setdefault(kid, key)
        self._primary = keys[0]
        self._primary_raw_id = self._raw_id(self._primary)

    @staticmethod
    def _raw_id(key: bytes) -> bytes:
        return _hkdf(key, _KEY_ID_HKDF_INFO, _KEY_ID_BYTES)

    @classmethod
    def key_id(cls, key: bytes) -> str:
        """The public identifier of a master key, as 8 hex characters.

        Derived from the key one-way; safe to log and store.
        """
        return cls._raw_id(_check_key(key)).hex()

    @property
    def primary_id(self) -> str:
        return self._primary_raw_id.hex()

    @property
    def key_ids(self) -> list[str]:
        """All key ids, primary first."""
        return [kid.hex() for kid in self._keys]

    def __len__(self) -> int:
        return len(self._keys)

    def __repr__(self) -> str:
        return f"Keyring(primary={self.primary_id}, keys={len(self)})"


class Tokenizer:
    """Tokenizes and detokenizes string values, one key per token domain.

    >>> key = Tokenizer.generate_key()
    >>> t = Tokenizer(key)
    >>> tok = t.tokenize("ada@example.com", column="email")
    >>> tok == t.tokenize("ada@example.com", column="email")
    True
    >>> t.detokenize(tok, column="email")
    'ada@example.com'

    ``column`` names the token domain: values tokenized under the same
    domain and key can be joined. ``None`` passes through unchanged in both
    directions, so SQL ``NULL`` stays ``NULL``.

    Pass a :class:`Keyring` instead of a key to rotate keys.
    """

    def __init__(self, key: bytes | Keyring) -> None:
        self._keyring = key if isinstance(key, Keyring) else Keyring(key)
        self._v2: dict[tuple[bytes, str], AESSIV] = {}
        self._v1: dict[tuple[bytes, str], AESSIV] = {}

    def __getstate__(self) -> dict[str, list[bytes]]:
        # Cipher objects don't pickle; rebuild them lazily after unpickling
        # (e.g. on Spark executors).
        ring = self._keyring
        previous = [k for k in ring._keys.values() if k != ring._primary]
        return {"keys": [ring._primary, *previous]}

    def __setstate__(self, state: dict[str, list[bytes]]) -> None:
        primary, *previous = state["keys"]
        self._keyring = Keyring(primary, previous=previous)
        self._v2 = {}
        self._v1 = {}

    def __repr__(self) -> str:
        return f"Tokenizer(<key {self._keyring.primary_id}; master keys hidden>)"

    @property
    def keyring(self) -> Keyring:
        return self._keyring

    @staticmethod
    def generate_key() -> bytes:
        """Return a new random master key from the OS CSPRNG."""
        return os.urandom(MIN_MASTER_KEY_BYTES)

    # --- tokenizing ---------------------------------------------------------

    def tokenize(self, value: str | None, *, column: str) -> str | None:
        """Return the deterministic token for ``value`` in ``column``."""
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError(f"value must be str or None, got {type(value).__name__}")
        ring = self._keyring
        header = _V2 + ring._primary_raw_id
        cipher = self._v2_cipher(ring._primary_raw_id, column)
        body = cipher.encrypt(_V2_PAD + value.encode("utf-8"), [header])
        return base64.urlsafe_b64encode(header + body).rstrip(b"=").decode("ascii")

    def tokenize_many(self, values: Iterable[str | None], *, column: str) -> list[str | None]:
        """Tokenize many values in one domain; faster than calling :meth:`tokenize` in a loop.

        Same result as ``[tokenize(v, column=column) for v in values]``, with
        no cardinality check (see :meth:`tokenize_column`).
        """
        ring = self._keyring
        header = _V2 + ring._primary_raw_id
        encrypt = self._v2_cipher(ring._primary_raw_id, column).encrypt
        ad = [header]
        b64 = base64.urlsafe_b64encode
        out: list[str | None] = []
        for value in values:
            if value is None:
                out.append(None)
            elif isinstance(value, str):
                out.append(b64(header + encrypt(_V2_PAD + value.encode("utf-8"), ad)).rstrip(b"=").decode("ascii"))
            else:
                raise TypeError(f"value must be str or None, got {type(value).__name__}")
        return out

    def tokenize_column(
        self,
        values: Iterable[str | None],
        *,
        column: str,
        min_distinct: int = DEFAULT_MIN_DISTINCT,
        allow_low_cardinality: bool = False,
    ) -> list[str | None]:
        """Tokenize a whole column, refusing if it is too predictable.

        Raises :class:`~colgov.LowCardinalityError` when the column has fewer
        than ``min_distinct`` distinct non-null values, unless
        ``allow_low_cardinality`` is set. Nothing is tokenized on refusal.
        """
        values = list(values)
        if not allow_low_cardinality:
            risk = column_risk(values)
            if risk.is_low_cardinality(min_distinct):
                raise LowCardinalityError(column, risk, min_distinct)
        return self.tokenize_many(values, column=column)

    # --- detokenizing -------------------------------------------------------

    def detokenize(self, token: str | None, *, column: str) -> str | None:
        """Recover the plaintext of a token made with any key in the keyring.

        Accepts current (v2) tokens and tokens from colgov 0.1-0.2 (v1).
        """
        if token is None:
            return None
        raw = self._decode(token)
        self._check_column(column)
        if self._looks_v2(raw):
            plaintext = self._try_v2(raw, column)
            if plaintext is not None:
                return plaintext
        plaintext = self._try_v1(raw, column)
        if plaintext is not None:
            return plaintext
        raise InvalidToken("token failed authentication for this column and keyring")

    def retokenize(self, token: str | None, *, column: str) -> str | None:
        """Re-issue ``token`` under the primary key and current format.

        Use it to migrate stored tokens after rotating keys or upgrading
        from colgov 0.1-0.2. Returns the token unchanged if it is already
        current.
        """
        if token is None or self.is_current(token):
            return token
        return self.tokenize(self.detokenize(token, column=column), column=column)

    def is_current(self, token: str) -> bool:
        """True if ``token`` was made with the primary key in the current format.

        Checks the header only (no decryption), so it is cheap enough to use
        in migration queries. A tampered token can still pass; detokenize
        authenticates it fully.
        """
        try:
            raw = self._decode(token)
        except InvalidToken:
            return False
        return self._looks_v2(raw) and raw[1:_V2_HEADER_BYTES] == self._keyring._primary_raw_id

    # --- internals ----------------------------------------------------------

    @staticmethod
    def _decode(token: str) -> bytes:
        if not isinstance(token, str):
            raise TypeError(f"token must be str or None, got {type(token).__name__}")
        try:
            return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        except (binascii.Error, ValueError) as exc:
            raise InvalidToken("token is not valid base64") from exc

    @staticmethod
    def _looks_v2(raw: bytes) -> bool:
        return len(raw) >= _V2_HEADER_BYTES + _SIV_TAG_BYTES + len(_V2_PAD) and raw[:1] == _V2

    def _try_v2(self, raw: bytes, column: str) -> str | None:
        kid = raw[1:_V2_HEADER_BYTES]
        if kid not in self._keyring._keys:
            return None
        try:
            plaintext = self._v2_cipher(kid, column).decrypt(raw[_V2_HEADER_BYTES:], [raw[:_V2_HEADER_BYTES]])
        except (InvalidTag, ValueError):
            return None
        if not plaintext.startswith(_V2_PAD):
            return None
        return plaintext[len(_V2_PAD) :].decode("utf-8")

    def _try_v1(self, raw: bytes, column: str) -> str | None:
        # v1 tokens don't name their key, so try each key in turn.
        for kid in self._keyring._keys:
            try:
                plaintext = self._v1_cipher(kid, column).decrypt(raw, None)
            except (InvalidTag, ValueError):
                continue
            if plaintext.startswith(_V1_MARKER):
                return plaintext[len(_V1_MARKER) :].decode("utf-8")
        return None

    @staticmethod
    def _check_column(column: object) -> None:
        if not isinstance(column, str) or not column:
            raise ValueError("column must be a non-empty str")

    def _v2_cipher(self, kid: bytes, column: str) -> AESSIV:
        self._check_column(column)
        cipher = self._v2.get((kid, column))
        if cipher is None:
            key = self._keyring._keys[kid]
            cipher = AESSIV(_hkdf(key, _V2_HKDF_INFO + column.encode("utf-8"), _DOMAIN_KEY_BYTES))
            self._v2[(kid, column)] = cipher
        return cipher

    def _v1_cipher(self, kid: bytes, column: str) -> AESSIV:
        cipher = self._v1.get((kid, column))
        if cipher is None:
            key = self._keyring._keys[kid]
            cipher = AESSIV(_hkdf(key, _V1_HKDF_INFO + column.encode("utf-8"), _DOMAIN_KEY_BYTES))
            self._v1[(kid, column)] = cipher
        return cipher
