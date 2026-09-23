# colgov

**Deterministic, reversible tokenization and fail-closed access policy for tabular PII.**

Tokenize a column and it stays joinable. Same plaintext, same token — every
time, across tables and across runs — so `JOIN`, `GROUP BY` and
`COUNT(DISTINCT)` keep working on data nobody can read.

> **Status: pre-release (`0.1.0.dev0`).** Deterministic tokenization works
> today; the rest of v0.1 is in progress. The API may still change before
> `v0.1.0`.

## The problem

Encrypting a column normally destroys its analytical value. Standard
authenticated encryption uses a random IV, so the same email address becomes
different ciphertext every time it is encrypted — correct for protecting text,
useless for a warehouse:

```python
encrypt("ada@example.com")   # 'Yk2p...'
encrypt("ada@example.com")   # 'Qm9x...'  ← different every call
```

Join two tables on that column and you get zero rows back.

## The approach

`colgov` uses AES-SIV (RFC 5297), a deterministic authenticated encryption
mode. The same input always produces the same token, and the original value is
recoverable with the key:

```python
t.tokenize("ada@example.com", column="email")   # 'dEmr4UrbAT3YC8v2o0S4Uuf_L06ueUs51KdWaw0Y8YQ'
t.tokenize("ada@example.com", column="email")   # 'dEmr4UrbAT3YC8v2o0S4Uuf_L06ueUs51KdWaw0Y8YQ'  ← stable
```

Determinism is a deliberate trade, not a free win: it preserves the frequency
distribution of a column, so low-cardinality fields stay re-identifiable even
once tokenized. `colgov` treats that as a first-class concern and refuses, by
default, to tokenize columns whose cardinality is too low to protect.

## Usage

```bash
pip install "git+https://github.com/chowkuanlaw/colgov"   # until v0.1.0 is on PyPI
```

```python
from colgov import Tokenizer

key = Tokenizer.generate_key()        # 32 random bytes — store it in a KMS / secret manager
t = Tokenizer(key)

token = t.tokenize("ada@example.com", column="email")
t.detokenize(token, column="email")   # 'ada@example.com'

t.tokenize(None, column="email")      # None — NULL stays NULL
```

- **One key per column.** Each column's AES-256-SIV key is derived from the
  master key with HKDF-SHA256, using the column name as context. The same
  value in two different columns gives unrelated tokens, so you can't join
  tables on a column the policy didn't mean to link.
- **Tokens are URL- and SQL-safe.** They use unpadded base64url (`A–Z a–z 0–9 - _`).
- **Tampering is detected.** `detokenize` raises `colgov.InvalidToken` when a
  token was changed or was made with a different key or column.
- **Lose the master key and the tokens can't be reversed.** Anyone who has
  the key can reverse every token.

## Planned for v0.1

- [x] Deterministic reversible tokenization with per-column key derivation (HKDF)
- [ ] Column classification from portable YAML rule packs
- [ ] Human review workflow — a machine suggests, a person decides
- [ ] Fail-closed policy resolution: an unclassified column is never visible
- [ ] Re-identification risk scoring (cardinality, k-anonymity)

## Scope

`colgov` governs **columns in tabular data**. It does not detect PII inside
free-text prose — for that, use
[Presidio](https://github.com/data-privacy-stack/presidio), which is excellent
at it. An optional bridge is planned so Presidio can act as a value-shape
detector feeding `colgov`'s classification.

## License

Apache-2.0
