# colgov

**Deterministic, reversible tokenization and fail-closed access policy for tabular PII.**

Tokenize a column and it stays joinable. Same plaintext, same token — every
time, across tables and across runs — so `JOIN`, `GROUP BY` and
`COUNT(DISTINCT)` keep working on data nobody can read.

> **Status: placeholder.** Version `0.0.1` reserves the name while the first
> release is built. There is no working API yet. Watch the repository for
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
tokenize("ada@example.com")   # 'Ik9dLm2pQx7vRn4tYw8sBa=='
tokenize("ada@example.com")   # 'Ik9dLm2pQx7vRn4tYw8sBa=='  ← stable
```

Determinism is a deliberate trade, not a free win: it preserves the frequency
distribution of a column, so low-cardinality fields stay re-identifiable even
once tokenized. `colgov` treats that as a first-class concern and refuses, by
default, to tokenize columns whose cardinality is too low to protect.

## Planned for v0.1

- Deterministic reversible tokenization with per-column key derivation (HKDF)
- Column classification from portable YAML rule packs
- Human review workflow — a machine suggests, a person decides
- Fail-closed policy resolution: an unclassified column is never visible
- Re-identification risk scoring (cardinality, k-anonymity)

## Scope

`colgov` governs **columns in tabular data**. It does not detect PII inside
free-text prose — for that, use
[Presidio](https://github.com/data-privacy-stack/presidio), which is excellent
at it. An optional bridge is planned so Presidio can act as a value-shape
detector feeding `colgov`'s classification.

## License

Apache-2.0
