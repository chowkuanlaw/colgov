# Changelog

## Unreleased

### Added

- **Security documentation:**
  - `SECURITY.md`, covering private vulnerability reporting
  - a threat model (`docs/threat-model.md`) setting out guarantees, known
    limitations and the cryptographic details
  - an API stability policy (`docs/stability.md`)
- **Documentation site** built with MkDocs and mkdocstrings, published to
  GitHub Pages by the new `Docs` workflow.
- **Stricter CI:**
  - `ruff` linting and format checks
  - `mypy --strict` over the package
  - the docs site built with `--strict`
- **New extras:** `dev` and `docs`.

### Changed

- **Code formatted with `ruff format`.**
- **Mismatched column lengths are now an error.** Internal `zip` calls use
  `strict=True`, so columns of different lengths raise instead of being
  silently cut short.

## 0.3.0 — unreleased

Stored tokens and policies need a small migration. See **Upgrading from
0.2** below.

### Breaking

- **Token format v2.** Tokens now carry a key ID (`0x02 || key_id ||
  AES-SIV(...)`), so the same value tokenizes differently from 0.2. Tokens
  from 0.1–0.2 are still accepted by `detokenize`; re-issue them with
  `Tokenizer.retokenize` or `colgov retokenize`.
- **Detokenizing needs an explicit grant.** Use `{view: ..., detokenize:
  true}`. Seeing a column in `clear` no longer implies it.
- **Renamed argument.** `Policy.apply`'s first argument is now `data`, and
  `table=` names the catalog table.
- **Catalog file version 2.** Catalogs are written as `version: 2`, which
  colgov 0.2 cannot read. Version 1 files still load.

### Added

- **`Keyring`:** a primary key plus older keys for reading. Also
  `Keyring.key_id`, `Tokenizer.retokenize` and `Tokenizer.is_current`.
- **`colgov.keys`:** `load_key` and `load_keyring` for key specs, AWS KMS
  envelope keys (`aws-kms:...`, `generate_aws_kms_key`) and the
  `colgov[aws]` extra.
- **Tables in catalogs:** `table=` on `Catalog`, `Policy`, `colgov.pandas`
  and `colgov.spark`, with no fallback between tables. Decisions can carry a
  `domain` to choose which columns join.
- **Detokenize grants:** `Grant` and `Policy.may_detokenize`.
- **CLI:** `--table`, `retokenize`, `keygen --aws-kms-key-id`, keyring files
  with the primary key first, and `plan` showing detokenize grants.

### Upgrading from 0.2

1. **Policies:** for each role that should reverse tokens, change
   `label: clear` to `label: {view: clear, detokenize: true}`.
2. **Stored tokens:** re-issue them. Run `colgov retokenize data.csv
   --columns a,b -o out.csv`, or call `Tokenizer.retokenize` in your
   pipeline. Until you do, 0.2 tokens and 0.3 tokens for the same value
   won't match in joins.
3. **Code:** if you call `policy.apply(table=...)` by keyword, rename the
   argument to `data=`.

## 0.2.0 — 2026-09-24

### Added

- **Detokenization under policy.** `Policy.detokenize` lets a role reverse
  tokens only for columns it may see in `clear`. It requires a named actor
  and a purpose, and raises `AccessDenied` otherwise.
- **Audit trail.** `JsonlAuditLog` is a hash-chained, append-only JSON Lines
  log, and `verify_audit_log` detects edited, deleted or reordered lines.
  `MemoryAuditLog` is available for tests. Detokenization is always
  audited, including denied and failed attempts, and `Policy.apply` can be
  audited with `audit=` and `actor=`. Audit records never contain data.
- **`colgov.pandas`:** `classify`, `apply` and `detokenize` for DataFrames
  and Series. Install with `pip install "colgov[pandas]"`.
- **`colgov.spark`:** `classify` and `apply` for Spark DataFrames, with
  tokenization in a UDF and a distributed cardinality check. Install with
  `pip install "colgov[spark]"`.
- **`colgov` command-line tool:** `keygen`, `classify`, `review`
  (interactive), `plan`, `apply`, `detokenize` and `audit verify`.
- `Tokenizer` can now be pickled (the cipher cache is rebuilt), and its
  `repr` hides the key.

## 0.1.0 — 2026-09-24

First working release.

### Added

- **Tokenization.** `Tokenizer` does deterministic, reversible AES-256-SIV
  tokenization (RFC 5297). Each column's key is derived from one master key
  with HKDF-SHA256. Tokens are unpadded base64url, `None` passes through, and
  tampered or wrong-key tokens raise `InvalidToken`.
- **Low-cardinality refusal.** `Tokenizer.tokenize_column` refuses to tokenize
  a column with fewer than 10 distinct non-null values and raises
  `LowCardinalityError`. This is configurable.
- **Risk scoring.** `column_risk` profiles a single column's frequencies.
  `k_anonymity` measures the smallest equivalence class over a set of
  quasi-identifiers.
- **Classification.** `RulePack` loads strictly validated YAML rule packs that
  match column names and sampled values. A built-in `core` pack covers common
  personal data.
- **Review.** `Catalog` records a human decision for each column, with a named
  reviewer and a timestamp. It round-trips through YAML, and `PUBLIC` marks a
  column that was reviewed and found not sensitive.
- **Access policy.** `Policy` gives each role a `clear`, `tokenize` or `deny`
  treatment per label, and fails closed. Unknown roles, unreviewed columns
  and labels a role isn't granted are all denied.

## 0.0.1

- Placeholder release that reserves the package name.
