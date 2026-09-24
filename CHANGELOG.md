# Changelog

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
