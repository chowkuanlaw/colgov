# colgov scanner guidance

Read `docs/threat-model.md` and `SECURITY.md` in this repository for the full
security contract and known limitations. colgov governs columns of tabular
personal data using deterministic AES-SIV tokens, a reviewed catalog, and a
fail-closed role policy. It does not protect free-text prose.

## Priority targets

- Untrusted CSV or Parquet contents, token strings, column names, policy and
  catalog YAML, and CLI arguments must not bypass role restrictions or expose
  plaintext, master keys, or data from columns denied to that role.
- Unknown columns, roles, labels, and malformed policy or catalog entries must
  fail closed. Detokenization through colgov must require an explicit grant and
  produce the documented audit event, including on denial.
- A party that has tokens but no master key must not forge a token that
  detokenizes, alter its key ID or ciphertext undetected, or recover plaintext
  beyond the documented equality, frequency, and length leakage.
- Key rotation, domain separation, KMS key handling, audit-log verification,
  and SQL view generation deserve particular attention. Check both Python and
  CLI entry points, plus the pandas, Polars, Parquet, and Spark integrations.

Treat a practical bypass of a guarantee above, or disclosure of a master key,
as high or critical depending on attacker prerequisites and blast radius.
Explain those prerequisites in each report. Include a minimal reproducer using
synthetic data, the affected version, and a patch with a regression test when
possible. Do not use real personal data or live credentials.

## Documented limitations

The threat model explicitly allows equality, frequency, and length leakage
from deterministic tokens; possession of a master key permits decryption
outside colgov's policy and audit layer. Hash chaining alone cannot detect a
fully rewritten or truncated audit log without an external checkpoint.
Generated SQL views rely on warehouse permissions to block raw-table access.
Do not report these design properties alone as implementation vulnerabilities.
