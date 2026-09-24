# Threat model

This page covers what colgov protects against, what it doesn't, and what you
have to get right yourself. Please read it before trusting colgov with real
personal data.

## What colgov is for

colgov lets people analyse tabular data that contains personal data, such as
joins, counts and group-bys, without seeing the personal values themselves.
It does this with three pieces:

1. **Deterministic tokens.** AES-256-SIV (RFC 5297) is used with a separate
   key for each token domain, derived with HKDF-SHA256. The same value gives
   the same token, so joins still work.
2. **A reviewed catalog.** A named person decides what each column holds.
3. **A fail-closed policy.** It decides which roles see which labels, and
   how.

## Assets

- **Personal values** in governed columns.
- **Master keys.** Anyone holding a key can reverse every token made with it.
- **The integrity of catalog and policy files.** Whoever can edit them
  decides who sees what.
- **The audit trail** of views and detokenizations.

## Adversaries and guarantees

| Adversary | Guarantee |
|---|---|
| Holds tokens, but not the key (an analyst, a leaked extract, a compromised warehouse) | Cannot recover values beyond the leaks listed below. Cannot forge a token that detokenizes. Cannot alter a token, including its key-ID header, without detection. |
| Holds a role that isn't granted a label | That label's columns are left out of the role's view, detokenizing them raises `AccessDenied`, and the attempt is audited. |
| Adds a new, unreviewed column upstream | The column is denied to every role until a person reviews it. |
| Misspells a label or role in a policy or catalog | Fails closed: the affected columns are denied. |
| Edits, deletes or reorders lines in a `JsonlAuditLog` | `verify_audit_log` reports the first broken line. |

## Known limitations

These follow from the design. They are not bugs.

- **Equality is revealed.** Deterministic tokens show which rows share a
  value within a token domain. That is what makes joins work.
- **Frequency is revealed.** The distribution of tokens mirrors the
  distribution of values, so columns with few distinct values can be
  reversed by frequency analysis alone. colgov refuses by default to
  tokenize columns with fewer than 10 distinct values (`LowCardinalityError`),
  and `column_risk` and `k_anonymity` help you judge the rest. Treat this as
  a guard rail, not a guarantee.
- **Length is revealed.** A token's length is the value's UTF-8 length plus
  a fixed overhead, so lengths leak. Pad values before tokenizing if length
  is sensitive.
- **Tokens link across tables by design.** Columns in the same domain, which
  by default means the same column name, produce matching tokens. Use
  distinct `domain`s to keep data sets apart.
- **Several columns together can identify a person.** Tokenizing every
  column does not stop someone being singled out by a combination of
  quasi-identifiers such as birth year, postcode and gender. Measure it with
  `k_anonymity`.
- **Anyone with the key has everything.** Whoever holds a master key can
  detokenize without asking the policy and without leaving an audit record.
  The policy and audit log control people who use colgov, not people who
  hold keys.
- **Truncating the end of the audit log goes undetected.** Hash chaining
  catches edits, deletions and reordering inside the log, but not removal
  of its last lines. Ship the log off the machine promptly, e.g. to a SIEM
  or to storage with object lock, and compare event counts.
- **Shared audit logs need file locking.** Several processes may append to
  one `JsonlAuditLog` on Linux and macOS, where each write takes an
  exclusive `flock`. Network filesystems may not honour `flock`, and
  Windows has none, so there use one writer per file.
- **Rotation doesn't revoke old tokens.** Tokens made with an older key stay
  readable until that key is removed from the keyring. Retokenize stored
  data, then remove the key.
- **Spark ships the key.** `colgov.spark` sends the tokenizer, including its
  keys, to the executors. Use only clusters you trust with the key.

## Your responsibilities

- **Store master keys in a KMS or secret manager,** for example with the
  `aws-kms:` key specs. Never commit them.
- **Protect the catalog and policy files.** Review changes to them like
  code, e.g. with branch protection and required reviewers.
- **Keep the audit log off the machine** that produces it, and restrict who
  can write to it.
- **Rotate keys when a key may have leaked,** then retokenize stored data
  and remove the old key.

## Cryptographic details

| Item | Value |
|---|---|
| Cipher | AES-256-SIV (RFC 5297), via `cryptography`'s `AESSIV` |
| Domain keys | HKDF-SHA256 over the master key, no salt, info `colgov/v2/domain-key/<domain>`, 64 bytes |
| Key ID | HKDF-SHA256 over the master key, info `colgov/v2/key-id`, first 4 bytes |
| Token v2 | `0x02 ‖ key_id ‖ AES-SIV(domain_key, 0x00 ‖ utf8(value), AD = 0x02 ‖ key_id)`, base64url without padding |
| Token v1 (read-only) | `AES-SIV(v1_domain_key, 0x01 ‖ utf8(value))`, info `colgov/v1/column-key/<domain>` |
| Master keys | At least 32 bytes from a CSPRNG |

This design has not yet had an independent cryptographic review. One is
planned, and its findings will be published in the changelog and, where
they affect security, as a security advisory.
