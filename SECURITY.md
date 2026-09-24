# Security policy

colgov protects personal data, so we treat security reports as the highest
priority.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on
<https://github.com/chowkuanlaw/colgov/security/advisories/new>.

Please include:

- the colgov version, and your Python and `cryptography` versions
- what an attacker can do, and what they need first (for example, holding
  tokens but not the key)
- a minimal reproduction, if you have one

We aim to acknowledge reports within 7 days. We will keep you informed while
we work on a fix, and credit you in the advisory unless you prefer not to be
named.

## Supported versions

| Version | Supported |
|---|---|
| Latest minor release | Yes |
| Anything older | No: please upgrade |

Before 1.0, fixes go into the next release only.

## Scope

In scope: anything that breaks a guarantee in the
[threat model](docs/threat-model.md). That includes recovering plaintext
from tokens without the key, forging or altering tokens undetected, getting
past a fail-closed policy check, detokenizing without an audit record, and
audit-log tampering that `verify_audit_log` misses.

Out of scope: the known limitations listed in the threat model. Examples
are deterministic tokens revealing equality, frequency and length, and
attacks that require the master key.
