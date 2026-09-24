# API stability

From 1.0.0, colgov follows [Semantic Versioning](https://semver.org). This
page defines what counts as the public API that promise covers. Before
1.0, minor releases may still break it, and the changelog says how to
upgrade.

## Public

- **Package names:** everything listed in `__all__` of `colgov`,
  `colgov.keys`, `colgov.pandas` and `colgov.spark`, including the
  signatures, keyword names and documented behaviour.
- **The `colgov` command:** its subcommands, options, exit statuses
  (0 = success, 1 = error, 2 = usage error) and the CSV it reads and writes.
- **File and data formats:**
  - tokens (format v2)
  - catalog files (`version: 2`)
  - policy files
  - rule packs
  - key and keyring specs
  - `JsonlAuditLog` lines

## Not public

- Anything starting with `_`, and any module or name not listed above.
- The wording of error messages. Rely on the exception type instead.
- Which suggestions the built-in `core` rule pack makes. Its patterns
  improve between minor releases.

## Changes after 1.0

- **Deprecation before removal.** A deprecated name keeps working, with a
  `DeprecationWarning`, for at least one minor release before a major
  release removes it.
- **Formats last a major version.** A new token or file format is
  introduced only in a major release. The previous format stays readable
  for at least the next major version, as v1 tokens are in 0.3.
- **Checks never quietly loosen.** A change that would let something
  through that the previous version denied is always a major change, and is
  called out in the changelog.
