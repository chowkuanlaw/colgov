<p align="center">
  <img src="https://raw.githubusercontent.com/chowkuanlaw/colgov/main/docs/assets/logo-256.png" width="128" height="128" alt="colgov logo: a table whose middle column is locked">
</p>

# colgov

**Deterministic, reversible tokenization and fail-closed access policy for tabular PII.**

Tokenize a column and it stays joinable. Same plaintext, same token — every
time, across tables and across runs — so `JOIN`, `GROUP BY` and
`COUNT(DISTINCT)` keep working on data nobody can read.

> **Status: stable (`1.0.0`).** The public API and file formats follow
> Semantic Versioning: see the [stability policy](https://github.com/chowkuanlaw/colgov/blob/main/docs/stability.md).
> The cryptographic design has not yet had an independent review. Read the
> [threat model](https://github.com/chowkuanlaw/colgov/blob/main/docs/threat-model.md) before relying on it. See [CHANGELOG.md](https://github.com/chowkuanlaw/colgov/blob/main/CHANGELOG.md).

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
pip install colgov
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
  master key with HKDF-SHA256, using the column name (its *token domain*) as
  context. The same value in two different domains gives unrelated tokens,
  so you can't join tables on a column the policy didn't mean to link.
- **Tokens name their key.** Each token starts with a key ID, so master keys
  can be rotated (see below).
- **Tokens are URL- and SQL-safe.** They use unpadded base64url (`A–Z a–z 0–9 - _`).
- **Tampering is detected.** `detokenize` raises `colgov.InvalidToken` when a
  token was changed or was made with a different key or column.
- **Lose the master key and the tokens can't be reversed.** Anyone who has
  the key can reverse every token.

### Rotating keys, and keeping them in AWS KMS

```python
from colgov import Keyring, Tokenizer

t = Tokenizer(Keyring(new_key, previous=[old_key]))
t.tokenize("ada@example.com", column="email")        # made with new_key
t.detokenize(old_token, column="email")              # old_key tokens still read
t.retokenize(old_token, column="email")              # re-issued under new_key
t.is_current(token)                                  # header check, no decryption
```

- **Tokens depend on the key.** After rotating, the same value gets a new
  token, so migrate stored tokens with `retokenize` (or
  `colgov retokenize`) before joining old data with new.
- **Keys can live in AWS KMS.** `colgov keygen --aws-kms-key-id alias/colgov`
  prints an `aws-kms:...` spec. That is a data key encrypted by KMS, and it's
  safe to keep in configuration. It is decrypted with `kms:Decrypt` only
  when loaded. Install with `pip install "colgov[aws]"`.
- **Keyring specs:** `load_keyring(text)`, `$COLGOV_MASTER_KEY` and
  `--key-file` all take key specs, one per line or comma-separated, with the
  primary key first.
- **Tokens from colgov 0.1–0.2 still read.** They have no key ID, so each
  key in the keyring is tried. `retokenize` upgrades them.

### Refusing columns too predictable to protect

`tokenize_column` profiles a column before it tokenizes anything. If the
column has fewer than 10 distinct non-null values, it raises
`LowCardinalityError` and tokenizes nothing:

```python
t.tokenize_column(["M", "F", "F", None], column="gender")
# LowCardinalityError: column 'gender' has 2 distinct values (minimum 10) ...

t.tokenize_column(values, column="gender", min_distinct=3)             # adjust the threshold
t.tokenize_column(values, column="gender", allow_low_cardinality=True) # opt out explicitly
```

### Measuring re-identification risk

```python
from colgov import column_risk, k_anonymity

column_risk(["a", "a", "a", "b", None])
# ColumnRisk(n_rows=5, n_null=1, n_distinct=2, min_frequency=1, top_share=0.75)

result = k_anonymity(rows, quasi_identifiers=["birth_year", "postcode", "gender"])
result.k               # size of the smallest group of rows sharing all three values
result.rows_below(5)   # how many rows sit in groups smaller than 5
```

`k == 1` means at least one person is unique on those columns and can be
singled out, even when every column is tokenized.

### Classify, review, then govern

The full workflow has three steps: a rule pack **suggests** labels, a person
**decides**, and a policy **resolves** what each role sees.

```python
from colgov import PUBLIC, Catalog, Policy, RulePack, Tokenizer

table = {
    "customer_email": [...],
    "mobile_no": [...],
    "order_total": [...],
    "comments": [...],
}

# 1. Suggest: rule packs match column names and sampled values.
suggestions = RulePack.builtin("core").classify(table)
suggestions["customer_email"][0]
# Suggestion(column='customer_email', label='email', confidence=0.95,
#            rule_ids=('email-name', 'email-value'), ...)

# 2. Decide: only a named person turns a suggestion into a decision.
catalog = Catalog()
catalog.accept(suggestions["customer_email"][0], by="alice")
catalog.accept(suggestions["mobile_no"][0], by="alice")
catalog.decide("order_total", PUBLIC, by="alice", note="no personal data")
catalog.pending(table)     # ['comments']  — not reviewed yet
catalog.save("catalog.yaml")  # commit it; review decisions like code

# 3. Resolve: a fail-closed policy per role.
policy = Policy.from_yaml("""
roles:
  analyst:
    email: tokenize
    phone_number: deny
""")
view = policy.apply(table, role="analyst", catalog=catalog, tokenizer=Tokenizer(key))
list(view)                 # ['customer_email', 'order_total']
```

Policies fail closed at every step:

- **An unknown role sees nothing.**
- **A column nobody has reviewed is denied,** whatever the machine suggested.
- **A label the role isn't granted is denied.** That includes misspelt labels.
- **Tokenized columns still go through the cardinality check,** so a
  predictable column raises `LowCardinalityError` instead of leaking.

Treatments are `clear`, `tokenize` and `deny`. Columns reviewed as `public`
are `clear` unless a role overrides it. Use `policy.plan(role, columns,
catalog)` to see each column's treatment and the reason for it.

### Writing a rule pack

```yaml
pack: my-org
version: 1
labels:
  employee_id:
    description: Internal staff number
rules:
  - id: employee-id-name
    label: employee_id
    column_name: 'emp(loyee)?_?(id|no)'   # regex, case-insensitive, searched in the name
    confidence: 0.8
  - id: employee-id-value
    label: employee_id
    value_pattern: 'E[0-9]{6}'           # regex, must match the whole value
    min_match_ratio: 0.9                 # share of sampled non-null values (default 0.8)
    confidence: 0.9
```

Load it with `RulePack.load("my-org.yaml")`. Packs are validated strictly:
unknown keys, undeclared labels, invalid regexes and duplicate rule ids are
all rejected when the pack loads. The built-in `core` pack covers email,
phone numbers, names, national IDs, dates of birth, postal codes, street
addresses, IP addresses and payment cards.

### Detokenization, with an audit trail

Detokenizing is its own permission. It is granted per label with the long
form of a grant, and seeing a column in `clear` does **not** imply it:

```yaml
roles:
  support:
    email: clear                                  # sees plaintext; can't detokenize
  fraud:
    email: {view: tokenize, detokenize: true}     # works on tokens; may reverse them
```

The same fail-closed checks apply as for views: the role must be known, the
column reviewed, and the label granted. Every attempt is recorded before any
plaintext is returned, whether it was allowed, denied or failed. Each
record names who asked, why, and how many values were involved.

```python
from colgov import AccessDenied, JsonlAuditLog

audit = JsonlAuditLog("audit.jsonl")
policy.detokenize(
    tokens, column="customer_email", role="fraud", catalog=catalog,
    tokenizer=t, actor="carol", purpose="TICKET-4521", audit=audit,
)                          # ['ada@example.com', ...]

policy.detokenize(tokens, column="customer_email", role="analyst", ...)
# AccessDenied: role 'analyst' may not detokenize 'customer_email' ...
```

- **Actor and purpose are required.** If the audit log can't be written,
  no plaintext is returned.
- **Audit records never contain data,** neither plaintext nor tokens.
- **The log is tamper-evident.** `JsonlAuditLog` chains every line to the
  one before it with SHA-256. `verify_audit_log("audit.jsonl")` (or
  `colgov audit verify`) finds any line that was edited, deleted or
  reordered.
- **Views can be audited too.** Pass `audit=` and `actor=` to
  `policy.apply`.

### Several tables in one catalog

Decisions are keyed by table and column, so `customers.id` and `orders.id`
are reviewed separately. A decision never covers a table it wasn't made for:
there is no fallback from a table to table-less decisions.

```python
catalog.decide("email", "email", by="alice", table="customers")
catalog.decide("buyer_email", "email", by="alice", table="orders", domain="email")

policy.apply(customers, role="analyst", catalog=catalog, table="customers", tokenizer=t)
policy.apply(orders, role="analyst", catalog=catalog, table="orders", tokenizer=t)
# customers.email and orders.buyer_email share the "email" token domain, so they join.
```

A column's token domain defaults to its name, so same-named columns join
across tables. Set `domain=` to join differently named columns, or to keep
same-named columns apart. The CLI takes `--table` for the same purpose.

### pandas and PySpark

```bash
pip install "colgov[pandas]"   # or "colgov[spark]"
```

```python
from colgov import pandas as cpd

suggestions = cpd.classify(df)
view = cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=t)
plain = cpd.detokenize(view["customer_email"], policy, role="support", catalog=catalog,
                       tokenizer=t, actor="carol", purpose="TICKET-4521", audit=audit)

from colgov import spark as cspark

view = cspark.apply(sdf, policy, role="analyst", catalog=catalog, tokenizer=t)  # lazy DataFrame
```

- **pandas:** the index and the dtypes of `clear` columns are kept. `None`,
  `NaN` and `pd.NA` all count as null.
- **Spark:** tokenization runs in a UDF on the executors, and the
  cardinality check is a single aggregation. The master key is shipped to
  the executors, so colgov must be installed there, and you should only use
  a cluster you trust with the key.
- **Both:** tokenized columns must hold strings, so cast other types first.

### Command line

```bash
colgov keygen                                   # new master key (base64)
colgov keygen --aws-kms-key-id alias/colgov     # ...or one protected by AWS KMS
export COLGOV_MASTER_KEY=...                    # or --key-file (primary first, older keys after)

colgov classify customers.csv                   # suggestions per column
colgov review customers.csv -c catalog.yaml --by alice
                                                # decide interactively; saved after every answer
colgov plan customers.csv -p policy.yaml -c catalog.yaml --role analyst
                                                # what the role would see, and why
colgov apply customers.csv -p policy.yaml -c catalog.yaml --role analyst -o analyst.csv \
             --audit audit.jsonl --actor bob
colgov detokenize -p policy.yaml -c catalog.yaml --role support --column customer_email \
                  --actor carol --purpose TICKET-4521 --audit audit.jsonl < tokens.txt
colgov retokenize analyst.csv --columns customer_email -o migrated.csv
                                                # after rotating keys
colgov audit verify audit.jsonl
```

Add `--table customers` to `review`, `plan`, `apply` and `detokenize` to use
that table's catalog decisions.

`review` shows suggestions and the evidence for them, but never the
column's values. In the CSV files, empty cells are treated as nulls.

## Roadmap

**v0.1**

- [x] Deterministic reversible tokenization with per-column key derivation (HKDF)
- [x] Column classification from portable YAML rule packs
- [x] Human review workflow — a machine suggests, a person decides
- [x] Fail-closed policy resolution: an unclassified column is never visible
- [x] Re-identification risk scoring (cardinality, k-anonymity)

**v0.2**

- [x] Policy-governed detokenization with a tamper-evident audit log
- [x] pandas and PySpark helpers
- [x] `colgov` command-line tool

**v0.3**

- [x] Key rotation: key IDs in tokens, keyrings, `retokenize`, AWS KMS
- [x] Catalogs keyed by table, with configurable token domains
- [x] Detokenizing as a separate, explicitly granted permission

**Road to 1.0**

- [x] `ruff`, `mypy --strict`, docs site, API stability policy
- [x] `SECURITY.md` and threat model
- [x] Audit log shared by several processes; `logging` and multi-log sinks
- [x] Streaming CLI, Arrow-based Spark UDF, benchmarks
- [x] Property-based and fuzz tests, coverage gate
- [x] 1.0.0 release candidate (`1.0.0rc1`)
- [x] 1.0.0

**After 1.0**

- [ ] Independent review of the cryptographic design
- [ ] Optional Presidio bridge for value-shape detection

## Scope

`colgov` governs **columns in tabular data**. It does not detect PII inside
free-text prose — for that, use
[Presidio](https://github.com/data-privacy-stack/presidio), which is excellent
at it. An optional bridge is planned so Presidio can act as a value-shape
detector feeding `colgov`'s classification.

## Security

Read the [threat model](https://github.com/chowkuanlaw/colgov/blob/main/docs/threat-model.md) before using colgov with real
personal data. Report vulnerabilities privately as described in
[SECURITY.md](https://github.com/chowkuanlaw/colgov/blob/main/SECURITY.md). The [API stability policy](https://github.com/chowkuanlaw/colgov/blob/main/docs/stability.md)
explains what stays compatible from 1.0.

## License

Apache-2.0
